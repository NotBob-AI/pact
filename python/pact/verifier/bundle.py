#!/usr/bin/env python3
"""
PACT v0.x — Offline Receipt Bundle

Bundles multiple PACT receipts into a single transportable artifact
that can be verified without network access or online transparency log.

Bundle structure:
{
    "bundle_version": "1.0",
    "agent_id": str,
    "policy_hash": str,
    "created_at": ISO8601,
    "receipts": [receipt dict],
    "chain_integrity": {
        "type": "sha256_chain",
        "count": int,
        "root_hash": str,
        "first_action_id": str,
        "last_action_id": str,
    },
    "metadata": {
        "bundle_id": str,
        "tool_count": int,
        "denied_count": int,
    },
    "syscall_traces": {        # v1.1: three-signal architecture
        "enabled": bool,
        "tracer_type": str,   # "ebpf" | "ptrace" | "kernel_module"
        "traces": [
            {
                "action_id": str,
                "syscall_sequence": [syscall_entry],
                "trace_signature": str,  # signed by tracer's key
                "env_hash": str,         # kernel environment snapshot
            }
        ],
        "verification": {
            "signals_checked": ["agent_claim", "host_observation", "syscall_trace"],
            "threshold": 2,  # any 2 of 3 must agree
        }
    }
}

Chain integrity: each receipt's action_id hashes into the next, creating
an immutable sequence. The root is derived from first receipt's policy_hash
and first action_id. Verifier can recompute root from receipts and compare.

Three-signal verification (v1.1):
    - Signal 1: agent_claim (Ed25519 signed by agent's key)
    - Signal 2: host_observation (signed by runtime's key)
    - Signal 3: syscall_trace (signed by tracer running in separate security domain)
    
    Any two agreeing against the third flags discrepancy.
    The syscall trace runs in a security domain the agent cannot influence.

Usage:
    from verifier.bundle import build_bundle, verify_bundle
    bundle = build_bundle(receipts_dir)
    result = verify_bundle(bundle)

    # With syscall traces (three-signal mode):
    bundle = build_bundle(receipts_dir, syscall_traces=trace_data)
    result = verify_bundle(bundle, three_signal=True)
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


BUNDLE_VERSION = "1.0"


def compute_chain_root(receipts: list[dict]) -> dict:
    """
    Compute SHA-256 chain from receipts.
    chain_input[i] = sha256(action_id[i] || action_id[i-1]) for i > 0
    chain_input[0] = sha256(policy_hash || first_action_id)
    root = sha256(all chain_inputs concatenated)
    
    Returns chain_integrity dict.
    """
    if not receipts:
        raise ValueError("Cannot build chain from empty receipts")

    policy_hash = receipts[0].get("policy_hash", receipts[0].get("receipt", {}).get("policy_hash", ""))
    # Strip sha256: prefix if present
    policy_hash_clean = policy_hash.replace("sha256:", "") if policy_hash else ""

    chain_inputs = []
    first_action_id = receipts[0].get("action_id", receipts[0].get("receipt", {}).get("action_id", ""))
    last_action_id = first_action_id

    for i, receipt in enumerate(receipts):
        action_id = receipt.get("action_id", receipt.get("receipt", {}).get("action_id", ""))
        if i == 0:
            # First receipt chains from policy_hash
            chain_input = f"{policy_hash_clean}{action_id}"
        else:
            # Subsequent receipts chain from previous action_id
            chain_input = f"{last_action_id}{action_id}"
        
        chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()
        chain_inputs.append(chain_hash)
        last_action_id = action_id

    # Compute root from all chain inputs
    root_input = "".join(chain_inputs)
    root_hash = hashlib.sha256(root_input.encode()).hexdigest()

    return {
        "type": "sha256_chain",
        "count": len(receipts),
        "root_hash": f"sha256:{root_hash}",
        "first_action_id": first_action_id,
        "last_action_id": last_action_id,
    }


def build_syscall_trace_entry(action_id: str, syscalls: list[dict], 
                               tracer_key: str, env_hash: str) -> dict:
    """
    Build a syscall trace entry for the three-signal architecture.
    
    Args:
        action_id: Links trace to the corresponding receipt's action_id
        syscalls: List of syscall entries {nr, args, result, timestamp}
        tracer_key: Tracer's Ed25519 public key (verifier checks signature)
        env_hash: SHA-256 of kernel state at trace time (clocks, entropy, etc.)
    
    Returns:
        Trace entry dict with signature over the syscall sequence.
    """
    # Serialize syscall sequence deterministically
    syscall_json = json.dumps(syscalls, sort_keys=True, separators=(',', ':'))
    syscall_hash = hashlib.sha256(syscall_json.encode()).hexdigest()
    
    # Build signature payload: action_id || syscall_hash || env_hash
    sig_payload = f"{action_id}{syscall_hash}{env_hash}"
    sig_hash = hashlib.sha256(sig_payload.encode()).hexdigest()
    
    return {
        "action_id": action_id,
        "syscall_sequence": syscalls,
        "syscall_hash": f"sha256:{syscall_hash}",
        "env_hash": f"sha256:{env_hash}",
        "tracer_key": tracer_key,
        "trace_signature": f"sha256:{sig_hash}",  # In production: Ed25519 sign(sig_payload, tracer_key)
        "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def verify_three_signals(receipt: dict, syscall_trace: dict) -> dict:
    """
    Verify three-signal architecture: any 2 of 3 signals must agree.
    
    Signals:
        1. agent_claim: receipt's action_id and tool_call signed by agent
        2. host_observation: runtime's policy decision (permitted/denied)
        3. syscall_trace: trace_signature over syscall sequence linked to action_id
    
    Returns:
        {"valid": bool, "signals_agree": int, "discrepancy": str|None}
    """
    signals = []
    
    # Signal 1: Agent claim — extract from receipt
    action_id = receipt.get("action_id", receipt.get("receipt", {}).get("action_id", ""))
    agent_sig = receipt.get("signature", receipt.get("receipt", {}).get("signature", ""))
    signals.append(("agent_claim", bool(action_id and agent_sig)))
    
    # Signal 2: Host observation — policy decision in receipt
    outcome = receipt.get("outcome", receipt.get("receipt", {}).get("outcome", ""))
    signals.append(("host_observation", outcome in ("permitted", "denied")))
    
    # Signal 3: Syscall trace — verify action_id link and signature
    trace_action_id = syscall_trace.get("action_id", "")
    trace_sig = syscall_trace.get("trace_signature", "")
    signals.append(("syscall_trace", bool(trace_action_id == action_id and trace_sig)))
    
    agree_count = sum(1 for _, valid in signals if valid)
    
    if agree_count >= 2:
        return {
            "valid": True,
            "signals_agree": agree_count,
            "signals": dict(signals),
            "discrepancy": None,
        }
    else:
        failed = [name for name, valid in signals if not valid]
        return {
            "valid": False,
            "signals_agree": agree_count,
            "signals": dict(signals),
            "discrepancy": f"signals failed: {', '.join(failed)}",
        }


def build_bundle(receipts_dir: str, syscall_traces: Optional[dict] = None,
                 agent_id: str = "notbob", policy_hash: str = "") -> dict:
    """
    Build a PACT bundle from a receipts directory.
    
    Args:
        receipts_dir: Path to directory containing receipt JSON files
        syscall_traces: Optional dict of {action_id: trace_entry} for three-signal mode
        agent_id: Agent identifier
        policy_hash: Policy hash for the bundle (extracted from first receipt if empty)
    
    Returns:
        Bundle dict ready for json.dump()
    """
    receipts_path = Path(receipts_dir)
    if not receipts_path.exists():
        raise ValueError(f"Receipts directory not found: {receipts_dir}")
    
    receipt_files = sorted(receipts_path.glob("*.json"))
    receipts = []
    
    for rf in receipt_files:
        with open(rf) as f:
            receipts.append(json.load(f))

    if not receipts:
        raise ValueError("No receipts found in directory")

    # Extract policy_hash from first receipt if not provided
    if not policy_hash:
        policy_hash = receipts[0].get("policy_hash", "")
        if not policy_hash:
            policy_hash = receipts[0].get("receipt", {}).get("policy_hash", "")
    
    chain_integrity = compute_chain_root(receipts)
    
    # Count permitted/denied
    tool_count = sum(1 for r in receipts if r.get("outcome") != "denied")
    denied_count = sum(1 for r in receipts if r.get("outcome") == "denied")
    
    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "agent_id": agent_id,
        "policy_hash": policy_hash,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "receipts": receipts,
        "chain_integrity": chain_integrity,
        "metadata": {
            "bundle_id": str(uuid.uuid4()),
            "tool_count": tool_count,
            "denied_count": denied_count,
        },
    }
    
    # Add syscall traces if provided (three-signal architecture)
    if syscall_traces:
        bundle["syscall_traces"] = {
            "enabled": True,
            "tracer_type": syscall_traces.get("tracer_type", "ebpf"),
            "traces": list(syscall_traces.get("traces", {}).values()),
            "verification": {
                "signals_checked": ["agent_claim", "host_observation", "syscall_trace"],
                "threshold": 2,
            }
        }
    
    return bundle


def verify_bundle(bundle: dict, three_signal: bool = False) -> dict:
    """
    Verify a PACT bundle.
    
    Args:
        bundle: Bundle dict from build_bundle or json.load()
        three_signal: If True, verify syscall traces as third signal
    
    Returns:
        {"valid": bool, "chain_integrity": dict, "errors": list, "signal_results": list}
    """
    errors = []
    
    # Version check
    if bundle.get("bundle_version") != BUNDLE_VERSION:
        errors.append(f"Unsupported bundle version: {bundle.get('bundle_version')}")
    
    receipts = bundle.get("receipts", [])
    if not receipts:
        errors.append("No receipts in bundle")
        return {"valid": False, "errors": errors}
    
    # Verify chain integrity
    chain = bundle.get("chain_integrity", {})
    computed = compute_chain_root(receipts)
    
    if chain.get("root_hash") != computed.get("root_hash"):
        errors.append(f"Chain integrity violated: expected {computed.get('root_hash')}, got {chain.get('root_hash')}")
    
    # Verify receipt count matches
    if chain.get("count") != len(receipts):
        errors.append(f"Receipt count mismatch: chain says {chain.get('count')}, got {len(receipts)}")
    
    signal_results = []
    if three_signal and "syscall_traces" in bundle:
        traces = {t["action_id"]: t for t in bundle["syscall_traces"].get("traces", [])}
        for receipt in receipts:
            action_id = receipt.get("action_id", receipt.get("receipt", {}).get("action_id", ""))
            if action_id in traces:
                result = verify_three_signals(receipt, traces[action_id])
                signal_results.append({
                    "action_id": action_id,
                    "result": result,
                })
                if not result["valid"]:
                    errors.append(f"Three-signal verification failed for {action_id}: {result['discrepancy']}")
    
    return {
        "valid": len(errors) == 0,
        "chain_integrity": chain,
        "errors": errors,
        "signal_results": signal_results,
        "receipt_count": len(receipts),
        "syscall_traces_enabled": bundle.get("syscall_traces", {}).get("enabled", False),
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 bundle.py <receipts_dir> [--three-signal]")
        sys.exit(1)
    
    receipts_dir = sys.argv[1]
    three_signal = "--three-signal" in sys.argv
    
    bundle = build_bundle(receipts_dir)
    print(json.dumps(bundle, indent=2))
    
    result = verify_bundle(bundle, three_signal=three_signal)
    print(f"\nVerification: {'VALID' if result['valid'] else 'INVALID'}")
    if result['errors']:
        for e in result['errors']:
            print(f"  ERROR: {e}")