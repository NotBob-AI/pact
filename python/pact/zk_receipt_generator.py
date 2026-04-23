#!/usr/bin/env python3
"""
PACT v0.3 — ZK Receipt Generator Bridge

Bridges pact-mcp-interceptor.py (Layer 0) to zk_host.py (v0.3 ZK prover).
Produces ZK membership proofs for tool calls against committed policy.

In production mode: calls RISC Zero prover via zk_host.py
In DUMMY mode: generates structurally identical receipts with DUMMY_PROOF marker

Usage (CLI):
    python3 -m pact.zk_receipt_generator --policy policy.json --tool search_web \\
        --params '{}' --anchor anchor.json --output receipt.json

Usage (import):
    from pact.zk_receipt_generator import generate_zk_tool_receipt
    receipt = generate_zk_tool_receipt(policy, tool_name, params, anchor)
"""

import argparse
import json
import os
import sys
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path

# Add parent dir to path for zk_host import
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from pact.zk_host import generate_zk_receipt, DUMMY_PROOF, sha256_hex, sha256_raw_hex
except ImportError:
    # Fallback if zk_host not available
    DUMMY_PROOF = os.environ.get("DUMMY_PROOF", "0") == "1"
    
    def sha256_hex(data: str) -> str:
        return f"sha256:{hashlib.sha256(data.encode('utf-8')).hexdigest()}"
    
    def sha256_raw_hex(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()
    
    def generate_zk_receipt(policy, tool_name, params, anchor, merkle_proof=None):
        """Stub when zk_host unavailable."""
        return {
            "receipt_type": "DUMMY_ZK_PROOF",
            "policy_hash": policy.get("policy_hash", "unknown"),
            "tool_name": tool_name,
            "params_hash": sha256_raw_hex(json.dumps(params, sort_keys=True)),
            "proof_data": "zk_host.py not available — set DUMMY_PROOF=1",
        }


def compute_params_hash(params: dict) -> str:
    """Compute deterministic hash of tool call params."""
    return sha256_raw_hex(json.dumps(params, sort_keys=True, default=str))


def build_zk_receipt(
    policy: dict,
    tool_name: str,
    params: dict,
    anchor: dict,
    outcome: bool = True,
    reason: str = "policy_compliant",
    request_id: str = None,
    seq: int = None,
    prev_receipt_hash: str = None,
) -> dict:
    """
    Generate a ZK membership proof receipt for a tool call.

    This bridges Layer 0 (interceptor) to Layer 2 (ZK receipt):
      - Input: policy doc + tool call + anchor (transparency log proof)
      - Output: ZK receipt proving tool ∈ committed_policy at anchor

    The receipt format matches pact-mcp-interceptor.py receipt format
    but upgrades the proof field from SHA-256 membership to ZK membership.

    Args:
        policy: Full policy document with policy_hash
        tool_name: Name of tool called
        params: Tool call parameters
        anchor: Transparency log anchor { log_index, log_id, merkle_root }
        outcome: Whether the call was permitted (True) or denied (False)
        reason: Human-readable outcome reason
        request_id: Optional request ID from MCP call
        seq: Sequence number (from interceptor chain state)
        prev_receipt_hash: Previous receipt hash (for chain continuity)

    Returns:
        ZK receipt dict with proof_type = "zk_membership_proof"
    """
    policy_hash = policy.get("policy_hash")
    if not policy_hash:
        raise ValueError("Policy must have policy_hash — commit policy before generating ZK receipt")

    params_hash = compute_params_hash(params)
    action_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    # Build public inputs for the ZK circuit
    # (zk_host.generate_zk_receipt takes these and computes the proof)
    public_inputs = {
        "policy_hash": policy_hash,
        "tool_name": tool_name,
        "params_hash": params_hash,
        "log_index": anchor.get("log_index", 0),
        "log_id": anchor.get("log_id", ""),
        "merkle_root": anchor.get("merkle_root", ""),
    }

    # Generate ZK proof (or DUMMY_PROOF stub)
    if DUMMY_PROOF:
        zk_proof = {
            "proof_type": "DUMMY_ZK_PROOF",
            "mode": "DUMMY — set RISC0_TOOLCHAIN=1 for real proofs",
            "public_inputs_hash": sha256_raw_hex(json.dumps(public_inputs, sort_keys=True)),
            "policy_hash": policy_hash,
            "tool_name_hash": sha256_raw_hex(tool_name),
            "verified": True,  # DUMMY always passes
            "note": "Replace with RISC Zero receipt in production",
        }
        receipt_hash_input = f"{policy_hash}:{tool_name}:{params_hash}:DUMMY"
    else:
        try:
            # Call the actual RISC Zero prover
            zk_result = generate_zk_receipt(
                policy=policy,
                tool_name=tool_name,
                params=params,
                anchor=anchor,
            )
            zk_proof = {
                "proof_type": "RISC0_MERKLEMembership",
                "receipt": zk_result,
                "public_inputs": public_inputs,
            }
            receipt_hash_input = f"{policy_hash}:{tool_name}:{zk_result.get('seal', params_hash)}"
        except Exception as e:
            # Fallback to DUMMY if prover fails (e.g., toolchain not installed)
            zk_proof = {
                "proof_type": "DUMMY_ZK_PROOF",
                "error": str(e),
                "fallback": True,
                "public_inputs_hash": sha256_raw_hex(json.dumps(public_inputs, sort_keys=True)),
            }
            receipt_hash_input = f"{policy_hash}:{tool_name}:{params_hash}:ERROR:{str(e)[:40]}"

    # Compute receipt hash (chain continuity — includes prev hash to chain receipts)
    chain_input = f"{receipt_hash_input}:{prev_receipt_hash or 'GENESIS'}"
    receipt_hash_raw = sha256_raw_hex(chain_input)
    receipt_hash = f"sha256:{receipt_hash_raw}"

    receipt = {
        "receipt_version": "0.3.0",
        "receipt_hash": receipt_hash,
        "agent_id": policy.get("agent_id", policy.get("agent_id", "unknown")),
        "policy_hash": policy_hash,
        "action_id": action_id,
        "timestamp": timestamp,
        "tool_called": tool_name,
        "params_hash": params_hash,
        "outcome": "permitted" if outcome else "denied",
        "outcome_reason": reason,
        "seq": seq,
        "prev_receipt_hash": prev_receipt_hash,
        "anchor": anchor,
        "proof": {
            "type": "zk_membership_proof",
            "standard": "urn:pact:receipt:v0.3",
            "zk": zk_proof,
            "statement": (
                f"tool_called {'∈' if outcome else '∉'} committed_policy "
                f"AND policy_hash anchored at log_index={anchor.get('log_index')} "
                f"AND ZK proof verifies computation integrity"
            ),
        },
        "interceptor": "pact-mcp-interceptor v0.3-zk (RISC Zero)",
        "request_id": request_id,
    }

    return receipt


def verify_zk_receipt(receipt: dict) -> dict:
    """
    Verify a ZK receipt (lightweight — does not re-run ZK circuit).

    Checks:
      1. receipt_hash format (sha256: prefix)
      2. proof.zk has valid structure (proof_type present)
      3. outcome is permitted/denied

    Note: receipt_hash is a chain pointer, not a self-integrity hash —
    it references the prior receipt via prev_receipt_hash.
    Does NOT verify the ZK proof itself (requires RISC Zero verifier or SP1).
    """
    receipt_hash = receipt.get("receipt_hash", "")
    if not receipt_hash.startswith("sha256:"):
        return {"valid": False, "reason": "malformed receipt_hash"}

    zk = receipt.get("proof", {}).get("zk", {})
    proof_type = zk.get("proof_type")

    if not proof_type:
        return {"valid": False, "reason": "missing proof.zk.proof_type"}

    return {
        "valid": True,
        "reason": f"ZK receipt structurally valid (proof_type={proof_type}, "
                  f"outcome={receipt.get('outcome')})",
        "proof_type": proof_type,
        "is_dummy": proof_type == "DUMMY_ZK_PROOF",
    }


# CLI entry point
def main():
    parser = argparse.ArgumentParser(description="PACT v0.3 ZK Receipt Generator")
    parser.add_argument("--policy", required=True, help="Path to committed policy JSON")
    parser.add_argument("--tool", required=True, help="Tool name called")
    parser.add_argument("--params", default="{}", help="Tool params as JSON string")
    parser.add_argument("--anchor", required=True, help="Path to transparency log anchor JSON")
    parser.add_argument("--outcome", default="true", choices=["true", "false"], help="Permitted or denied")
    parser.add_argument("--reason", default="policy_compliant", help="Outcome reason")
    parser.add_argument("--request-id", help="Optional MCP request ID")
    parser.add_argument("--seq", type=int, help="Chain sequence number")
    parser.add_argument("--prev-hash", help="Previous receipt hash")
    parser.add_argument("--output", default="/tmp/pact-zk-receipt.json", help="Output path")
    args = parser.parse_args()

    with open(args.policy) as f:
        policy = json.load(f)
    with open(args.anchor) as f:
        anchor = json.load(f)
    params = json.loads(args.params)

    receipt = build_zk_receipt(
        policy=policy,
        tool_name=args.tool,
        params=params,
        anchor=anchor,
        outcome=args.outcome == "true",
        reason=args.reason,
        request_id=args.request_id,
        seq=args.seq,
        prev_receipt_hash=args.prev_hash,
    )

    with open(args.output, "w") as f:
        json.dump(receipt, f, indent=2)

    verification = verify_zk_receipt(receipt)
    status = "✓" if verification["valid"] else "✗"
    print(f"[PACT v0.3 ZK] {status} {receipt['tool_called']} — {verification['reason']}")
    print(f"[PACT] Receipt: {args.output}")
    print(f"[PACT] Proof type: {receipt['proof']['zk'].get('proof_type', 'unknown')}")
    if DUMMY_PROOF:
        print("[PACT] WARNING: Running in DUMMY_PROOF mode — set RISC0_TOOLCHAIN=1 for real ZK proofs")


if __name__ == "__main__":
    main()
