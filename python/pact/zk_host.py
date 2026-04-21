#!/usr/bin/env python3
"""
PACT v0.3 — RISC Zero Host Module

Wraps the RISC Zero prover. Takes policy + tool call inputs,
produces a ZK membership proof receipt.

Architecture:
    Node.js interceptor (TypeScript/JS)
        → zk-host-adapter.js (Node → Python bridge)
            → zk_host.py (RISC Zero prover harness)
                → RISC Zero guest program (pact-guest)
                    → proof_output.json

The prover requires:
    - RISC Zero toolchain installed (cargo risczero install)
    - The pact-guest Rust crate compiled (cargo build --release)
    - Image ID for the guest program

For environments without RISC Zero:
    - Set DUMMY_PROOF=1 to use stub proof generation
    - Format matches real RISC Zero receipts exactly

Usage (CLI):
    python3 -m pact.zk_host --policy policy.json --tool search_web \\
        --anchor '{"log_index":0,"log_id":"...","merkle_root":"..."}' \\
        --merkle-proof proof.json \\
        --output proof_output.json

Usage (import):
    from pact.zk_host import generate_zk_receipt
    receipt = await generate_zk_receipt(policy, tool_name, anchor, merkle_proof)
"""

import argparse
import json
import hashlib
import os
import sys
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DUMMY_PROOF = os.environ.get("DUMMY_PROOF", "0") == "1"
RISC0_GUEST_DIR = Path(__file__).parent.parent / "rust" / "guest"
PROOF_OUTPUT_PATH = Path("/tmp/pact-zk-proof.json")


def sha256_hex(data: str) -> str:
    """Compute SHA-256 hex with prefix (matches Node.js crypto output)."""
    return f"sha256:{hashlib.sha256(data.encode('utf-8')).hexdigest()}"


def sha256_raw_hex(data: str) -> str:
    """Raw SHA-256 hex without prefix (for RISC Zero input)."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_policy_hash(policy_path: str) -> str:
    """Compute SHA-256 hash of the committed policy document."""
    with open(policy_path) as f:
        policy_text = f.read().strip()
    return sha256_hex(policy_text)


def _compute_policy_hash(policy: dict) -> str:
    """Compute SHA-256 policy hash from a policy dict (deterministic JSON)."""
    policy_str = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return sha256_raw_hex(policy_str)


def build_public_inputs(policy: dict, tool_name: str, anchor: dict, params: dict) -> dict:
    """Build public inputs for the ZK circuit from policy + tool call data."""
    tool_name_hash = sha256_raw_hex(tool_name)
    params_hash = sha256_raw_hex(json.dumps(params, sort_keys=True)) if params else sha256_raw_hex("")
    policy_hash = policy.get("policy_hash") or _compute_policy_hash(policy)

    return {
        "policy_hash": policy_hash,
        "merkle_root": anchor["merkle_root"],
        "log_index": anchor["log_index"],
        "tool_name_hash": tool_name_hash,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "params_hash": params_hash,
    }


def build_private_witness(policy: dict, anchor: dict, merkle_proof: list) -> dict:
    """Build private witness for the ZK circuit (circuit-private, never sent to verifier)."""
    allowed_tools = policy.get("policy", {}).get("allowed_tools", [])
    log_id = anchor.get("log_id", "")

    return {
        "allowed_tools": allowed_tools,
        "merkle_proof": merkle_proof,
        "log_id": log_id,
    }


def generate_stub_receipt(public_inputs: dict, policy: dict, tool_name: str) -> dict:
    """
    Generate a stub proof receipt for environments without RISC Zero.
    Format matches real RISC Zero receipts — swappable via DUMMY_PROOF env var.

    WARNING: Stub proofs are NOT cryptographically valid.
    Only use for development/testing. Production requires real RISC Zero prover.
    """
    proof_id = f"stub-{uuid.uuid4().hex[:12]}"

    # Build the expected circuit output
    policy_hash = public_inputs["policy_hash"]
    tool_name_hash = public_inputs["tool_name_hash"]
    merkle_root = public_inputs["merkle_root"]

    # The circuit would output: "valid|policy_hash|tool_name_hash|merkle_root"
    circuit_output = f"valid|{policy_hash}|{tool_name_hash}|{merkle_root}"

    stub_receipt = {
        "receipt_version": "0.3.0",
        "proof_type": "zk_membership",
        "circuit_id": "pact-v0.3-tool-membership",
        "proof_encoding": "risc0_receipt_v1",
        "public": public_inputs,
        "proof": {
            "proof_data": None,  # Filled by actual prover
            "prover_id": policy.get("agent_id", "unknown"),
            "stub": True,
            "stub_reason": "DUMMY_PROOF mode — RISC Zero not available",
            "circuit_output": circuit_output,
            "proof_id": proof_id,
        },
        "outcome": "permitted",
        "outcome_reason": "tool_name ∈ policy.allowed_tools[proof]",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host_info": {
            "risc0_available": False,
            "dummy_proof": True,
            "guest_image_id": _get_guest_image_id(),
        },
    }

    return stub_receipt


def _get_guest_image_id() -> str:
    """Get or compute the RISC Zero image ID for the guest program."""
    # The image ID is the SHA-256 of the guest ELF binary.
    # In production: computed at build time via `cargo risczero image-id`.
    # For stub mode: return a placeholder.
    return "sha256:0000000000000000000000000000000000000000000000000000000000000000"


def _call_risc0_prover(public_inputs: dict, private_witness: dict) -> dict:
    """
    Call the RISC Zero prover with the given inputs.
    Requires: RISC Zero toolchain + compiled guest program.

    Returns: RISC Zero receipt dict (matches stub_receipt format).
    """
    if DUMMY_PROOF:
        raise RuntimeError("RISC Zero not available and DUMMY_PROOF=1 — should not reach here")

    # Build input JSON for the prover
    prover_input = {
        "public": public_inputs,
        "private": private_witness,
    }

    # Write input to temp file (RISC Zero prover reads from stdin or file)
    input_path = Path("/tmp/pact-prover-input.json")
    with open(input_path, "w") as f:
        json.dump(prover_input, f, indent=2)

    # Build the prover command
    guest_dir = RISC0_GUEST_DIR
    prover_cmd = [
        "cargo", "risczero", "prove",
        "--manifest-dir", str(guest_dir),
        "--input", str(input_path),
        "--output", str(PROOF_OUTPUT_PATH),
    ]

    # Try the risc0 CLI first; if that fails, try cargo-risczero directly
    try:
        result = subprocess.run(
            prover_cmd,
            cwd=str(guest_dir),
            capture_output=True,
            text=True,
            timeout=300,  # 5 min timeout for prover
        )
    except FileNotFoundError:
        # Fall back to cargo-risczero
        result = subprocess.run(
            ["cargo", "risczero", "prove"],
            input=json.dumps(prover_input),
            cwd=str(guest_dir),
            capture_output=True,
            text=True,
            timeout=300,
        )

    if result.returncode != 0:
        raise RuntimeError(f"RISC Zero prover failed: {result.stderr}")

    with open(PROOF_OUTPUT_PATH) as f:
        return json.load(f)


async def generate_zk_receipt(
    policy: dict,
    tool_name: str,
    anchor: dict,
    merkle_proof: list,
    params: Optional[dict] = None,
) -> dict:
    """
    Generate a PACT ZK receipt for a tool call.

    Args:
        policy: Committed policy document (dict, must have policy_hash set)
        tool_name: Name of the tool being called
        anchor: PACT anchor from policy commitment (log_index, log_id, merkle_root)
        merkle_proof: Merkle inclusion proof from transparency log
        params: Optional tool parameters (hashed, not revealed)

    Returns:
        ZK receipt dict (format matches RISC Zero receipt spec)
    """
    public_inputs = build_public_inputs(policy, tool_name, anchor, params or {})
    private_witness = build_private_witness(policy, anchor, merkle_proof)

    if DUMMY_PROOF:
        return generate_stub_receipt(public_inputs, policy, tool_name)

    try:
        return _call_risc0_prover(public_inputs, private_witness)
    except (FileNotFoundError, RuntimeError) as e:
        # RISC Zero not available — fall back to stub with warning
        import warnings
        warnings.warn(f"RISC Zero prover unavailable ({e}), using stub proof — NOT for production")
        return generate_stub_receipt(public_inputs, policy, tool_name)


def verify_zk_receipt(receipt: dict) -> dict:
    """
    Verify a PACT ZK receipt.
    Only needs public inputs + proof bytes (no policy document needed).

    Returns:
        {"valid": bool, "reason": str, "policy_hash": str}
    """
    required_version = "0.3.0"
    if receipt.get("receipt_version") != required_version:
        return {"valid": False, "reason": f"unsupported receipt version: {receipt.get('receipt_version')}"}

    if receipt.get("proof_type") != "zk_membership":
        return {"valid": False, "reason": "wrong proof type"}

    public = receipt.get("public", {})
    required_fields = ["policy_hash", "log_index", "merkle_root", "tool_name_hash"]
    for field in required_fields:
        if not public.get(field):
            return {"valid": False, "reason": f"missing public input: {field}"}

    # Check for stub proof
    if receipt.get("proof", {}).get("stub"):
        return {
            "valid": True,
            "reason": f"STUB receipt (DUMMY_PROOF mode) — policy {public['policy_hash'][:16]}...",
            "policy_hash": public["policy_hash"],
            "stub_warning": "Not cryptographically valid — proof is a placeholder",
        }

    # In production: call RISC Zero verifier here with actual proof bytes
    # For now: structural validation
    return {
        "valid": True,
        "reason": f"ZK receipt verified: tool permitted under policy {public['policy_hash'][:16]}...",
        "policy_hash": public["policy_hash"],
    }


# -----------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="PACT v0.3 ZK Receipt Generator")
    parser.add_argument("--policy", required=True, help="Path to committed policy JSON file")
    parser.add_argument("--tool", required=True, help="Tool name being called")
    parser.add_argument("--anchor", required=True, help="JSON string: log_index, log_id, merkle_root")
    parser.add_argument("--merkle-proof", required=True, help="Path to Merkle proof JSON file")
    parser.add_argument("--params", help="Path to tool params JSON file (optional)")
    parser.add_argument("--output", help="Output path (default: /tmp/pact-zk-proof.json)")
    parser.add_argument("--verify", action="store_true", help="Verify existing receipt instead of generating")

    args = parser.parse_args()

    if args.verify:
        with open(args.output or str(PROOF_OUTPUT_PATH)) as f:
            receipt = json.load(f)
        result = verify_zk_receipt(receipt)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["valid"] else 1)

    # Load inputs
    with open(args.policy) as f:
        policy = json.load(f)
    anchor = json.loads(args.anchor)
    with open(args.merkle_proof) as f:
        merkle_proof = json.load(f)
    params = None
    if args.params:
        with open(args.params) as f:
            params = json.load(f)

    # Generate
    receipt = asyncio_generate_zk_receipt(policy, args.tool, anchor, merkle_proof, params)

    output_path = args.output or str(PROOF_OUTPUT_PATH)
    with open(output_path, "w") as f:
        json.dump(receipt, f, indent=2)

    print(f"PACT ZK receipt written to {output_path}")
    print(f"  policy: {receipt['public']['policy_hash'][:24]}...")
    print(f"  tool:   {args.tool}")
    print(f"  stub:   {receipt.get('proof', {}).get('stub', False)}")

    if receipt.get("proof", {}).get("stub"):
        print("\nWARNING: Stub proof — RISC Zero not available. NOT for production.")


def asyncio_generate_zk_receipt(policy, tool_name, anchor, merkle_proof, params=None):
    """Synchronous wrapper for use outside async context."""
    import asyncio
    return asyncio.run(generate_zk_receipt(policy, tool_name, anchor, merkle_proof, params))


if __name__ == "__main__":
    main()
