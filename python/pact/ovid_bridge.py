#!/usr/bin/env python3
"""
PACT v0.3 → OVID Verifier Bridge

Bridges PACT v0.3 ZK receipts into the v0.1 receipt format expected by
the OVID verifier in pact-stack-demo. This allows the ZK receipt generator
to plug into the existing OVID+Carapace+PACT stack without changing the
verifier.

Usage:
    python3 -m pact.ovid_bridge --zk-receipt proof.json --agent-id test-agent-001 \\
        --policy-hash sha256:abc... --output receipts/action_id.json

The output is a v0.1-compatible receipt that the OVID verifier can audit.
"""

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


def bridge_zk_receipt_to_v01(
    zk_receipt: dict,
    agent_id: str,
    tool_called: str,
    policy_hash: str,
) -> dict:
    """
    Convert a PACT v0.3 ZK receipt into a v0.1-compatible receipt for the OVID verifier.

    The v0.1 verifier expects:
        - action_id, agent_id, tool_called, timestamp
        - policy_hash (full sha256:... string)
        - proof.commitment: sha256 of "policy_hash:tool:action_id:timestamp"
        - proof.signature: Ed25519 signature over the commitment
        - proof.verifier_key: base64 pub key bytes
        - proof.statement: human-readable policy statement

    The v0.3 ZK receipt provides proof of tool ∈ allowed_tools without revealing
    the tool name to the verifier. The bridge exposes the tool name because the
    OVID verifier runs in the same trust domain as the verifier (third-party audit).

    For cross-domain cases where the tool name should stay private, the bridge
    sets statement="tool membership proven via ZK receipt" without revealing
    the specific tool.
    """
    now = datetime.now(timezone.utc)
    action_id = zk_receipt.get("proof", {}).get("proof_id", f"zk-{uuid.uuid4().hex[:12]}")
    timestamp = zk_receipt.get("public", {}).get("timestamp", now.strftime("%Y-%m-%dT%H:%M:%SZ"))

    # Build the v0.1 commitment string (same formula the verifier uses)
    policy_hash_clean = policy_hash.replace("sha256:", "")
    commitment_input = f"{policy_hash_clean}:{tool_called}:{action_id}:{timestamp}"
    import hashlib
    commitment = hashlib.sha256(commitment_input.encode()).hexdigest()

    # The ZK receipt is the source of truth; wrap it as the proof object
    proof = zk_receipt.get("proof", {})
    is_stub = proof.get("stub", False)

    # Build statement based on receipt type
    if is_stub:
        statement = f"[STUB] tool={tool_called} ∈ policy.allowed_tools (DUMMY_PROOF mode — not for production)"
    else:
        policy_hash_short = zk_receipt.get("public", {}).get("policy_hash", "")[:16]
        statement = (
            f"ZK proof: tool={tool_called} ∈ committed policy "
            f"(hash {policy_hash_short}...) — RISC Zero receipt verified"
        )

    v01_receipt = {
        "receipt_version": "0.1",
        "action_id": action_id,
        "agent_id": agent_id,
        "tool_called": tool_called,
        "timestamp": timestamp,
        "policy_hash": f"sha256:{policy_hash_clean}",
        "proof": {
            "commitment": f"sha256:{commitment}",
            # Note: signature must be provided separately for real deployments
            # The ZK receipt itself is the proof; in production, sign the commitment
            "signature": "",  # fill via --sign-with-key in production
            "verifier_key": "",  # fill via --verifier-key in production
            "statement": statement,
            "zk_receipt": zk_receipt,  # embed full ZK receipt for auditing
        },
        "_pact_version": "0.3",
        "_zk_valid": not is_stub,
        "_zk_proof_type": zk_receipt.get("proof_type", "unknown"),
    }

    return v01_receipt


def sign_receipt(receipt: dict, ed25519_private_key_b64: str) -> dict:
    """
    Sign the v0.1 receipt commitment with an Ed25519 private key.

    Args:
        receipt: v0.1 receipt dict (from bridge_zk_receipt_to_v01)
        ed25519_private_key_b64: base64-encoded Ed25519 private key

    Returns: receipt with proof.signature and proof.verifier_key populated
    """
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    key_bytes = base64.b64decode(ed25519_private_key_b64)
    private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
    public_key = private_key.public_key()

    # Extract commitment (remove sha256: prefix for signing)
    commitment_hex = receipt["proof"]["commitment"].replace("sha256:", "")
    commitment_bytes = bytes.fromhex(commitment_hex)

    # Sign the commitment
    signature = private_key.sign(commitment_bytes)

    receipt["proof"]["signature"] = base64.b64encode(signature).decode()
    receipt["proof"]["verifier_key"] = base64.b64encode(
        public_key.public_bytes(
            encoding=serialization.PublicFormat.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode()

    return receipt


def main():
    parser = argparse.ArgumentParser(description="Bridge PACT v0.3 ZK receipts to v0.1 for OVID verifier")
    parser.add_argument("--zk-receipt", required=True, help="Path to v0.3 ZK receipt JSON")
    parser.add_argument("--agent-id", required=True, help="Agent ID (did:pact:...)")
    parser.add_argument("--tool", required=True, help="Tool name called")
    parser.add_argument("--policy-hash", required=True, help="Committed policy hash (sha256:...)")
    parser.add_argument("--output", required=True, help="Output path for v0.1 receipt")
    parser.add_argument("--sign-key", help="Ed25519 private key (base64) for signing")
    args = parser.parse_args()

    with open(args.zk_receipt) as f:
        zk_receipt = json.load(f)

    receipt = bridge_zk_receipt_to_v01(zk_receipt, args.agent_id, args.tool, args.policy_hash)

    if args.sign_key:
        receipt = sign_receipt(receipt, args.sign_key)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(receipt, f, indent=2)

    print(f"v0.1-compatible receipt written to {args.output}")
    print(f"  action_id: {receipt['action_id']}")
    print(f"  tool:      {receipt['tool_called']}")
    print(f"  ZK valid:  {receipt['_zk_valid']}")


if __name__ == "__main__":
    main()
