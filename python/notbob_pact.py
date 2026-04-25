#!/usr/bin/env python3
"""
notbob_pact.py — Commit NotBob's policy and demonstrate a real PACT receipt.

Usage:
    python3 notbob_pact.py [--commit] [--receipt TOOL_NAME]

Options:
    --commit    Register the policy in the transparency log (one-time)
    --receipt   Generate a PACT receipt for a tool call (default: web_search)
"""

import argparse
import hashlib
import json
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

_PACT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PACT_ROOT / "python"))

from pact import create_policy, generate_receipt, verify_receipt
from pact.transparency import register_policy


def load_notbob_policy():
    policy_path = _PACT_ROOT / "notbob-policy.json"
    with open(policy_path) as f:
        raw = json.load(f)
    return raw


def commit_notbob_policy(policy_json: dict) -> dict:
    """Commit NotBob's policy to the transparency log."""
    # Compute the policy hash (excluding the zk_policy_hash placeholder)
    policy_for_hash = {k: v for k, v in policy_json.items() if k != "zk_policy_hash"}
    policy_str = json.dumps(policy_for_hash, sort_keys=True)
    policy_hash = f"sha256:{hashlib.sha256(policy_str.encode()).hexdigest()}"
    
    # Update the placeholder
    policy_json["zk_policy_hash"] = policy_hash
    policy_json["policy"]["committed_at"] = datetime.now(timezone.utc).isoformat()
    
    # Register with transparency log
    policy_str_committed = json.dumps(policy_json, sort_keys=True, indent=2)
    anchor = register_policy(policy_str_committed, policy_json["agent"]["did"])
    
    print(f"[COMMIT] Policy hash: {policy_hash}")
    print(f"[COMMIT] Anchored at: {anchor.get('entry_id', anchor.get('index', 'local'))}")
    
    # Save committed policy
    committed_path = _PACT_ROOT / "notbob-policy.committed.json"
    with open(committed_path, "w") as f:
        f.write(policy_str_committed)
    print(f"[COMMIT] Saved to: {committed_path}")
    
    return anchor


def generate_notbob_receipt(tool_name: str, tool_params: dict, policy: dict, anchor: dict):
    """Generate a PACT receipt for a NotBob tool call."""
    receipt, outcome, reason = generate_receipt(policy, tool_name, tool_params)
    
    # Verify
    result = verify_receipt(receipt, policy)
    
    print(f"[RECEIPT] Tool: {tool_name}")
    print(f"[RECEIPT] Outcome: {outcome} — {reason}")
    print(f"[RECEIPT] Verified: {'✓' if result['valid'] else '✗'} {result['reason']}")
    print(f"[RECEIPT] Receipt ID: {receipt['action_id']}")
    print(f"[RECEIPT] Version: {receipt.get('receipt_version', '0.1')}")
    
    # Save receipt
    receipts_dir = _PACT_ROOT / "receipts"
    receipts_dir.mkdir(exist_ok=True)
    receipt_path = receipts_dir / f"{receipt['action_id']}.json"
    with open(receipt_path, "w") as f:
        json.dump(receipt, f, indent=2)
    print(f"[RECEIPT] Saved to: {receipt_path}")
    
    return receipt, outcome, result


def main():
    parser = argparse.ArgumentParser(description="NotBob PACT — policy commitment and receipt generation")
    parser.add_argument("--commit", action="store_true", help="Commit NotBob's policy to the transparency log")
    parser.add_argument("--receipt", default="web_search", help="Tool name for receipt demo (default: web_search)")
    args = parser.parse_args()

    print("=" * 60)
    print("NotBob PACT — Policy Attestation via Cryptographic Trace")
    print("=" * 60)
    print()

    # Load policy
    policy_json = load_notbob_policy()
    agent_id = policy_json["agent"]["did"]
    print(f"[LOAD] NotBob policy for: {agent_id}")
    print(f"[LOAD] Mission: {policy_json['agent']['mission'][:60]}...")
    print()

    # Commit policy
    anchor = None
    if args.commit:
        print("[COMMIT] Committing NotBob policy to transparency log...")
        anchor = commit_notbob_policy(policy_json)
        print()
    else:
        # Try to load committed policy
        committed_path = _PACT_ROOT / "notbob-policy.committed.json"
        if committed_path.exists():
            with open(committed_path) as f:
                policy_json = json.load(f)
            print(f"[LOAD] Using previously committed policy")
            print()
            # Reconstruct anchor from committed policy
            anchor = {
                "entry_id": "previously_committed",
                "policy_hash": policy_json.get("zk_policy_hash", "").replace("sha256:", "")
            }
        else:
            print("[WARN] Policy not yet committed. Run with --commit first.")
            print()

    # Generate receipt for tool call
    tool_params = {
        "query": "ZK proofs agent accountability production 2026",
        "limit": 5
    }
    if args.receipt:
        # Build a minimal policy dict compatible with generate_receipt
        policy_for_receipt = {
            "policy_hash": policy_json.get("zk_policy_hash", "sha256:").replace("sha256:", ""),
            "policy": policy_json.get("policy", {}),
            "agent_id": agent_id
        }
        print(f"[RECEIPT] Generating receipt for: {args.receipt}")
        receipt, outcome, result = generate_notbob_receipt(
            args.receipt, tool_params, policy_for_receipt, anchor
        )

    print()
    print("=" * 60)
    print("Done.")


if __name__ == "__main__":
    main()
