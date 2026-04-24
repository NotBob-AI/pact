#!/usr/bin/env python3
"""
demo.py — PACT End-to-End Demo CLI

Simulates a policy commitment, intercepts a tool call,
generates a ZK receipt, and verifies it.

Usage:
    PYTHONPATH=path/to/pact/python python3 demo.py [--zk] [--verbose]
"""

import argparse
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Resolve pact package relative to this file
_PACT_ROOT = Path(__file__).parent
sys.path.insert(0, str(_PACT_ROOT))

from pact import create_policy, generate_receipt, verify_receipt
from pact.transparency import register_policy


def sha256_hex(data: str) -> str:
    return f"sha256:{hashlib.sha256(data.encode('utf-8')).hexdigest()}"


def run_demo(use_zk: bool = True, verbose: bool = False):
    print("=" * 60)
    print("PACT End-to-End Demo")
    print("=" * 60)
    print()

    agent_id = "did:key:z6Mkdemo123456789"

    # Layer 1: Create + commit policy
    policy = create_policy(
        agent_id=agent_id,
        allowed_tools=["read_file", "search_web", "send_email"],
        denied_tools=["delete_file", "execute_code", "access_credentials"],
    )
    policy_hash = policy["policy_hash"]
    print(f"[1] Policy created for agent: {agent_id}")
    print(f"    Allowed tools: {policy['policy']['allowed_tools']}")
    print(f"    Denied tools: {policy['policy']['denied_tools']}")
    print(f"    Policy hash: {policy_hash}")
    print()

    # Layer 1: Anchor in transparency log
    # Layer 1: Register + anchor policy in transparency log
    # Uses local file fallback if siglog server unavailable
    policy_str = json.dumps(policy, sort_keys=True)
    anchor = register_policy(policy_str, agent_id)
    print(f"[2] Policy anchored — entry_id: {anchor.get('entry_id', anchor.get('index', 'local'))}")
    print()

    # Layer 0: Simulated tool call
    tool_name = "search_web"
    tool_params = {"query": "decentralized identity 2026", "limit": 5}
    print(f"[3] Tool call intercepted: {tool_name}({tool_params})")
    print()

    # Layer 2: Receipt generation — v0.1 (always)
    print("[4] Generating PACT v0.1 receipt...")
    receipt, outcome, reason = generate_receipt(policy, tool_name, tool_params)
    print(f"    outcome: {outcome}")
    print(f"    reason: {reason}")
    print(f"    receipt_id: {receipt['action_id']}")
    print(f"    policy_hash: {receipt['policy_hash']}")
    print()

    # Layer 2: ZK receipt — v0.3 (if zk_host is wired)
    if use_zk:
        print("[5] Generating PACT v0.3 ZK receipt (DUMMY_PROOF mode)...")
        try:
            from pact.zk_host import generate_stub_receipt, build_public_inputs
            anchor_dict = {
                "log_index": anchor.get("index", 0),
                "log_id": anchor.get("entry_id", anchor.get("log_id", "local")),
                "merkle_root": anchor.get("merkle_root", policy_hash),
            }
            pub_inputs = build_public_inputs(policy, tool_name, anchor_dict, tool_params)
            zk_receipt = generate_stub_receipt(pub_inputs, policy, tool_name)
            print(f"    proof_type: {zk_receipt['proof_type']}")
            print(f"    circuit_id: {zk_receipt['circuit_id']}")
            print(f"    circuit_output: {zk_receipt['proof']['circuit_output']}")
            print(f"    guest_image_id: {zk_receipt['host_info']['guest_image_id'][:32]}...")
        except Exception as e:
            print(f"    ZK receipt skipped: {e}")

    # Show receipt
    print("[5] Receipt:")
    receipt_out = json.dumps(receipt, indent=2)
    if verbose:
        print(receipt_out)
    else:
        print(receipt_out[:600] + "..." if len(receipt_out) > 600 else receipt_out)
    print()

    # Layer 3: Verification
    print("[6] Verifying receipt against committed policy...")
    result = verify_receipt(receipt, policy)
    status = "✓ valid" if result["valid"] else "✗ invalid"
    print(f"    {status} — {result['reason']}")
    print()

    # Denied tool test
    print("[7] Testing denied tool (execute_code)...")
    receipt2, outcome2, reason2 = generate_receipt(policy, "execute_code", {})
    print(f"    outcome: {outcome2}")
    print(f"    reason: {reason2}")
    result2 = verify_receipt(receipt2, policy)
    print(f"    verified: {result2['valid']}")
    print()

    print("=" * 60)
    print("Demo complete.")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PACT End-to-End Demo CLI")
    parser.add_argument("--no-zk", dest="zk", action="store_false",
                       help="Skip ZK (force v0.1 only)")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Show full receipt JSON")
    args = parser.parse_args()

    run_demo(use_zk=args.zk, verbose=args.verbose)
