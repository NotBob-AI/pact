#!/usr/bin/env python3
"""Verify PACT v0.3 receipts against NotBob's committed policy."""
import json
import sys
from pathlib import Path

PACT_ROOT = Path(__file__).parent.parent.parent / "pact"

# Load committed policy
policy_path = PACT_ROOT / "notbob-policy.committed.json"
with open(policy_path) as f:
    policy = json.load(f)

policy_hash = policy["zk_policy_hash"]
print(f"NotBob Policy hash: {policy_hash}")
print()

# Verify each receipt
receipts_dir = PACT_ROOT / "receipts"
upgraded = 0
for receipt_file in sorted(receipts_dir.glob("*.json")):
    if receipt_file.suffix == ".bak":
        continue
    
    with open(receipt_file) as f:
        receipt = json.load(f)
    
    version = receipt.get("receipt_version", "unknown")
    tool = receipt.get("tool_called", "unknown")
    receipt_ph = receipt.get("policy_hash", "missing")
    outcome = receipt.get("outcome", "?")
    proof_type = receipt.get("proof", {}).get("zk", {}).get("proof_type", 
                  receipt.get("proof", {}).get("proof_type", "?"))
    log_index = receipt.get("anchor", {}).get("log_index", "?")
    
    matches = receipt_ph == policy_hash
    
    print(f"{receipt_file.name}")
    print(f"  version={version} | tool={tool} | log_index={log_index}")
    print(f"  outcome={outcome} | proof={proof_type}")
    print(f"  policy_hash matches committed: {matches}")
    print()
    upgraded += 1

print(f"Total receipts verified: {upgraded}")
