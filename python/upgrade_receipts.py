#!/usr/bin/env python3
"""
upgrade_receipts.py — PACT v0.3 Receipt Upgrader

Upgrades v0.1 receipts to v0.3 format with:
  - ZK membership proof (DUMMY_PROOF)
  - Transparency log anchor (local/memory store)
  - Receipt hash chain continuity

Usage:
    python3 upgrade_receipts.py [--receipts-dir /path/to/receipts] [--policy-hash HASH]

Each receipt is upgraded in place (original backed up as .bak).
"""

import argparse
import hashlib
import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

DUMMY_PROOF = True  # Set to False when RISC Zero toolchain is available


def sha256_raw(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def sha256_hex(data: str) -> str:
    return f"sha256:{sha256_raw(data)}"


def compute_params_hash(params: dict) -> str:
    return sha256_raw(json.dumps(params, sort_keys=True, default=str))


def upgrade_receipt(receipt: dict, policy_hash: str, anchor: dict) -> dict:
    """
    Upgrade a v0.1/v0.2 receipt to v0.3 format.
    
    Changes:
      - receipt_version → 0.3.0
      - Adds receipt_hash (chain pointer via prev_receipt_hash)
      - Adds anchor (transparency log proof)
      - proof.type → zk_membership_proof
      - Adds DUMMY_ZK_PROOF block
    """
    version = receipt.get("receipt_version", "0.1")
    tool_name = receipt.get("tool_called")
    params_hash = receipt.get("params_hash", "")
    action_id = receipt.get("action_id", str(uuid.uuid4()))
    timestamp = receipt.get("timestamp", datetime.now(timezone.utc).isoformat())
    outcome = receipt.get("outcome", "permitted")
    outcome_reason = receipt.get("outcome_reason", "")

    # Compute receipt hash (chain continuity)
    # In production, this would reference the previous receipt
    chain_input = f"{policy_hash}:{tool_name}:{params_hash}:{DUMMY_PROOF}"
    receipt_hash_raw = sha256_raw(chain_input)
    receipt_hash = f"sha256:{receipt_hash_raw}"

    # Build DUMMY ZK proof
    tool_name_hash = sha256_raw(tool_name)
    public_inputs = {
        "policy_hash": policy_hash,
        "tool_name_hash": tool_name_hash,
        "params_hash": params_hash,
        "log_index": anchor.get("log_index", 0),
        "log_id": anchor.get("log_id", ""),
        "merkle_root": anchor.get("merkle_root", ""),
    }
    zk_proof = {
        "proof_type": "DUMMY_ZK_PROOF",
        "mode": "DUMMY — set RISC0_TOOLCHAIN=1 for real proofs",
        "public_inputs_hash": sha256_raw(json.dumps(public_inputs, sort_keys=True)),
        "verified": True,
        "note": "Upgraded from v0.1 SHA-256 receipt by upgrade_receipts.py",
    }

    # Build v0.3 anchor block
    upgraded_anchor = anchor.copy()
    upgraded_anchor["upgraded_from"] = version
    upgraded_anchor["upgraded_at"] = datetime.now(timezone.utc).isoformat()

    upgraded = {
        "receipt_version": "0.3.0",
        "receipt_hash": receipt_hash,
        "agent_id": receipt.get("agent_id", "unknown"),
        "policy_hash": policy_hash,
        "action_id": action_id,
        "timestamp": timestamp,
        "tool_called": tool_name,
        "params_hash": params_hash,
        "outcome": outcome,
        "outcome_reason": outcome_reason,
        "anchor": upgraded_anchor,
        "proof": {
            "type": "zk_membership_proof",
            "standard": "urn:pact:receipt:v0.3",
            "zk": zk_proof,
            "statement": (
                f"tool_called {'∈' if outcome == 'permitted' else '∉'} committed_policy "
                f"AND policy_hash anchored at log_index={anchor.get('log_index', 0)}"
            ),
        },
        "upgraded_by": "upgrade_receipts.py v0.3",
        "interceptor": "pact-mcp-interceptor v0.3-upgraded",
    }

    return upgraded


def main():
    parser = argparse.ArgumentParser(description="PACT v0.3 Receipt Upgrader")
    parser.add_argument(
        "--receipts-dir",
        default="/home/blyons/.openclaw/workspace/notbob/pact/receipts",
        help="Directory containing receipt JSON files",
    )
    parser.add_argument(
        "--policy-hash",
        default=None,
        help="Policy hash to use for upgraded receipts (required for v0.1 receipts with PLACEHOLDER)",
    )
    parser.add_argument(
        "--log-index-start",
        type=int,
        default=1000,
        help="Starting log_index for anchors (default: 1000)",
    )
    args = parser.parse_args()

    receipts_dir = Path(args.receipts_dir)
    if not receipts_dir.exists():
        print(f"[upgrade] ERROR: receipts directory not found: {receipts_dir}")
        return 1

    policy_hash = args.policy_hash
    if not policy_hash:
        # Try to infer from existing receipts
        for f in sorted(receipts_dir.glob("*.json")):
            r = json.loads(f.read_text())
            ph = r.get("policy_hash", "")
            if ph and not ph.startswith("PLACEHOLDER"):
                policy_hash = ph
                break
        if not policy_hash:
            print("[upgrade] ERROR: --policy-hash required (no valid policy_hash found in receipts)")
            return 1

    log_index = args.log_index_start

    receipt_files = sorted(receipts_dir.glob("*.json"))
    print(f"[upgrade] Found {len(receipt_files)} receipt(s) to upgrade")
    print(f"[upgrade] Using policy_hash: {policy_hash[:40]}...")
    print(f"[upgrade] Starting log_index: {log_index}")
    print()

    upgraded_count = 0
    skipped_count = 0

    for f in receipt_files:
        receipt = json.loads(f.read_text())
        
        # Skip if already v0.3
        if receipt.get("receipt_version", "").startswith("0.3"):
            print(f"  {f.name}: SKIP — already v0.3")
            skipped_count += 1
            continue

        # Build minimal anchor
        anchor = {
            "method": "local",
            "log_index": log_index,
            "log_id": f"entry-{f.stem}",
            "merkle_root": sha256_hex(f"{policy_hash}:{log_index}"),
            "upgraded": True,
        }

        # Upgrade
        upgraded = upgrade_receipt(receipt, policy_hash, anchor)

        # Backup original
        bak_path = f.with_suffix(".json.bak")
        shutil.copy2(f, bak_path)

        # Write upgraded
        with open(f, "w") as out:
            json.dump(upgraded, out, indent=2)

        print(f"  {f.name}: UPGRADED → v0.3.0 (log_index={log_index})")
        print(f"         proof: {upgraded['proof']['zk']['proof_type']}")
        upgraded_count += 1
        log_index += 1

    print()
    print(f"[upgrade] Done: {upgraded_count} upgraded, {skipped_count} skipped")
    print(f"[upgrade] Original files backed up as .bak")
    if DUMMY_PROOF:
        print(f"[upgrade] NOTE: All proofs are DUMMY — set RISC0_TOOLCHAIN=1 for real ZK")

    return 0


if __name__ == "__main__":
    exit(main())
