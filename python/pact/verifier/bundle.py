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
    }
}

Chain integrity: each receipt's action_id hashes into the next, creating
an immutable sequence. The root is derived from first receipt's policy_hash
and first action_id. Verifier can recompute root from receipts and compare.

Usage:
    from verifier.bundle import build_bundle, verify_bundle
    bundle = build_bundle(receipts_dir)
    result = verify_bundle(bundle)

    # Save for transport
    bundle_path = "/tmp/pact-bundle-$(date +%s).json"
    json.dump(bundle, open(bundle_path, "w"))

    # Verify offline
    result = verify_bundle(bundle)
    if result["valid"]:
        print(f"Bundle valid: {result['chain_integrity']['count']} receipts")
    else:
        print(f"INVALID: {result['errors']}")
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
            inp = policy_hash_clean + action_id
        else:
            prev_action_id = receipts[i - 1].get("action_id", receipts[i - 1].get("receipt", {}).get("action_id", ""))
            inp = prev_action_id + action_id
        chain_inputs.append(inp)
        last_action_id = action_id

    # Compute root: SHA256 of all chain inputs concatenated
    concatenated = "".join(chain_inputs)
    root_hash = f"sha256:{hashlib.sha256(concatenated.encode('utf-8')).hexdigest()}"

    return {
        "type": "sha256_chain",
        "count": len(receipts),
        "root_hash": root_hash,
        "first_action_id": first_action_id,
        "last_action_id": last_action_id,
    }


def build_metadata(receipts: list[dict]) -> dict:
    """Build metadata from receipts."""
    tool_count = 0
    denied_count = 0
    for r in receipts:
        outcome = r.get("outcome", r.get("receipt", {}).get("outcome", ""))
        if outcome in ("permitted", "denied"):
            tool_count += 1
        if outcome == "denied":
            denied_count += 1
    return {
        "bundle_id": str(uuid.uuid4()),
        "tool_count": tool_count,
        "denied_count": denied_count,
    }


def build_bundle(receipts_dir: Path) -> dict:
    """
    Build a bundle from a directory of receipt JSON files.
    
    Args:
        receipts_dir: Path containing receipt JSON files (any naming)
    
    Returns:
        Bundle dict ready for transport/verification
    """
    receipt_files = sorted(receipts_dir.glob("*.json"))
    receipts = []
    for rf in receipt_files:
        with open(rf) as f:
            receipts.append(json.load(f))

    if not receipts:
        raise ValueError("No receipts found in directory")

    chain_integrity = compute_chain_root(receipts)
    metadata = build_metadata(receipts)

    # Agent ID from first receipt
    agent_id = receipts[0].get("agent_id", receipts[0].get("receipt", {}).get("agent_id", "unknown"))

    # Policy hash from first receipt
    policy_hash = receipts[0].get("policy_hash", receipts[0].get("receipt", {}).get("policy_hash", ""))

    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "agent_id": agent_id,
        "policy_hash": policy_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "receipts": receipts,
        "chain_integrity": chain_integrity,
        "metadata": metadata,
    }

    return bundle


def verify_chain_integrity(receipts: list[dict], stored_integrity: dict) -> tuple[bool, str]:
    """
    Verify chain integrity matches the stored value.
    Returns (valid, reason).
    """
    computed = compute_chain_root(receipts)
    if computed["root_hash"] != stored_integrity.get("root_hash"):
        return False, f"Chain root mismatch: expected {stored_integrity['root_hash']}, computed {computed['root_hash']}"
    if computed["count"] != stored_integrity.get("count"):
        return False, f"Receipt count mismatch: expected {stored_integrity['count']}, got {computed['count']}"
    return True, "chain_integrity valid"


def verify_receipt_structure(receipt: dict) -> tuple[bool, list[str]]:
    """
    Verify a single receipt has required fields.
    Returns (valid, errors).
    """
    errors = []
    required = ["action_id", "outcome", "timestamp"]
    for field in required:
        if field not in receipt:
            # Check inside receipt sub-dict too
            if field not in receipt.get("receipt", {}):
                errors.append(f"Missing field: {field}")
    return len(errors) == 0, errors


def verify_bundle(bundle: dict) -> dict:
    """
    Full verification of a PACT receipt bundle.
    
    Returns:
        {
            "valid": bool,
            "bundle_id": str,
            "chain_integrity": {"pass": bool, "reason": str},
            "receipts": {"count": int, "valid": int, "errors": int},
            "errors": [str],
        }
    """
    result = {
        "valid": False,
        "bundle_id": bundle.get("metadata", {}).get("bundle_id", "unknown"),
        "chain_integrity": {"pass": False, "reason": ""},
        "receipts": {"count": 0, "valid": 0, "errors": 0},
        "errors": [],
    }

    # Check bundle version
    if bundle.get("bundle_version") != BUNDLE_VERSION:
        result["errors"].append(f"Bundle version mismatch: expected {BUNDLE_VERSION}, got {bundle.get('bundle_version')}")

    # Check receipts present
    receipts = bundle.get("receipts", [])
    if not receipts:
        result["errors"].append("No receipts in bundle")
        return result

    result["receipts"]["count"] = len(receipts)

    # Verify each receipt structure
    for i, receipt in enumerate(receipts):
        valid, errors = verify_receipt_structure(receipt)
        if valid:
            result["receipts"]["valid"] += 1
        else:
            result["receipts"]["errors"] += 1
            result["errors"].extend([f"Receipt {i}: {e}" for e in errors])

    # Verify chain integrity
    chain_valid, chain_reason = verify_chain_integrity(receipts, bundle.get("chain_integrity", {}))
    result["chain_integrity"] = {"pass": chain_valid, "reason": chain_reason}
    if not chain_valid:
        result["errors"].append(f"Chain integrity: {chain_reason}")

    # Overall
    if not result["errors"]:
        result["valid"] = True

    return result


def verify_bundle_from_file(bundle_path: str) -> dict:
    """Load and verify a bundle file."""
    with open(bundle_path) as f:
        bundle = json.load(f)
    return verify_bundle(bundle)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Build or verify PACT receipt bundles")
    parser.add_argument("command", choices=["build", "verify"])
    parser.add_argument("--input", help="Receipts dir (build) or bundle file (verify)")
    parser.add_argument("--output", help="Output file path")
    args = parser.parse_args()

    if args.command == "build":
        bundle = build_bundle(Path(args.input))
        output = open(args.output, "w") if args.output else sys.stdout
        json.dump(bundle, output, indent=2)
        if args.output:
            print(f"Bundle written to {args.output}", file=sys.stderr)
    elif args.command == "verify":
        result = verify_bundle_from_file(args.input)
        print(json.dumps(result, indent=2))
        if not result["valid"]:
            sys.exit(1)


if __name__ == "__main__":
    main()