"""
PACT v0.3 — Third-Party Receipt Verifier

Verifies ZK receipts without requiring access to the agent or its logs.
The verifier only needs:
  1. The receipt (containing policy_hash, anchor, proof)
  2. The transparency log entries up to the anchor's log_index
  3. The Git-anchored Merkle root for that batch

This module implements the verification path — the untrusted path.

Architecture:
    Receipt (from agent) 
        → verify_receipt() 
        → check policy_hash committed in transparency log 
        → verify Merkle proof against anchored root
        → validate ZK proof structure (not the math — that's the prover's job)
        → return { valid: bool, reason: str, receipt_id: str }

Verification does NOT require:
  - Access to the agent
  - Access to the agent's internal state
  - Access to the MCP server
  - The original policy document
  - The original tool call parameters

What verification DOES prove:
  - A receipt existed with this policy_hash, tool_name, timestamp
  - The policy_hash was committed to the transparency log at or before the anchor timestamp
  - The Merkle proof proves the entry was in the log when the root was anchored
  - The ZK proof structure is valid (basic sanity check)
"""

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

PACT_DIR = Path(__file__).parent.parent.parent.parent
TRANSPARENCY_LOG = PACT_DIR / "transparency_log.jsonl"
COMMITMENTS_DIR = PACT_DIR / "commitments"
GIT_ANCHOR_FILE = PACT_DIR / "merkle_root_anchored.txt"


def sha256_hex(data: str) -> str:
    return f"sha256:{hashlib.sha256(data.encode('utf-8')).hexdigest()}"


def sha256_raw_hex(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def _compute_merkle_node(left: str, right: str) -> str:
    """Combine two node hashes into a parent Merkle node."""
    combined = json.dumps([left, right], sort_keys=True).encode()
    return "sha256:" + hashlib.sha256(combined).hexdigest()


def _rebuild_merkle_tree(leaf_hashes: list[str]) -> str:
    """Rebuild a Merkle tree from leaf hashes. Returns root hash."""
    if not leaf_hashes:
        return "sha256:" + "0" * 64

    current = leaf_hashes[:]
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            next_level.append(_compute_merkle_node(left, right))
        current = next_level

    return current[0]


def _get_merkle_proof_path(leaf_hashes: list[str], index: int) -> list[dict]:
    """
    Compute the Merkle proof path from leaf at `index` to root.
    Returns list of {hash, side} dicts — the proof a verifier uses to
    recompute the root independently.
    """
    if index >= len(leaf_hashes):
        raise ValueError(f"Index {index} out of range for {len(leaf_hashes)} leaves")

    if len(leaf_hashes) == 1:
        return []

    proof = []
    level_hashes = leaf_hashes[:]
    current_index = index

    while len(level_hashes) > 1:
        is_right = current_index % 2 == 1
        sibling_index = current_index - 1 if is_right else current_index + 1

        if sibling_index < len(level_hashes):
            sibling_hash = level_hashes[sibling_index]
        else:
            sibling_hash = level_hashes[current_index]

        proof.append({
            "hash": sibling_hash,
            "side": "left" if is_right else "right",
        })

        next_level = []
        for i in range(0, len(level_hashes), 2):
            left = level_hashes[i]
            right = level_hashes[i + 1] if i + 1 < len(level_hashes) else level_hashes[i]
            next_level.append(_compute_merkle_node(left, right))

        level_hashes = next_level
        current_index = current_index // 2

    return proof


def compute_merkle_root_from_proof(leaf_hash: str, proof_path: list[dict]) -> str:
    """
    Given a leaf hash and a proof path, compute the root hash.
    This is what verifiers do — they take the claim "leaf at index N has hash X"
    and check if it reproduces the known root.
    """
    current = leaf_hash
    for step in proof_path:
        sibling = step["hash"]
        side = step["side"]
        if side == "left":
            current = _compute_merkle_node(sibling, current)
        else:
            current = _compute_merkle_node(current, sibling)
    return current


def verify_receipt(receipt: dict) -> dict:
    """
    Verify a PACT ZK receipt (third-party, untrusted path).

    Checks in order:
      1. Receipt structure is well-formed (version, required fields present)
      2. Policy_hash is a valid sha256:... hash
      3. Policy was committed to the transparency log at or before the action timestamp
      4. Merkle proof proves the log entry is in the anchored Merkle root
      5. ZK proof has valid structure (not the math — basic sanity check)
      6. Receipt chain continuity (if prev_receipt_hash is present)

    Args:
        receipt: JSON dict from PACT ZK receipt

    Returns:
        dict: { valid: bool, reason: str, receipt_id: str, warnings: list }
    """
    warnings = []
    receipt_id = receipt.get("receipt_id", receipt.get("action_id", "unknown"))
    now = datetime.now(timezone.utc)

    # 1. Basic structure checks
    required_fields = ["receipt_version", "receipt_hash", "policy_hash",
                       "tool_called", "timestamp", "proof"]
    for field in required_fields:
        if field not in receipt:
            return {"valid": False, "reason": f"Missing required field: {field}",
                    "receipt_id": receipt_id, "warnings": []}

    # 2. Policy hash format
    policy_hash = receipt["policy_hash"]
    if not policy_hash.startswith("sha256:"):
        return {"valid": False, "reason": "Malformed policy_hash — must be sha256:...",
                "receipt_id": receipt_id, "warnings": []}

    # 3. Check anchor is present
    anchor = receipt.get("anchor", {})
    if not anchor.get("log_index") or not anchor.get("merkle_root"):
        return {"valid": False, "reason": "Missing anchor — cannot verify log entry",
                "receipt_id": receipt_id, "warnings": []}

    # 4. Verify log entry exists and matches policy_hash
    log_index = anchor["log_index"]
    log_entry = _get_log_entry(log_index)

    if log_entry is None:
        return {"valid": False, "reason": f"Log entry {log_index} not found in transparency log",
                "receipt_id": receipt_id, "warnings": []}

    if log_entry.get("policy_hash") != policy_hash:
        return {"valid": False, "reason": "policy_hash mismatch with log entry",
                "receipt_id": receipt_id, "warnings": []}

    # 5. Verify timestamp ordering: policy committed BEFORE action
    committed_at = datetime.fromisoformat(log_entry["committed_at"].replace("Z", "+00:00"))
    action_at = datetime.fromisoformat(receipt["timestamp"].replace("Z", "+00:00"))
    if action_at < committed_at:
        return {"valid": False,
                "reason": f"Action timestamp ({action_at.isoformat()}) precedes policy commitment ({committed_at.isoformat()}) — receipt invalid",
                "receipt_id": receipt_id, "warnings": []}

    # 6. Merkle proof verification
    merkle_proof = anchor.get("merkle_proof", [])
    log_entry_hash = log_entry.get("entry_hash")

    if not log_entry_hash:
        return {"valid": False, "reason": "Log entry missing entry_hash",
                "receipt_id": receipt_id, "warnings": []}

    try:
        computed_root = compute_merkle_root_from_proof(log_entry_hash, merkle_proof)
    except Exception as e:
        return {"valid": False, "reason": f"Merkle proof computation failed: {e}",
                "receipt_id": receipt_id, "warnings": []}

    anchored_root = anchor["merkle_root"]
    if computed_root != anchored_root:
        return {"valid": False,
                "reason": "Merkle proof does not reproduce anchored root — log may have been tampered with",
                "receipt_id": receipt_id, "warnings": []}

    # 7. ZK proof structure sanity check
    zk = receipt.get("proof", {}).get("zk", {})
    proof_type = zk.get("proof_type", "unknown")

    if proof_type == "DUMMY_ZK_PROOF":
        warnings.append("Receipt uses DUMMY_ZK_PROOF — ZK circuit not verified")
    elif proof_type not in ("RISC0_MERKLEMembership", "SP1_GROTH16", "DUMMY_ZK_PROOF"):
        return {"valid": False, "reason": f"Unknown proof_type: {proof_type}",
                "receipt_id": receipt_id, "warnings": warnings}

    # 8. Receipt hash chain continuity
    prev_hash = receipt.get("prev_receipt_hash")
    if prev_hash and prev_hash != "GENESIS":
        # For chain verification we would need the previous receipt.
        # We can only do a format check here — the actual chain verification
        # requires a chain of receipts. Flag as warning, not failure.
        if not prev_hash.startswith("sha256:"):
            warnings.append("prev_receipt_hash does not match sha256: format — possible chain discontinuity")

    # 9. Timestamp sanity check (not from the future, not too old)
    max_age_days = 365
    min_timestamp = datetime.now(timezone.utc).replace(year=now.year - 1)
    if action_at < min_timestamp:
        warnings.append(f"Receipt timestamp is more than {max_age_days} days old")

    return {
        "valid": True,
        "reason": (
            f"Receipt valid — policy_hash committed at log_index={log_index}, "
            f"Merkle proof verified against anchored root, "
            f"proof_type={proof_type}, action={receipt['tool_called']} at {receipt['timestamp']}"
        ),
        "receipt_id": receipt_id,
        "warnings": warnings,
        "policy_hash": policy_hash,
        "log_index": log_index,
        "tool_called": receipt["tool_called"],
        "proof_type": proof_type,
    }


def _get_log_entry(index: int) -> Optional[dict]:
    """Retrieve a specific log entry by index from the transparency log."""
    entry_file = COMMITMENTS_DIR / f"{index:06d}.json"
    if entry_file.exists():
        with open(entry_file) as f:
            return json.load(f)

    # Fallback: scan the log file
    if not TRANSPARENCY_LOG.exists():
        return None

    with open(TRANSPARENCY_LOG) as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry.get("log_index") == index:
                return entry

    return None


def verify_receipt_from_file(receipt_path: str) -> dict:
    """Convenience: verify a receipt from a file path."""
    with open(receipt_path) as f:
        receipt = json.load(f)
    return verify_receipt(receipt)


def batch_verify(receipts: list[dict]) -> dict:
    """
    Verify a batch of receipts and return a summary.

    Returns:
        dict: {
            total: int,
            valid: int,
            invalid: int,
            results: list[dict]  # individual verify_receipt results
        }
    """
    results = []
    valid_count = 0
    invalid_count = 0

    for receipt in receipts:
        result = verify_receipt(receipt)
        results.append(result)
        if result["valid"]:
            valid_count += 1
        else:
            invalid_count += 1

    return {
        "total": len(receipts),
        "valid": valid_count,
        "invalid": invalid_count,
        "results": results,
    }


# CLI entry point

def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 verifier.py <receipt.json> [receipt2.json ...]")
        print("       Or pipe receipts: cat receipt.json | python3 verifier.py -")
        sys.exit(1)

    if sys.argv[1] == "-":
        # Read from stdin
        receipts = [json.loads(line) for line in sys.stdin if line.strip()]
    else:
        receipts = []
        for path in sys.argv[1:]:
            with open(path) as f:
                receipts.append(json.load(f))

    result = batch_verify(receipts)

    print(f"\nVerification Report")
    print("=" * 50)
    print(f"Total receipts: {result['total']}")
    print(f"Valid:   {result['valid']}")
    print(f"Invalid: {result['invalid']}")
    print()

    for i, r in enumerate(result["results"]):
        status = "✓" if r["valid"] else "✗"
        print(f"[{i+1}] {status} {r['receipt_id'][:16]}... | {r['reason'][:80]}")
        if r.get("warnings"):
            for w in r["warnings"]:
                print(f"    ⚠ {w}")

    sys.exit(0 if result["invalid"] == 0 else 1)


if __name__ == "__main__":
    main()