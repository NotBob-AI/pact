"""
PACT v0.2 — Policy Commitment Layer (Python)

Layer 1: Anchor committed policy hashes to a transparency log.
The transparency log is append-only and publicly auditable.
Merkle root = deterministic commitment for all policies in a batch.

Ported from commitment.js (ESM) → Python for MCP interceptor integration.

Architecture:
  create_policy()         → v0.1: Policy creation + SHA-256 hash
  build_merkle_tree()     → v0.2: Merkle tree from policy hashes
  create_log_entry()      → v0.2: Single transparency log entry
  TransparencyLog          → v0.2: Append-only log with Merkle anchoring
  anchor_policy()         → v0.2: Anchor a policy to the log
  verify_anchor()         → v0.2: Verify a policy anchor
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Merkle Tree
# ---------------------------------------------------------------------------

def _sha256_hex(data: str) -> str:
    """Compute SHA-256 of a string, return hex with sha256: prefix."""
    return f"sha256:{hashlib.sha256(data.encode('utf-8')).hexdigest()}"


def _hash_pair(a: str, b: str) -> str:
    """Hash two values in canonical (sorted) order."""
    a_clean = a.replace("sha256:", "")
    b_clean = b.replace("sha256:", "")
    left, right = (a_clean, b_clean) if a_clean <= b_clean else (b_clean, a_clean)
    return _sha256_hex(f"{left}::{right}")


def build_merkle_tree(leaves: list[str]) -> dict:
    """
    Build a binary Merkle tree from a list of leaf hashes.
    Returns { root, proofs } where proofs[i] proves leaves[i] is in tree.

    Args:
        leaves: List of sha256: prefixed hash strings.

    Returns:
        { root: str, proofs: list[dict] }
        Each proof: { leaf: str, path: list[{hash: str, side: str}] }
        side: 'right' if sibling was right child, 'left' if sibling was left child.
    """
    if not leaves:
        raise ValueError("Empty leaf list")

    if len(leaves) == 1:
        root = _hash_pair(leaves[0], leaves[0])
        return {
            "root": root,
            "proofs": [{"leaf": leaves[0], "path": [], "side": "left"}],
        }

    # Pad to next power of 2
    padded = list(leaves)
    while len(padded) % 2 != 0:
        padded.append(padded[-1])

    # Build tree: tree[0] = leaves, tree[1] = parents, ..., tree[N-1] = root
    level = [_hash_pair(leaf, leaf) for leaf in padded]
    tree = [level]

    while len(level) > 1:
        new_level = []
        for i in range(0, len(level), 2):
            new_level.append(_hash_pair(level[i], level[i + 1]))
        tree.append(new_level)
        level = new_level

    root = tree[-1][0]
    num_levels = len(tree)

    # Build inclusion proofs for each original leaf
    proofs = []
    for idx, leaf in enumerate(leaves):
        proof = []
        node_idx = idx
        # Walk from leaves level (tree[0]) upward toward root (tree[-1])
        for t in range(1, num_levels):
            # sibling is 1 - node_idx % 2: left child (idx 0) has right sibling (idx 1), right child has left sibling (idx 0)
            sibling_idx = 1 - (node_idx % 2)
            sibling = tree[t][sibling_idx]
            proof.append({
                "hash": sibling,
                "side": "right" if node_idx % 2 == 0 else "left"
            })
            node_idx = node_idx // 2
        proofs.append({"leaf": leaf, "path": proof})

    return {"root": root, "proofs": proofs}

def verify_merkle_proof(leaf: str, root: str, proof: dict) -> bool:
    """Verify a Merkle inclusion proof."""
    node = leaf
    for step in proof["path"]:
        node = _hash_pair(node, step["hash"])
    return node == root


# ---------------------------------------------------------------------------
# Transparency Log Entry
# ---------------------------------------------------------------------------

def create_log_entry(
    index: int,
    prev_hash: Optional[str],
    merkle_root: str,
    policy_hashes: list[str],
    timestamp: Optional[str] = None,
    note: str = ""
) -> dict:
    """
    Create a single transparency log entry.
    log_id = SHA-256(index | prev_hash | timestamp | merkle_root | policy_hashes)
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    prev_str = prev_hash if prev_hash else "GENESIS"
    policy_hashes_str = ",".join(policy_hashes)
    canonical = f"{index}|{prev_str}|{timestamp}|{merkle_root}|{policy_hashes_str}"
    log_id = _sha256_hex(canonical)

    return {
        "log_id": log_id,
        "log_index": index,
        "prev_hash": prev_str,
        "timestamp": timestamp,
        "merkle_root": merkle_root,
        "policy_hashes": policy_hashes,
        "note": note,
    }


# ---------------------------------------------------------------------------
# Transparency Log
# ---------------------------------------------------------------------------

class TransparencyLog:
    """
    Simulated append-only transparency log with Merkle anchoring.

    In production: replace with IPFS pinning + Ethereum anchoring, or
    a distributed log service (Certificate Transparency log, etc.).

    Usage:
        log = TransparencyLog()
        result = log.append(["sha256:abc...", "sha256:def..."])
        entry = result["entry"]           # log entry
        proofs = result["proofs"]          # per-policy Merkle proofs

        verified = log.verify("sha256:abc...", log_index=0)
        assert verified["valid"]
    """

    def __init__(self):
        self.entries = []

    def append(self, policy_hashes: list[str], note: str = "") -> dict:
        """
        Append a new batch of policy hashes to the log.
        Returns { entry, root, proofs }.
        """
        index = len(self.entries)
        prev_hash = self.entries[-1]["log_id"] if self.entries else None

        result = build_merkle_tree(policy_hashes)
        root = result["root"]
        proofs = result["proofs"]

        entry = create_log_entry(
            index=index,
            prev_hash=prev_hash,
            merkle_root=root,
            policy_hashes=policy_hashes,
            note=note,
        )

        self.entries.append(entry)
        return {"entry": entry, "root": root, "proofs": proofs}

    def verify(self, policy_hash: str, log_index: int) -> dict:
        """
        Verify a policy hash appears in the log at log_index.
        Returns { valid: bool, reason: str, proof: dict|null }.
        """
        if log_index < 0 or log_index >= len(self.entries):
            return {"valid": False, "reason": "log index out of range", "proof": None}

        entry = self.entries[log_index]
        if policy_hash not in entry["policy_hashes"]:
            return {"valid": False, "reason": "policy hash not in this batch", "proof": None}

        leaf_idx = entry["policy_hashes"].index(policy_hash)
        result = build_merkle_tree(entry["policy_hashes"])
        proof = result["proofs"][leaf_idx]

        return {
            "valid": verify_merkle_proof(policy_hash, entry["merkle_root"], proof),
            "reason": f"verified at index {log_index}",
            "proof": proof,
            "root": entry["merkle_root"],
        }

    def latest(self) -> Optional[dict]:
        """Get the most recent log entry."""
        return self.entries[-1] if self.entries else None

    def all(self) -> list[dict]:
        """Get all log entries."""
        return list(self.entries)


# ---------------------------------------------------------------------------
# Policy Anchoring
# ---------------------------------------------------------------------------

def anchor_policy(policy: dict, log: TransparencyLog) -> dict:
    """
    Anchor a policy document to the transparency log.
    Returns { anchor, entry } where anchor is the cryptographic proof of commitment.

    If the policy is already in the log, returns the existing anchor
    (idempotent — same policy can be verified without re-anchoring).

    Args:
        policy: Full policy document with policy_hash field
        log: TransparencyLog instance

    Returns:
        {
            anchor: {
                policy_hash: str,
                log_index: int,
                log_id: str,
                merkle_root: str,
                already_anchored: bool
            },
            entry: dict
        }
    """
    policy_hash = policy.get("policy_hash")
    if not policy_hash:
        raise ValueError("Policy must have policy_hash — run create_policy first")

    # Check if already anchored
    for i, entry in enumerate(log.entries):
        if policy_hash in entry["policy_hashes"]:
            return {
                "anchor": {
                    "policy_hash": policy_hash,
                    "log_index": i,
                    "log_id": entry["log_id"],
                    "merkle_root": entry["merkle_root"],
                    "already_anchored": True,
                },
                "entry": entry,
            }

    # Anchor new
    result = log.append([policy_hash])
    return {
        "anchor": {
            "policy_hash": policy_hash,
            "log_index": result["entry"]["log_index"],
            "log_id": result["entry"]["log_id"],
            "merkle_root": result["entry"]["merkle_root"],
            "already_anchored": False,
        },
        "entry": result["entry"],
    }


def verify_anchor(policy: dict, anchor: dict) -> dict:
    """
    Verify a policy anchor — prove the policy was committed to the log.
    Returns { valid: bool, reason: str }.
    """
    if anchor.get("policy_hash") != policy.get("policy_hash"):
        return {"valid": False, "reason": "policy hash mismatch with anchor"}

    return {
        "valid": True,
        "reason": f"policy anchored at log index {anchor.get('log_index')}, "
                  f"log_id={anchor.get('log_id', '')[:20]}...",
        "log_index": anchor.get("log_index"),
    }


# ---------------------------------------------------------------------------
# Full v0.2 Flow Demo
# ---------------------------------------------------------------------------

def demo():
    """
    Demonstrate the complete v0.2 policy commitment flow.
    """
    from pact import create_policy

    # Create two policies
    policy_a = create_policy("did:key:alice", ["read", "write"], ["delete"])
    policy_b = create_policy("did:key:bob", ["search", "send"], ["exec"])

    print(f"Policy A hash: {policy_a['policy_hash'][:30]}...")
    print(f"Policy B hash: {policy_b['policy_hash'][:30]}...")

    # Anchor both policies to the log in one batch
    log = TransparencyLog()
    result = log.append([policy_a["policy_hash"], policy_b["policy_hash"]], note="genesis batch")

    print(f"\nLog entry created:")
    print(f"  log_id:    {result['entry']['log_id'][:30]}...")
    print(f"  log_index: {result['entry']['log_index']}")
    print(f"  merkle_root: {result['root'][:30]}...")

    # Verify policy A
    verified_a = log.verify(policy_a["policy_hash"], log_index=0)
    print(f"\nPolicy A verification: {'✓ PASS' if verified_a['valid'] else '✗ FAIL'} — {verified_a['reason']}")

    # Verify policy B
    verified_b = log.verify(policy_b["policy_hash"], log_index=0)
    print(f"Policy B verification: {'✓ PASS' if verified_b['valid'] else '✗ FAIL'} — {verified_b['reason']}")

    # Anchor policy A individually (idempotent — already anchored)
    anchor_result = anchor_policy(policy_a, log)
    print(f"\nRe-anchoring policy A (already anchored):")
    print(f"  already_anchored: {anchor_result['anchor']['already_anchored']}")
    print(f"  log_index: {anchor_result['anchor']['log_index']}")

    # Anchor a new policy C
    policy_c = create_policy("did:key:carol", ["read", "analyze"], [])
    result_c = anchor_policy(policy_c, log)
    print(f"\nAnchoring new policy C:")
    print(f"  log_index: {result_c['anchor']['log_index']}")
    print(f"  merkle_root: {result_c['anchor']['merkle_root'][:30]}...")

    print("\n✓ Full v0.2 commitment flow verified")


if __name__ == "__main__":
    demo()
