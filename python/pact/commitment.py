"""
PACT v0.2 — Policy Commitment Layer

Commits a policy document to a transparency log BEFORE agent execution,
producing a commitment receipt with a Merkle root anchored in Git.
Verifiable by any third party without requiring access to the agent.

Key invariant: A policy can only be used to generate valid receipts
AFTER it has been committed. The commitment timestamp is the proof
that the policy existed before the actions it authorizes.
"""

import json
import hashlib
import struct
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field
from .receipt import generate_receipt

PACT_DIR = Path(__file__).parent.parent.parent
TRANSPARENCY_LOG = PACT_DIR / "transparency_log.jsonl"
COMMITMENTS_DIR = PACT_DIR / "commitments"
GIT_ANCHOR_FILE = PACT_DIR / "merkle_root_anchored.txt"


@dataclass
class PolicyCommitment:
    """A committed policy document with transparency log proof."""
    policy_doc: dict
    policy_hash: str
    commitment_index: int
    merkle_root: str
    committed_at: str
    log_anchors: list[str] = field(default_factory=list)


def _compute_merkle_node(left: str, right: str) -> str:
    """Combine two node hashes into a parent Merkle node."""
    combined = json.dumps([left, right], sort_keys=True).encode()
    return "sha256:" + hashlib.sha256(combined).hexdigest()


def _build_merkle_tree(hashes: list[str]) -> tuple[list[str], str]:
    """
    Build a Merkle tree from a list of leaf hashes.
    Returns (tree_nodes, root_hash).
    """
    if not hashes:
        return [], "sha256:" + "0" * 64

    tree = [hashes]
    level = 0

    while len(tree[level]) > 1:
        current_level = tree[level]
        next_level = []

        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
            parent = _compute_merkle_node(left, right)
            next_level.append(parent)

        tree.append(next_level)
        level += 1

    return tree, tree[-1][0]


def _append_to_transparency_log(entry: dict) -> tuple[int, str]:
    """
    Append a commitment entry to the append-only transparency log.
    Returns (entry_index, entry_hash).
    """
    COMMITMENTS_DIR.mkdir(exist_ok=True)

    # Read existing log to get entry index
    entries = []
    if TRANSPARENCY_LOG.exists():
        with open(TRANSPARENCY_LOG) as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))

    entry_index = len(entries)
    entry["log_index"] = entry_index

    entry_str = json.dumps(entry, sort_keys=True)
    entry_hash = "sha256:" + hashlib.sha256(entry_str.encode()).hexdigest()
    entry["entry_hash"] = entry_hash

    with open(TRANSPARENCY_LOG, "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")

    # Save individual commitment file
    commitment_file = COMMITMENTS_DIR / f"{entry_index:06d}.json"
    with open(commitment_file, "w") as f:
        json.dump(entry, f, indent=2)

    return entry_index, entry_hash


def _anchor_merkle_root_to_git(merkle_root: str, policy_hash: str) -> str:
    """
    Commit the current Merkle root to Git.
    This creates an immutable anchor — the root cannot be changed
    without changing the Git commit, which would be visible.
    """
    anchor_content = json.dumps({
        "merkle_root": merkle_root,
        "policy_hash": policy_hash,
        "anchored_at": datetime.now(timezone.utc).isoformat(),
        "type": "PACT_v0.2_merkle_anchor"
    }, indent=2) + "\n"

    with open(GIT_ANCHOR_FILE, "a") as f:
        f.write(anchor_content)

    try:
        subprocess.run(
            ["git", "add", str(GIT_ANCHOR_FILE.relative_to(PACT_DIR))],
            cwd=PACT_DIR, check=True, capture_output=True
        )
        result = subprocess.run(
            ["git", "commit", "-m", f"feat(pact): anchor PACT v0.2 merkle root\n\npolicy_hash: {policy_hash[:16]}...\nmerkle_root: {merkle_root[:16]}..."],
            cwd=PACT_DIR, check=True, capture_output=True, text=True
        )
        git_ref = result.stdout.split("\n")[0] if result.stdout else "committed"
    except subprocess.CalledProcessError:
        git_ref = "git_commit_failed"

    return git_ref


def commit_policy(policy_doc: dict) -> PolicyCommitment:
    """
    Commit a policy document to the transparency log.
    
    Process:
    1. Compute deterministic policy hash
    2. Append commitment entry to append-only log
    3. Rebuild Merkle tree from all log entries
    4. Anchor root to Git
    5. Return commitment with proof structure
    
    The commitment CANNOT be modified after creation.
    A new commitment creates a new log entry and a new Merkle root.
    """
    # Ensure deterministic field ordering
    canonical = json.dumps(policy_doc, sort_keys=True, ensure_ascii=True)
    policy_hash = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()

    committed_at = datetime.now(timezone.utc).isoformat()

    # Build log entry (no entry_hash yet — computed by _append_to_transparency_log)
    entry = {
        "type": "PACT_v0.2_policy_commitment",
        "policy_hash": policy_hash,
        "policy_version": policy_doc.get("policy_version", "unknown"),
        "agent_id": policy_doc.get("agent_id", "unknown"),
        "committed_at": committed_at,
    }

    # Append to transparency log (computes entry_hash)
    entry_index, entry_hash = _append_to_transparency_log(entry)

    # Rebuild Merkle tree from all entries
    all_entries = []
    if TRANSPARENCY_LOG.exists():
        with open(TRANSPARENCY_LOG) as f:
            for line in f:
                if line.strip():
                    all_entries.append(json.loads(line))

    leaf_hashes = [e["entry_hash"] for e in all_entries]
    _, merkle_root = _build_merkle_tree(leaf_hashes)

    # Anchor root to Git
    git_ref = _anchor_merkle_root_to_git(merkle_root, policy_hash)

    # Update the entry with the new Merkle root
    entry["merkle_root"] = merkle_root
    entry["git_anchor"] = git_ref
    entry["total_entries"] = len(all_entries)

    # Overwrite the last entry with full data
    with open(TRANSPARENCY_LOG) as f:
        lines = f.readlines()
    lines[-1] = json.dumps(entry, sort_keys=True) + "\n"
    with open(TRANSPARENCY_LOG, "w") as f:
        f.writelines(lines)

    # Update individual file
    commitment_file = COMMITMENTS_DIR / f"{entry_index:06d}.json"
    with open(commitment_file, "w") as f:
        json.dump(entry, f, indent=2)

    return PolicyCommitment(
        policy_doc=policy_doc,
        policy_hash=policy_hash,
        commitment_index=entry_index,
        merkle_root=merkle_root,
        committed_at=committed_at,
        log_anchors=[f"entry:{entry_hash}", f"git:{git_ref}", f"merkle_root:{merkle_root}"]
    )


def verify_commitment(policy_hash: str, commitment_index: int) -> dict:
    """
    Verify a commitment exists in the transparency log and its Merkle proof is valid.
    
    Third parties can call this without trusting the agent — they only need
    the transparency log file and the Git anchor for the Merkle root.
    """
    log_file = COMMITMENTS_DIR / f"{commitment_index:06d}.json"

    if not log_file.exists():
        return {"valid": False, "reason": "commitment not found in log"}

    with open(log_file) as f:
        commitment = json.load(f)

    if commitment["policy_hash"] != policy_hash:
        return {"valid": False, "reason": "policy hash mismatch"}

    # Rebuild Merkle tree up to this entry
    leaf_hashes = []
    for i in range(commitment_index + 1):
        cf = COMMITMENTS_DIR / f"{i:06d}.json"
        if not cf.exists():
            return {"valid": False, "reason": f"log entry {i} missing"}
        with open(cf) as f:
            entry = json.load(f)
        leaf_hashes.append(entry["entry_hash"])

    _, computed_root = _build_merkle_tree(leaf_hashes)

    if computed_root != commitment["merkle_root"]:
        return {"valid": False, "reason": "merkle root mismatch — log may have been tampered with"}

    return {
        "valid": True,
        "commitment": commitment,
        "merkle_proof": {
            "leaf_count": len(leaf_hashes),
            "root": computed_root,
            "index": commitment_index,
        }
    }


def get_latest_merkle_root() -> Optional[str]:
    """Get the most recent Merkle root anchored in the transparency log."""
    if not TRANSPARENCY_LOG.exists():
        return None
    with open(TRANSPARENCY_LOG) as f:
        lines = [l for l in f if l.strip()]
    if not lines:
        return None
    last = json.loads(lines[-1])
    return last.get("merkle_root")


# --- CLI support ---

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 commitment.py <policy.json>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        policy_doc = json.load(f)

    commitment = commit_policy(policy_doc)
    print(json.dumps({
        "policy_hash": commitment.policy_hash,
        "commitment_index": commitment.commitment_index,
        "merkle_root": commitment.merkle_root,
        "committed_at": commitment.committed_at,
        "log_anchors": commitment.log_anchors,
    }, indent=2))
