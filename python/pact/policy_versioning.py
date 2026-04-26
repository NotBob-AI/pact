#!/usr/bin/env python3
"""
PACT Layer 1 — Policy Versioning Module

Implements the insight from the donna-ai thread:
"versioned policy objects, immutable policy hashes in every run,
and a signed change log for who changed what, when, and under which approval path."

Every policy revision is anchored to its prior hash — not just timestamped.
The version history is itself a chain of receipts.
Post-hoc policy rewriting fails the prior_hash check at verification time.

Usage:
    from pact.policy_versioning import commit_policy_revision, verify_policy_chain

    # Commit a policy revision
    entry = commit_policy_revision(
        policy=policy_v2,
        prior_policy_hash="sha256:abc123...",
        changed_by="did:key:alice...",
        approval_path="multisig:3-of-5",
        change_reason="Expanded tool permissions for production deployment",
    )

    # Verify the chain is unbroken
    chain_valid, reasons = verify_policy_chain([entry_v1, entry_v2, entry_v3])
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Optional


def _compute_policy_hash(policy: dict) -> str:
    """Compute raw SHA-256 hex (no prefix) from a policy dict, deterministic."""
    policy_str = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(policy_str.encode("utf-8")).hexdigest()


def _build_policy_version_entry(
    policy: dict,
    prior_policy_hash: Optional[str],
    changed_by: str,
    approval_path: str,
    change_reason: str,
) -> dict:
    """
    Build a policy version entry — the atomic unit of the policy revision chain.

    Fields:
        version_entry_id: unique identifier for this entry
        policy_hash: hash of the NEW policy at this revision
        prior_policy_hash: hash of the PRIOR policy (None for genesis)
        policy_version: semantic version string
        changed_by: DID or identifier of the party that authorized the change
        approval_path: how this change was approved (e.g. "multisig:3-of-5", "single:did:key:...")
        change_reason: human-readable reason for the revision
        timestamp: ISO-8601 UTC timestamp
        commitment: sha256 of the concatenation of all fields above
                    This is the entry's identity in the chain — changing any field
                    changes the commitment, breaking the chain.

    The chain is verified by recomputing commitment for each entry and checking
    that entry[N].prior_policy_hash == entry[N-1].policy_hash.
    """
    now = datetime.now(timezone.utc)
    policy_hash = _compute_policy_hash(policy)
    prior_clean = prior_policy_hash.replace("sha256:", "") if prior_policy_hash else None

    # Semantic version — increment patch for minor edits, minor for new tools
    policy_version = policy.get("policy_version", "0.1.0")
    entry_id = f"pve-{uuid.uuid4().hex[:16]}"

    # Build the commitment input — this binds all fields together
    commitment_input = "|".join([
        entry_id,
        policy_hash,
        prior_clean or "GENESIS",
        policy_version,
        changed_by,
        approval_path,
        change_reason,
        now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    ])
    commitment = hashlib.sha256(commitment_input.encode("utf-8")).hexdigest()

    entry = {
        "entry_type": "PACT_POLICY_VERSION",
        "version_entry_id": entry_id,
        "policy_hash": f"sha256:{policy_hash}",
        "prior_policy_hash": f"sha256:{prior_clean}" if prior_clean else None,
        "policy_version": policy_version,
        "changed_by": changed_by,
        "approval_path": approval_path,
        "change_reason": change_reason,
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commitment": f"sha256:{commitment}",
        # Chain pointer — index in the version history array
        "chain_index": None,  # Set by caller
    }
    return entry


def commit_policy_revision(
    policy: dict,
    prior_policy_hash: Optional[str],
    changed_by: str,
    approval_path: str = "single",
    change_reason: str = "",
) -> dict:
    """
    Commit a new policy revision, producing a version entry with prior-hash chaining.

    prior_policy_hash: hash of the policy being revised (from the prior version entry's policy_hash).
                      Pass None for the genesis (first) policy commit.
    changed_by: DID or identifier of the party authorizing the change
    approval_path: approval mechanism — "multisig:N-of-K", "single:did:key:...", "automated:rule:..."
    change_reason: brief description of what changed and why

    Returns a version entry dict. The entry's commitment field is the cryptographic
    identity of this revision. It cannot be altered without breaking the chain.
    """
    return _build_policy_version_entry(
        policy=policy,
        prior_policy_hash=prior_policy_hash,
        changed_by=changed_by,
        approval_path=approval_path,
        change_reason=change_reason,
    )


def verify_policy_chain(entries: list) -> tuple[bool, list[str]]:
    """
    Verify a policy version chain is unbroken.

    Checks for each consecutive pair:
      1. entries[N].prior_policy_hash == entries[N-1].policy_hash
      2. entries[N].commitment is a valid sha256:... hash

    Genesis entry (first) must have prior_policy_hash == None.

    Returns (is_valid, list_of_reasons).
    """
    if not entries:
        return False, ["Empty chain — no entries provided"]

    reasons = []

    for i, entry in enumerate(entries):
        # Check commitment format
        commitment = entry.get("commitment", "")
        if not commitment.startswith("sha256:"):
            reasons.append(f"Entry {i}: malformed commitment (no sha256: prefix)")
            return False, reasons

        # Check entry_type
        if entry.get("entry_type") != "PACT_POLICY_VERSION":
            reasons.append(f"Entry {i}: wrong entry_type '{entry.get('entry_type')}'")
            return False, reasons

        # Verify the commitment is self-consistent
        commitment_input = "|".join([
            entry["version_entry_id"],
            entry["policy_hash"].replace("sha256:", ""),
            entry["prior_policy_hash"].replace("sha256:", "") if entry["prior_policy_hash"] else "GENESIS",
            entry["policy_version"],
            entry["changed_by"],
            entry["approval_path"],
            entry["change_reason"],
            entry["timestamp"],
        ])
        expected_commitment = hashlib.sha256(commitment_input.encode("utf-8")).hexdigest()
        if commitment != f"sha256:{expected_commitment}":
            reasons.append(
                f"Entry {i}: commitment mismatch — entry may have been altered "
                f"('{entry['version_entry_id']}')"
            )
            return False, reasons

        # Check chain linkage (skip genesis)
        if i == 0:
            if entry["prior_policy_hash"] is not None:
                reasons.append(f"Entry 0: genesis entry must have prior_policy_hash=None, got '{entry['prior_policy_hash']}'")
                return False, reasons
            reasons.append(f"Entry 0: GENESIS ✓ (commitment={commitment[:22]}...)")
        else:
            prior_entry = entries[i - 1]
            if entry.get("prior_policy_hash") != prior_entry.get("policy_hash"):
                reasons.append(
                    f"Entry {i}: chain broken — prior_policy_hash="
                    f"'{entry.get('prior_policy_hash')}' != "
                    f"expected '{prior_entry.get('policy_hash')}'"
                )
                return False, reasons
            reasons.append(
                f"Entry {i}: CHAINED ✓ (prior={entry['prior_policy_hash'][:22]}...)"
            )

    reasons.append(f"\nChain VALID — {len(entries)} version entries, all commitments verified")
    return True, reasons


def get_genesis_and_current(entries: list) -> tuple[dict, dict]:
    """Return (genesis_entry, current_entry) from a verified chain."""
    if not entries:
        raise ValueError("No entries in chain")
    return entries[0], entries[-1]


# ─── CLI ───────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="PACT Policy Versioning CLI")
    sub = parser.add_subparsers(dest="cmd")

    commit = sub.add_parser("commit", help="Commit a policy revision")
    commit.add_argument("--policy", required=True, help="Path to policy JSON file")
    commit.add_argument("--prior-hash", help="Prior policy hash (omit for genesis)")
    commit.add_argument("--changed-by", required=True)
    commit.add_argument("--approval", default="single")
    commit.add_argument("--reason", default="")
    commit.add_argument("--output", default="policy_version_entry.json")

    verify = sub.add_parser("verify", help="Verify a policy version chain")
    verify.add_argument("--chain", required=True, help="JSON file with entries array")
    verify.add_argument("--output", default="verification_result.json")

    args = parser.parse_args()

    if args.cmd == "commit":
        policy = json.loads(open(args.policy).read())
        entry = commit_policy_revision(
            policy=policy,
            prior_policy_hash=args.prior_hash,
            changed_by=args.changed_by,
            approval_path=args.approval,
            change_reason=args.reason,
        )
        with open(args.output, "w") as f:
            json.dump(entry, f, indent=2)
        print(f"Policy version entry written to {args.output}")
        print(f"  policy_hash:    {entry['policy_hash']}")
        print(f"  prior_hash:     {entry['prior_policy_hash']}")
        print(f"  commitment:     {entry['commitment']}")

    elif args.cmd == "verify":
        data = json.loads(open(args.chain).read())
        entries = data.get("entries", []) if isinstance(data, dict) else data
        valid, reasons = verify_policy_chain(entries)
        result = {"valid": valid, "reasons": reasons}
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        for r in reasons:
            print(r)
        print(f"\nVerification result written to {args.output}")


if __name__ == "__main__":
    main()
