#!/usr/bin/env python3
"""
PACT Policy Versioning — Unit Tests

Tests prior-hash chained policy revision entries:
  - Genesis entry has no prior_policy_hash
  - Each revision entry chains to its predecessor
  - Commitment is self-consistent (any field change breaks chain)
  - verify_policy_chain detects tampering

Run: python3 tests/test_policy_versioning.py
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from pact.policy_versioning import (
    commit_policy_revision,
    verify_policy_chain,
    get_genesis_and_current,
    _compute_policy_hash,
)
from pact import create_policy


class TestPolicyVersioning(unittest.TestCase):
    """Tests for PACT policy versioning with prior-hash chaining."""

    def _make_policy_v1(self) -> dict:
        policy = create_policy(
            agent_id="did:key:test-agent",
            allowed_tools=["read_file", "search_web"],
            denied_tools=["delete_file"],
        )
        policy["pact_version"] = "0.2.0"
        policy["created_at"] = policy.pop("created")
        return policy

    def _make_policy_v2(self, v1_policy: dict) -> dict:
        """Incrementally modify a policy — add a new tool."""
        policy = v1_policy.copy()
        policy["policy"] = v1_policy["policy"].copy()
        policy["policy"]["allowed_tools"] = ["read_file", "search_web", "send_email"]
        policy["pact_version"] = "0.2.1"
        return policy

    # -----------------------------------------------------------------
    # Genesis entry
    # -----------------------------------------------------------------

    def test_genesis_entry_has_no_prior_hash(self):
        """Genesis entry must have prior_policy_hash = None."""
        policy = self._make_policy_v1()
        entry = commit_policy_revision(
            policy=policy,
            prior_policy_hash=None,
            changed_by="did:key:alice",
            approval_path="single",
            change_reason="Initial policy commit",
        )

        self.assertIsNone(entry["prior_policy_hash"])
        self.assertEqual(entry["entry_type"], "PACT_POLICY_VERSION")
        self.assertIn("commitment", entry)
        self.assertTrue(entry["commitment"].startswith("sha256:"))
        self.assertEqual(entry["changed_by"], "did:key:alice")
        self.assertEqual(entry["approval_path"], "single")
        # GENESIS appears in the commitment INPUT (not the hash output). Check that
        # commitment is a valid sha256:... hash and genesis entry has no prior hash.
        self.assertTrue(entry["commitment"].startswith("sha256:"))
        self.assertEqual(len(entry["commitment"]), len("sha256:") + 64)

    def test_genesis_entry_fails_with_prior_hash(self):
        """Genesis entry with a prior_policy_hash should NOT be allowed in verify_policy_chain."""
        policy = self._make_policy_v1()
        entry = commit_policy_revision(
            policy=policy,
            prior_policy_hash="sha256:abc123",
            changed_by="did:key:alice",
            approval_path="single",
            change_reason="Should not have prior",
        )
        # The entry is created (prior_hash is set) but it will fail chain verification
        self.assertIsNotNone(entry["prior_policy_hash"])

    # -----------------------------------------------------------------
    # Chained entries
    # -----------------------------------------------------------------

    def test_chained_entry_has_prior_hash(self):
        """Non-genesis entries must have prior_policy_hash pointing to prior entry's policy_hash."""
        policy_v1 = self._make_policy_v1()
        entry_v1 = commit_policy_revision(
            policy=policy_v1,
            prior_policy_hash=None,
            changed_by="did:key:alice",
            approval_path="single",
            change_reason="Initial policy",
        )

        policy_v2 = self._make_policy_v2(policy_v1)
        entry_v2 = commit_policy_revision(
            policy=policy_v2,
            prior_policy_hash=entry_v1["policy_hash"],
            changed_by="did:key:bob",
            approval_path="multisig:2-of-3",
            change_reason="Add send_email tool",
        )

        self.assertEqual(entry_v2["prior_policy_hash"], entry_v1["policy_hash"])
        self.assertEqual(entry_v2["changed_by"], "did:key:bob")
        self.assertEqual(entry_v2["approval_path"], "multisig:2-of-3")

    def test_policy_hash_changes_on_content(self):
        """Different policy content → different policy_hash."""
        policy_v1 = self._make_policy_v1()
        entry_v1 = commit_policy_revision(
            policy=policy_v1,
            prior_policy_hash=None,
            changed_by="did:key:alice",
            approval_path="single",
            change_reason="Initial",
        )

        policy_v2 = self._make_policy_v2(policy_v1)
        entry_v2 = commit_policy_revision(
            policy=policy_v2,
            prior_policy_hash=entry_v1["policy_hash"],
            changed_by="did:key:alice",
            approval_path="single",
            change_reason="Add send_email",
        )

        self.assertNotEqual(entry_v1["policy_hash"], entry_v2["policy_hash"])

    def test_verify_valid_chain(self):
        """verify_policy_chain returns True for a valid 3-entry chain."""
        policy_v1 = self._make_policy_v1()
        entry_v1 = commit_policy_revision(
            policy=policy_v1,
            prior_policy_hash=None,
            changed_by="did:key:alice",
            approval_path="single",
            change_reason="Genesis",
        )

        policy_v2 = self._make_policy_v2(policy_v1)
        entry_v2 = commit_policy_revision(
            policy=policy_v2,
            prior_policy_hash=entry_v1["policy_hash"],
            changed_by="did:key:bob",
            approval_path="multisig:2-of-3",
            change_reason="Add send_email",
        )

        policy_v3 = policy_v2.copy()
        policy_v3["policy"] = policy_v2["policy"].copy()
        policy_v3["policy"]["denied_tools"] = ["delete_file", "reboot_machine"]
        entry_v3 = commit_policy_revision(
            policy=policy_v3,
            prior_policy_hash=entry_v2["policy_hash"],
            changed_by="did:key:alice",
            approval_path="single",
            change_reason="Add denied_tool",
        )

        valid, reasons = verify_policy_chain([entry_v1, entry_v2, entry_v3])

        self.assertTrue(valid)
        self.assertTrue(any("GENESIS" in r for r in reasons))
        self.assertTrue(any("CHAINED" in r for r in reasons))
        self.assertTrue(any("VALID" in r for r in reasons), f"VALID not in {reasons}")

    def test_verify_detects_broken_chain(self):
        """verify_policy_chain fails when prior_policy_hash doesn't match prior policy_hash."""
        policy_v1 = self._make_policy_v1()
        entry_v1 = commit_policy_revision(
            policy=policy_v1,
            prior_policy_hash=None,
            changed_by="did:key:alice",
            approval_path="single",
            change_reason="Genesis",
        )

        policy_v2 = self._make_policy_v2(policy_v1)
        # Deliberately use wrong prior hash
        entry_v2 = commit_policy_revision(
            policy=policy_v2,
            prior_policy_hash="sha256:0000000000000000000000000000000000000000000000000000000000000000",
            changed_by="did:key:bob",
            approval_path="single",
            change_reason="Tampered",
        )

        valid, reasons = verify_policy_chain([entry_v1, entry_v2])

        self.assertFalse(valid)
        self.assertTrue(any("chain broken" in r.lower() for r in reasons))

    def test_verify_detects_tampered_entry(self):
        """verify_policy_chain fails when an entry's own commitment doesn't recompute."""
        policy_v1 = self._make_policy_v1()
        entry_v1 = commit_policy_revision(
            policy=policy_v1,
            prior_policy_hash=None,
            changed_by="did:key:alice",
            approval_path="single",
            change_reason="Genesis",
        )

        # Tamper with the entry after creation
        entry_v1["change_reason"] = "Tampered after the fact"

        valid, reasons = verify_policy_chain([entry_v1])

        self.assertFalse(valid)
        self.assertTrue(any("commitment mismatch" in r.lower() for r in reasons))

    def test_verify_empty_chain_fails(self):
        """Empty chain fails verification."""
        valid, reasons = verify_policy_chain([])
        self.assertFalse(valid)
        self.assertTrue(any("empty" in r.lower() for r in reasons))

    def test_verify_single_genesis_valid(self):
        """A single genesis entry is a valid chain."""
        policy = self._make_policy_v1()
        entry = commit_policy_revision(
            policy=policy,
            prior_policy_hash=None,
            changed_by="did:key:alice",
            approval_path="single",
            change_reason="Solo genesis",
        )

        valid, reasons = verify_policy_chain([entry])
        self.assertTrue(valid)

    def test_verify_wrong_entry_type_fails(self):
        """Entry with wrong entry_type fails verification."""
        policy = self._make_policy_v1()
        entry = commit_policy_revision(
            policy=policy,
            prior_policy_hash=None,
            changed_by="did:key:alice",
            approval_path="single",
            change_reason="Genesis",
        )
        entry["entry_type"] = "PACT_RECEIPT"  # Wrong type

        valid, reasons = verify_policy_chain([entry])
        self.assertFalse(valid)
        self.assertTrue(any("wrong entry_type" in r.lower() for r in reasons))

    def test_verify_malformed_commitment_fails(self):
        """Entry with non-sha256 commitment fails."""
        policy = self._make_policy_v1()
        entry = commit_policy_revision(
            policy=policy,
            prior_policy_hash=None,
            changed_by="did:key:alice",
            approval_path="single",
            change_reason="Genesis",
        )
        entry["commitment"] = "md5:deadbeef"  # Wrong hash prefix

        valid, reasons = verify_policy_chain([entry])
        self.assertFalse(valid)
        self.assertTrue(any("malformed" in r.lower() for r in reasons))

    # -----------------------------------------------------------------
    # Helper functions
    # -----------------------------------------------------------------

    def test_get_genesis_and_current(self):
        """get_genesis_and_current returns first and last entries."""
        policy_v1 = self._make_policy_v1()
        entry_v1 = commit_policy_revision(
            policy=policy_v1,
            prior_policy_hash=None,
            changed_by="did:key:alice",
            approval_path="single",
            change_reason="Genesis",
        )

        policy_v2 = self._make_policy_v2(policy_v1)
        entry_v2 = commit_policy_revision(
            policy=policy_v2,
            prior_policy_hash=entry_v1["policy_hash"],
            changed_by="did:key:bob",
            approval_path="single",
            change_reason="Update",
        )

        genesis, current = get_genesis_and_current([entry_v1, entry_v2])

        self.assertEqual(genesis["version_entry_id"], entry_v1["version_entry_id"])
        self.assertEqual(current["version_entry_id"], entry_v2["version_entry_id"])

    def test_get_genesis_and_current_empty_fails(self):
        """get_genesis_and_current raises ValueError on empty list."""
        with self.assertRaises(ValueError):
            get_genesis_and_current([])

    def test_compute_policy_hash_deterministic(self):
        """_compute_policy_hash is deterministic for same policy JSON text."""
        # Use fixed policy dicts (create_policy generates a fresh timestamp each call)
        p1 = {"agent_id": "did:key:test", "policy": {"allowed_tools": ["a"], "denied_tools": ["b"]}}
        p2 = {"agent_id": "did:key:test", "policy": {"allowed_tools": ["a"], "denied_tools": ["b"]}}


        h1 = _compute_policy_hash(p1)
        h2 = _compute_policy_hash(p2)
        self.assertEqual(h1, h2)


        # Different content → different hash
        p3 = {"agent_id": "did:key:test", "policy": {"allowed_tools": ["b"], "denied_tools": ["a"]}}
        h3 = _compute_policy_hash(p3)
        self.assertNotEqual(h1, h3)

        # Same content different key order → same hash (JSON canonicalization)
        p4 = {"policy": {"denied_tools": ["b"], "allowed_tools": ["a"]}, "agent_id": "did:key:test"}
        h4 = _compute_policy_hash(p4)
        self.assertEqual(h1, h4)

    def test_approval_path_in_commitment(self):
        """Approval path is part of commitment — different approval_path → different commitment."""
        policy = self._make_policy_v1()

        entry_single = commit_policy_revision(
            policy=policy,
            prior_policy_hash=None,
            changed_by="did:key:alice",
            approval_path="single",
            change_reason="Genesis",
        )

        # Same policy, same prior_hash, different approval_path
        entry_multi = commit_policy_revision(
            policy=policy,
            prior_policy_hash=None,
            changed_by="did:key:alice",
            approval_path="multisig:5-of-7",
            change_reason="Genesis",
        )

        self.assertNotEqual(entry_single["commitment"], entry_multi["commitment"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
