#!/usr/bin/env python3
"""
PACT v0.3 — End-to-End Integration Test

Tests the full ZK receipt pipeline:
  1. Create a policy document
  2. Commit it (compute policy_hash)
  3. Build a mock Merkle anchor (DUMMY_PROOF mode)
  4. Generate a ZK receipt for a permitted tool call
  5. Verify the receipt structure

Uses DUMMY_PROOF mode — RISC Zero prover not required.
Real proofs require RISC Zero toolchain installed.

Run: python3 -m pytest tests/test_zk_receipt_generator.py -v
Or:  python3 tests/test_zk_receipt_generator.py
"""

import json
import os
import sys
import unittest
from pathlib import Path

# Ensure pact package is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

# Force DUMMY_PROOF mode for testing
os.environ["DUMMY_PROOF"] = "1"

from pact.zk_receipt_generator import (
    build_zk_receipt,
    verify_zk_receipt,
    compute_params_hash,
)
from pact import create_policy


class TestZKReceiptGenerator(unittest.TestCase):
    """Integration tests for PACT v0.3 ZK receipt pipeline."""

    def _make_mock_anchor(self, log_index: int = 0, policy_hash: str = None) -> dict:
        """Build a mock transparency log anchor for DUMMY_PROOF testing."""
        return {
            "log_index": log_index,
            "log_id": f"test-log-entry-{log_index}",
            "merkle_root": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "timestamp": "2026-04-23T12:00:00Z",
        }

    def _make_policy(self, allowed_tools: list = None) -> dict:
        """Create a test policy document."""
        policy = create_policy(
            agent_id="did:key:z6Mktest123",
            allowed_tools=allowed_tools or ["read_file", "search_web", "send_email"],
            denied_tools=["delete_file", "execute_code", "access_credentials"],
        )
        policy["pact_version"] = "0.3.0"  # Override for v0.3 tests
        policy["created_at"] = policy.pop("created")  # Rename field to match v0.3 format
        return policy

    # -----------------------------------------------------------------
    # Core receipt generation
    # -----------------------------------------------------------------

    def test_receipt_generation_permits(self):
        """Test ZK receipt generation for a permitted tool call."""
        policy = self._make_policy(allowed_tools=["search_web", "read_file"])
        anchor = self._make_mock_anchor(log_index=1)

        receipt = build_zk_receipt(
            policy=policy,
            tool_name="search_web",
            params={"query": "zero knowledge proofs"},
            anchor=anchor,
            outcome=True,
            reason="tool_in_allowed_list",
            seq=1,
        )

        self.assertEqual(receipt["receipt_version"], "0.3.0")
        self.assertEqual(receipt["tool_called"], "search_web")
        self.assertEqual(receipt["outcome"], "permitted")
        self.assertIn("receipt_hash", receipt)
        self.assertTrue(receipt["receipt_hash"].startswith("sha256:"))
        self.assertEqual(receipt["proof"]["type"], "zk_membership_proof")
        self.assertEqual(receipt["proof"]["zk"]["proof_type"], "DUMMY_ZK_PROOF")
        self.assertIn("params_hash", receipt)
        self.assertEqual(receipt["seq"], 1)

    def test_receipt_generation_denied(self):
        """Test ZK receipt generation for a denied tool call."""
        policy = self._make_policy(allowed_tools=["read_file"])
        anchor = self._make_mock_anchor()

        receipt = build_zk_receipt(
            policy=policy,
            tool_name="delete_file",
            params={"path": "/etc/passwd"},
            anchor=anchor,
            outcome=False,
            reason="tool_not_in_allowed_list",
            seq=2,
        )

        self.assertEqual(receipt["outcome"], "denied")
        self.assertEqual(receipt["proof"]["zk"]["proof_type"], "DUMMY_ZK_PROOF")

    def test_receipt_chain_continuity(self):
        """Test that receipts chain correctly via prev_receipt_hash."""
        policy = self._make_policy()
        anchor = self._make_mock_anchor(log_index=2)

        receipt_1 = build_zk_receipt(
            policy=policy,
            tool_name="read_file",
            params={"path": "/tmp/test.txt"},
            anchor=anchor,
            outcome=True,
            reason="policy_compliant",
            seq=1,
        )

        anchor_2 = self._make_mock_anchor(log_index=3)
        receipt_2 = build_zk_receipt(
            policy=policy,
            tool_name="send_email",
            params={"to": "test@example.com", "body": "hello"},
            anchor=anchor_2,
            outcome=True,
            reason="policy_compliant",
            seq=2,
            prev_receipt_hash=receipt_1["receipt_hash"],
        )

        self.assertEqual(receipt_2["prev_receipt_hash"], receipt_1["receipt_hash"])
        self.assertEqual(receipt_2["seq"], 2)
        # Chain hash should differ when prev changes
        receipt_2_no_prev = build_zk_receipt(
            policy=policy,
            tool_name="send_email",
            params={"to": "test@example.com", "body": "hello"},
            anchor=anchor_2,
            outcome=True,
            reason="policy_compliant",
            seq=2,
            prev_receipt_hash=None,
        )
        self.assertNotEqual(receipt_2["receipt_hash"], receipt_2_no_prev["receipt_hash"])

    def test_receipt_with_no_prev_hash(self):
        """First receipt in chain has no prev_receipt_hash."""
        policy = self._make_policy()
        anchor = self._make_mock_anchor(log_index=0)

        receipt = build_zk_receipt(
            policy=policy,
            tool_name="search_web",
            params={"query": "test"},
            anchor=anchor,
            outcome=True,
            reason="policy_compliant",
            seq=0,
            prev_receipt_hash=None,
        )

        self.assertIsNone(receipt["prev_receipt_hash"])
        self.assertEqual(receipt["seq"], 0)

    # -----------------------------------------------------------------
    # Receipt verification
    # -----------------------------------------------------------------

    def test_verify_valid_receipt(self):
        """Test verification of a structurally valid DUMMY receipt."""
        policy = self._make_policy()
        anchor = self._make_mock_anchor(log_index=5)

        receipt = build_zk_receipt(
            policy=policy,
            tool_name="read_file",
            params={"path": "/tmp/data.csv"},
            anchor=anchor,
            outcome=True,
            reason="policy_compliant",
            seq=3,
        )

        result = verify_zk_receipt(receipt)
        self.assertTrue(result["valid"])
        self.assertTrue(result["is_dummy"])
        self.assertIn("proof_type", result)

    def test_verify_malformed_receipt_hash(self):
        """Test verification fails on malformed receipt_hash."""
        policy = self._make_policy()
        anchor = self._make_mock_anchor()

        receipt = build_zk_receipt(
            policy=policy,
            tool_name="read_file",
            params={},
            anchor=anchor,
            outcome=True,
            reason="policy_compliant",
            seq=1,
        )
        # Corrupt the receipt_hash
        receipt["receipt_hash"] = "md5:deadbeef"

        result = verify_zk_receipt(receipt)
        self.assertFalse(result["valid"])
        self.assertIn("malformed", result["reason"])

    def test_verify_missing_proof_type(self):
        """Test verification fails when proof.zk.proof_type is missing."""
        policy = self._make_policy()
        anchor = self._make_mock_anchor()

        receipt = build_zk_receipt(
            policy=policy,
            tool_name="read_file",
            params={},
            anchor=anchor,
            outcome=True,
            reason="policy_compliant",
            seq=1,
        )
        # Corrupt proof type
        receipt["proof"]["zk"]["proof_type"] = None

        result = verify_zk_receipt(receipt)
        self.assertFalse(result["valid"])

    # -----------------------------------------------------------------
    # Params hashing
    # -----------------------------------------------------------------

    def test_params_hash_deterministic(self):
        """Test that params_hash is deterministic regardless of key order."""
        params_a = {"query": "test", "limit": 10, "offset": 0}
        params_b = {"offset": 0, "limit": 10, "query": "test"}

        hash_a = compute_params_hash(params_a)
        hash_b = compute_params_hash(params_b)
        self.assertEqual(hash_a, hash_b)

    def test_params_hash_differs_on_content(self):
        """Test that different params produce different hashes."""
        params_a = {"query": "zero knowledge"}
        params_b = {"query": "fully homomorphic encryption"}

        hash_a = compute_params_hash(params_a)
        hash_b = compute_params_hash(params_b)
        self.assertNotEqual(hash_a, hash_b)

    def test_empty_params_hash(self):
        """Test params hash for empty params."""
        h = compute_params_hash({})
        self.assertEqual(len(h), 64)  # Raw SHA-256 hex = 64 chars

    # -----------------------------------------------------------------
    # Policy hash
    # -----------------------------------------------------------------

    def test_policy_hash_deterministic(self):
        """Test that raw policy hash is deterministic for fixed content."""
        # create_policy() includes a dynamic timestamp, so two calls differ.
        # Test the underlying hash function directly with fixed input.
        from pact.zk_host import sha256_raw_hex
        # Same policy JSON text → same raw hash
        policy_text_a = '{"agent_id": "did:key:test", "policy": {"allowed_tools": ["a"], "denied_tools": []}}'
        policy_text_b = '{"agent_id": "did:key:test", "policy": {"allowed_tools": ["a"], "denied_tools": []}}'
        self.assertEqual(sha256_raw_hex(policy_text_a), sha256_raw_hex(policy_text_b))
        # Different policy text → different hash
        policy_text_c = '{"agent_id": "did:key:test", "policy": {"allowed_tools": ["b"], "denied_tools": []}}'
        self.assertNotEqual(sha256_raw_hex(policy_text_a), sha256_raw_hex(policy_text_c))

    # -----------------------------------------------------------------
    # Error cases
    # -----------------------------------------------------------------

    def test_receipt_without_policy_hash_raises(self):
        """Test that a policy without policy_hash raises ValueError."""
        bad_policy = {
            "pact_version": "0.3.0",
            "agent_id": "did:key:test",
            "created_at": "2026-04-23T00:00:00Z",
            "policy": {
                "allowed_tools": ["read_file"],
            },
            # Intentionally missing policy_hash
        }
        anchor = self._make_mock_anchor()

        with self.assertRaises(ValueError) as ctx:
            build_zk_receipt(
                policy=bad_policy,
                tool_name="read_file",
                params={},
                anchor=anchor,
                outcome=True,
                reason="policy_compliant",
            )
        self.assertIn("policy_hash", str(ctx.exception))

    # -----------------------------------------------------------------
    # Anchor binding
    # -----------------------------------------------------------------

    def test_anchor_logged_in_receipt(self):
        """Test that the anchor is stored inside the receipt."""
        policy = self._make_policy()
        anchor = self._make_mock_anchor(log_index=99)

        receipt = build_zk_receipt(
            policy=policy,
            tool_name="search_web",
            params={"query": "test"},
            anchor=anchor,
            outcome=True,
            reason="policy_compliant",
            seq=7,
        )

        stored_anchor = receipt["anchor"]
        self.assertEqual(stored_anchor["log_index"], 99)
        self.assertEqual(stored_anchor["log_id"], "test-log-entry-99")


class TestZKReceiptGeneratorCLI(unittest.TestCase):
    """Test the CLI entry point of zk_receipt_generator.py."""

    def test_cli_roundtrip(self):
        """Test CLI: generate a receipt and write to file, then verify."""
        import tempfile
        import subprocess

        policy = {
            "pact_version": "0.3.0",
            "agent_id": "did:key:z6Mkclitest",
            "created_at": "2026-04-23T00:00:00Z",
            "policy": {
                "allowed_tools": ["search_web", "read_file"],
                "denied_tools": [],
            },
        }
        policy = create_policy(
            agent_id="did:key:z6Mkclitest",
            allowed_tools=["search_web", "read_file"],
            denied_tools=[],
        )
        policy["pact_version"] = "0.3.0"
        policy["created_at"] = policy.pop("created")

        anchor = {
            "log_index": 0,
            "log_id": "cli-test-log",
            "merkle_root": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = os.path.join(tmpdir, "policy.json")
            anchor_path = os.path.join(tmpdir, "anchor.json")
            receipt_path = os.path.join(tmpdir, "receipt.json")

            with open(policy_path, "w") as f:
                json.dump(policy, f)
            with open(anchor_path, "w") as f:
                json.dump(anchor, f)

            # Run the CLI
            result = subprocess.run(
                [
                    sys.executable, "-m", "pact.zk_receipt_generator",
                    "--policy", policy_path,
                    "--tool", "search_web",
                    "--params", '{"query": "zk proofs"}',
                    "--anchor", anchor_path,
                    "--outcome", "true",
                    "--reason", "policy_compliant",
                    "--seq", "0",
                    "--output", receipt_path,
                ],
                capture_output=True,
                text=True,
                env={**os.environ, "DUMMY_PROOF": "1"},
            )

            self.assertEqual(result.returncode, 0, f"CLI failed: {result.stderr}")
            self.assertTrue(os.path.exists(receipt_path))

            with open(receipt_path) as f:
                receipt = json.load(f)

            self.assertEqual(receipt["tool_called"], "search_web")
            self.assertEqual(receipt["outcome"], "permitted")
            self.assertEqual(receipt["proof"]["zk"]["proof_type"], "DUMMY_ZK_PROOF")


if __name__ == "__main__":
    unittest.main(verbosity=2)
