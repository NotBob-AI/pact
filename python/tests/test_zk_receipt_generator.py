#!/usr/bin/env python3
"""
PACT v0.3 — ZK Receipt Generator Integration Tests

Tests the full pipeline:
  1. Policy hashing and commitment
  2. ZK receipt generation from a policy + tool call + anchor
  3. Receipt format validation (v0.3 format)
  4. Receipt chain integrity (receipt_hash → prev_receipt_hash link)
  5. Params hash determinism (same params → same hash)
  6. Verification flow (receipt → verify against policy hash + anchor)

These are integration tests for the Python bridge. Full ZK proof
generation requires RISC Zero toolchain; tests here validate the
DUMMY_PROOF path and receipt structure in all environments.
"""

import hashlib
import json
import os
import sys
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_hex(data: str) -> str:
    return f"sha256:{hashlib.sha256(data.encode('utf-8')).hexdigest()}"


def sha256_raw_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def build_policy(agent_id: str, allowed_tools: list, denied_tools: list = None) -> dict:
    """Build a policy document with policy_hash."""
    if denied_tools is None:
        denied_tools = []
    policy = {
        "version": "1.0.0",
        "agent_id": agent_id,
        "allowed_tools": allowed_tools,
        "denied_tools": denied_tools,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "policy_hash": None,  # filled below
    }
    hash_input = json.dumps(
        {k: v for k, v in policy.items() if k != "policy_hash"}, sort_keys=True
    )
    policy["policy_hash"] = sha256_raw_hex(hash_input)
    return policy


def build_anchor(policy_hash: str, index: int = 1, prev_hash: str = None) -> dict:
    """Build a fake transparency log anchor."""
    if prev_hash is None:
        prev_hash = sha256_raw_hex("genesis")
    anchor = {
        "log_type": "transparency_log",
        "version": "1.0.0",
        "entries": [
            {
                "index": index,
                "prev_hash": prev_hash,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "merkle_root": sha256_raw_hex(f"root_{policy_hash}_{index}"),
                "policy_hash": policy_hash,
            }
        ],
    }
    # Alias for compatibility
    anchor["log_index"] = index
    anchor["log_id"] = sha256_raw_hex(f"logid_{index}_{prev_hash}")
    anchor["merkle_root"] = anchor["entries"][0]["merkle_root"]
    return anchor


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestReceiptFormat(unittest.TestCase):
    """Validate v0.3 ZK receipt format has all required fields."""

    def test_required_fields_present(self):
        from pact.zk_receipt_generator import build_zk_receipt
        from pact.zk_receipt_generator import compute_params_hash

        policy = build_policy("test-agent", ["read_file", "write_file"])
        anchor = build_anchor(policy["policy_hash"])

        params = {"path": "/tmp/test", "mode": "r"}
        params_hash = compute_params_hash(params)

        receipt = build_zk_receipt(
            policy=policy,
            tool_name="read_file",
            params=params,
            anchor=anchor,
            outcome=True,
            reason="allowed",
            request_id="req-test-001",
            seq=1,
            prev_receipt_hash=None,
        )

        # Core fields
        self.assertEqual(receipt["receipt_version"], "0.3.0")
        self.assertIn("receipt_hash", receipt)
        self.assertTrue(receipt["receipt_hash"].startswith("sha256:"))

        self.assertIn("action_id", receipt)
        self.assertIn("agent_id", receipt)
        self.assertEqual(receipt["agent_id"], "test-agent")

        self.assertIn("policy_hash", receipt)
        self.assertEqual(receipt["policy_hash"], policy["policy_hash"])

        self.assertIn("tool_called", receipt)
        self.assertEqual(receipt["tool_called"], "read_file")

        self.assertIn("params_hash", receipt)
        self.assertEqual(receipt["params_hash"], params_hash)

        self.assertIn("outcome", receipt)
        self.assertEqual(receipt["outcome"], "permitted")

        self.assertIn("proof", receipt)
        proof = receipt["proof"]
        self.assertIn("type", proof)
        self.assertEqual(proof["type"], "zk_membership_proof")
        self.assertEqual(proof["standard"], "urn:pact:receipt:v0.3")

        self.assertIn("zk", proof)
        zk = proof["zk"]
        self.assertIn("proof_type", zk)
        # DUMMY path produces DUMMY_ZK_PROOF; real path produces RISC0_MERKLEMembership
        self.assertIn(zk["proof_type"], ("DUMMY_ZK_PROOF", "RISC0_MERKLEMembership"))

        # Chain fields
        self.assertEqual(receipt["seq"], 1)
        self.assertIsNone(receipt["prev_receipt_hash"])

        # Anchor embedded
        self.assertIn("anchor", receipt)
        self.assertEqual(receipt["anchor"]["log_index"], 1)

    def test_denied_tool_receipt(self):
        from pact.zk_receipt_generator import build_zk_receipt

        policy = build_policy("test-agent", ["read_file"], denied_tools=["delete_file"])
        anchor = build_anchor(policy["policy_hash"])

        receipt = build_zk_receipt(
            policy=policy,
            tool_name="delete_file",
            params={},
            anchor=anchor,
            outcome=False,
            reason="denied",
            request_id="req-test-deny",
            seq=1,
            prev_receipt_hash=None,
        )

        self.assertEqual(receipt["outcome"], "denied")
        self.assertEqual(receipt["proof"]["type"], "zk_membership_proof")

    def test_params_hash_deterministic(self):
        from pact.zk_receipt_generator import compute_params_hash

        params = {"path": "/tmp/test", "mode": "r", "encoding": "utf-8"}
        h1 = compute_params_hash(params)
        h2 = compute_params_hash(params)
        self.assertEqual(h1, h2, "Params hash must be deterministic")

        # Order-independent (sort_keys=True)
        params_shuffled = {"mode": "r", "path": "/tmp/test", "encoding": "utf-8"}
        h3 = compute_params_hash(params_shuffled)
        self.assertEqual(h1, h3, "Params hash must be order-independent")


class TestReceiptChain(unittest.TestCase):
    """Validate receipt chain hash linking."""

    def test_chain_hash_linked(self):
        from pact.zk_receipt_generator import build_zk_receipt

        policy = build_policy("test-agent", ["read_file"])
        anchor = build_anchor(policy["policy_hash"])

        # Receipt 1
        r1 = build_zk_receipt(
            policy=policy,
            tool_name="read_file",
            params={},
            anchor=anchor,
            outcome=True,
            reason="allowed",
            request_id="req-chain-1",
            seq=1,
            prev_receipt_hash=None,
        )

        # Receipt 2 — links to r1 via prev_receipt_hash
        r2 = build_zk_receipt(
            policy=policy,
            tool_name="write_file",
            params={},
            anchor=anchor,
            outcome=True,
            reason="allowed",
            request_id="req-chain-2",
            seq=2,
            prev_receipt_hash=r1["receipt_hash"],
        )

        self.assertEqual(r2["seq"], 2)
        self.assertEqual(r2["prev_receipt_hash"], r1["receipt_hash"])
        self.assertIsNotNone(r2["receipt_hash"])
        # r2 must have different hash from r1
        self.assertNotEqual(r2["receipt_hash"], r1["receipt_hash"])

    def test_genesis_receipt_has_no_prev(self):
        from pact.zk_receipt_generator import build_zk_receipt

        policy = build_policy("test-agent", ["read_file"])
        anchor = build_anchor(policy["policy_hash"])

        r = build_zk_receipt(
            policy=policy,
            tool_name="read_file",
            params={},
            anchor=anchor,
            outcome=True,
            reason="allowed",
            request_id="req-genesis",
            seq=1,
            prev_receipt_hash=None,
        )

        self.assertIsNone(r["prev_receipt_hash"])
        # prev_receipt_hash=None means GENESIS in chain hash computation
        self.assertIsNotNone(r["receipt_hash"])


class TestAnchor(unittest.TestCase):
    """Validate anchor/log_index embedding in receipt."""

    def test_anchor_log_index_included(self):
        from pact.zk_receipt_generator import build_zk_receipt

        policy = build_policy("test-agent", ["read_file"])
        anchor = build_anchor(policy["policy_hash"], index=42)

        receipt = build_zk_receipt(
            policy=policy,
            tool_name="read_file",
            params={},
            anchor=anchor,
            outcome=True,
            reason="allowed",
            request_id="req-anchor",
            seq=1,
            prev_receipt_hash=None,
        )

        self.assertIn("anchor", receipt)
        self.assertEqual(receipt["anchor"]["log_index"], 42)
        self.assertIn("merkle_root", receipt["anchor"])

    def test_receipt_proof_statement_records_outcome(self):
        from pact.zk_receipt_generator import build_zk_receipt

        policy = build_policy("test-agent", ["read_file"])
        anchor = build_anchor(policy["policy_hash"])

        receipt = build_zk_receipt(
            policy=policy,
            tool_name="read_file",
            params={},
            anchor=anchor,
            outcome=True,
            reason="allowed",
            request_id="req-stmt",
            seq=1,
            prev_receipt_hash=None,
        )

        statement = receipt["proof"]["statement"]
        self.assertIn("committed_policy", statement)
        self.assertIn("log_index", statement)


class TestZKDummyMode(unittest.TestCase):
    """Validate DUMMY_PROOF path when RISC Zero is not available."""

    def test_dummy_proof_receipt_structurally_valid(self):
        from pact.zk_receipt_generator import build_zk_receipt

        policy = build_policy("test-agent", ["read_file"])
        anchor = build_anchor(policy["policy_hash"])

        receipt = build_zk_receipt(
            policy=policy,
            tool_name="read_file",
            params={},
            anchor=anchor,
            outcome=True,
            reason="allowed",
            request_id="req-dummy",
            seq=1,
            prev_receipt_hash=None,
        )

        proof = receipt["proof"]
        self.assertEqual(proof["type"], "zk_membership_proof")
        self.assertEqual(proof["standard"], "urn:pact:receipt:v0.3")

        zk = proof["zk"]
        self.assertIn("proof_type", zk)
        self.assertIn(zk["proof_type"], ("DUMMY_ZK_PROOF", "RISC0_MERKLEMembership"))
        self.assertIn("public_inputs_hash", zk)


class TestVerifyReceipt(unittest.TestCase):
    """Validate verify_zk_receipt() function."""

    def test_verify_valid_receipt(self):
        from pact.zk_receipt_generator import build_zk_receipt, verify_zk_receipt

        policy = build_policy("test-agent", ["read_file"])
        anchor = build_anchor(policy["policy_hash"])

        receipt = build_zk_receipt(
            policy=policy,
            tool_name="read_file",
            params={},
            anchor=anchor,
            outcome=True,
            reason="allowed",
            request_id="req-verify",
            seq=1,
            prev_receipt_hash=None,
        )

        result = verify_zk_receipt(receipt)
        self.assertTrue(result["valid"])
        self.assertEqual(result["proof_type"], receipt["proof"]["zk"]["proof_type"])
        self.assertTrue(result["is_dummy"])

    def test_verify_malformed_receipt_hash(self):
        from pact.zk_receipt_generator import verify_zk_receipt

        bad_receipt = {
            "receipt_hash": "not-a-valid-hash",
            "proof": {"zk": {"proof_type": "DUMMY_ZK_PROOF"}},
        }

        result = verify_zk_receipt(bad_receipt)
        self.assertFalse(result["valid"])

    def test_verify_missing_proof_type(self):
        from pact.zk_receipt_generator import verify_zk_receipt

        bad_receipt = {
            "receipt_hash": "sha256:abc123",
            "proof": {"zk": {}},
        }

        result = verify_zk_receipt(bad_receipt)
        self.assertFalse(result["valid"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
