"""
test_hrt_bridge.py — Tests for PACT × HRT Schema Bridge

HRT: Human Root of Trust — https://humanrootoftrust.org
Every agent traces to a human principal.
"""

import hashlib
import json
import pytest
from datetime import datetime, timezone

from pact.hrt_bridge import (
    HrtPrincipal,
    HrtAuthorizationChain,
    pact_receipt_to_hrt,
    hrt_receipt_verify_signature,
    HRT_CONTEXT,
    HRT_SCHEMA_URL,
    receipt_format_owner,
)


def make_pact_v038_receipt() -> dict:
    """Minimal PACT v0.3.8 receipt dict for testing."""
    return {
        "receipt_id": "receipt-test-001",
        "issued_at": "2026-06-24T10:00:00Z",
        "tool_call": {
            "tool_name": "filesystem.read",
            "tool_input_hash": "sha256:a1b2c3d4e5f6",
            "timestamp": "2026-06-24T10:00:00Z",
            "action_id": "action-test-001",
        },
        "policy_commitment": {
            "policy_hash": "sha256:abc123def456",
            "log_id": "pact-log-001",
            "merkle_root": "sha256:merkleroot001",
            "log_index": 42,
        },
        "proof": {
            "proof_type": "groth16",
            "image_id": "pact-zk-image-v1",
            "public_inputs": ["sha256:abc123def456"],
        },
        "causal_binding": {
            "causal_hash": "sha256:causal001",
            "params_hash": "sha256:a1b2c3d4e5f6",
            "prev_commit_hash": "sha256:prevcommit",
        },
    }


def make_pact_v01_receipt() -> dict:
    """Minimal PACT v0.1 receipt dict for testing."""
    return {
        "receipt_version": "0.1.0",
        "agent_id": "test-agent-001",
        "policy_hash": "sha256:v01polhash",
        "action_id": "action-v01-001",
        "timestamp": "2026-06-24T10:00:00Z",
        "tool_called": "http.request",
        "params_hash": "sha256:params001",
        "outcome": "permitted",
        "outcome_reason": "tool 'http.request' is permitted",
    }


class TestHrtPrincipal:
    def test_hrt_principal_to_dict(self):
        p = HrtPrincipal(
            principal_id="hrp:test-principal-001",
            human_did="did:example:alice",
            display_name="Alice",
        )
        d = p.to_hrt_dict()
        assert d["principal_id"] == "hrp:test-principal-001"
        assert d["human_did"] == "did:example:alice"
        assert d["display_name"] == "Alice"


class TestHrtAuthorizationChain:
    def test_chain_to_hrt_dict(self):
        chain = HrtAuthorizationChain(
            chain_id="chain-001",
            principal_id="hrp:test-principal-001",
            agent_id="did:key:z6Mk...",
            delegated_scope=["read", "write"],
            valid_from="2026-06-24T00:00:00Z",
            valid_until="2026-06-25T00:00:00Z",
        )
        d = chain.to_hrt_dict()
        assert d["chain_id"] == "chain-001"
        assert d["principal_id"] == "hrp:test-principal-001"
        assert d["agent_id"] == "did:key:z6Mk..."
        assert d["delegated_scope"] == ["read", "write"]
        assert HRT_CONTEXT[0] in d["@context"]

    def test_chain_roundtrip(self):
        chain = HrtAuthorizationChain(
            chain_id="chain-002",
            principal_id="hrp:test-principal-002",
            agent_id="did:pact:test-agent",
            delegated_scope=["analyze", "report"],
            valid_from="2026-06-24T00:00:00Z",
            valid_until="2026-06-30T00:00:00Z",
            principal_signature="sig:ed25519:deadbeef",
        )
        d = chain.to_hrt_dict()
        assert d["principal_signature"] == "sig:ed25519:deadbeef"


class TestPactReceiptToHrt:
    def test_v038_receipt_conversion(self):
        pact_receipt = make_pact_v038_receipt()
        hrt = pact_receipt_to_hrt(pact_receipt, "hrp:test-principal-001", chain_id="chain-001")

        assert HRT_SCHEMA_URL in hrt["@context"]
        assert hrt["type"] == "AgentActionReceipt"
        assert hrt["receipt_id"] == "receipt-test-001"
        assert hrt["principal_id"] == "hrp:test-principal-001"
        assert hrt["authorization_chain_id"] == "chain-001"
        assert hrt["action"]["tool_name"] == "filesystem.read"
        assert hrt["action"]["input_hash"] == "sha256:a1b2c3d4e5f6"

        # PACT extensions preserved
        assert hrt["pact_policy_commitment"]["policy_hash"] == "sha256:abc123def456"
        assert hrt["pact_zk_proof"]["proof_type"] == "groth16"
        assert hrt["pact_causal_binding"]["causal_hash"] == "sha256:causal001"

    def test_v01_receipt_conversion(self):
        pact_receipt = make_pact_v01_receipt()
        hrt = pact_receipt_to_hrt(pact_receipt, "did:example:bob")

        assert HRT_SCHEMA_URL in hrt["@context"]
        assert hrt["principal_id"] == "did:example:bob"
        assert hrt["action"]["tool_name"] == "http.request"
        assert hrt["pact_policy_commitment"]["policy_hash"] == "sha256:v01polhash"

    def test_minimal_receipt(self):
        """Minimal receipt with only the required fields."""
        minimal = {
            "tool_called": "shell.exec",
            "policy_hash": "sha256:minhash",
        }
        hrt = pact_receipt_to_hrt(minimal, "hrp:minimal-001")
        assert HRT_SCHEMA_URL in hrt["@context"]
        assert hrt["principal_id"] == "hrp:minimal-001"
        assert hrt["action"]["tool_name"] == "shell.exec"
        assert hrt["pact_policy_commitment"]["policy_hash"] == "sha256:minhash"

    def test_dummy_proof_omitted(self):
        pact_receipt = make_pact_v038_receipt()
        pact_receipt["proof"]["proof_type"] = "dummy"
        hrt = pact_receipt_to_hrt(pact_receipt, "hrp:test-001")
        assert hrt["pact_zk_proof"] is None

    def test_missing_causal_binding(self):
        pact_receipt = make_pact_v038_receipt()
        del pact_receipt["causal_binding"]
        hrt = pact_receipt_to_hrt(pact_receipt, "hrp:test-001")
        assert "pact_causal_binding" not in hrt


class TestHrtReceiptVerification:
    def test_valid_hrt_receipt(self):
        pact_receipt = make_pact_v038_receipt()
        hrt = pact_receipt_to_hrt(pact_receipt, "hrp:test-principal-001")
        result = hrt_receipt_verify_signature(hrt, b"")
        assert result["valid"] is True
        assert result["principal_id"] == "hrp:test-principal-001"

    def test_missing_context(self):
        hrt = {
            "type": "AgentActionReceipt",
            "receipt_id": "test-001",
            "principal_id": "hrp:test-001",
            "action": {"tool_name": "test"},
            # no @context
        }
        result = hrt_receipt_verify_signature(hrt, b"")
        assert result["valid"] is False
        assert "context" in result["reason"]

    def test_missing_action(self):
        hrt = {
            "@context": HRT_CONTEXT,
            "type": "AgentActionReceipt",
            "receipt_id": "test-001",
            "principal_id": "hrp:test-001",
            # no action
        }
        result = hrt_receipt_verify_signature(hrt, b"")
        assert result["valid"] is False
        assert "required" in result["reason"]


class TestReceiptFormatOwnership:
    def test_format_owned_by_verifier(self):
        assert receipt_format_owner() == "verifier"
