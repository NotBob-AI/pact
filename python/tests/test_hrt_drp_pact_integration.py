"""
test_hrt_drp_pact_integration.py — PACT × HRT × DRP Full Stack Integration Test

Tests the complete accountability chain:
  HRT Principal (human) → DRP Authorization Object (user delegation)
    → PACT Policy (operator enforcement) → PACT Receipt (action proof)
    → HRT AgentActionReceipt (human-rooted, schema-compatible)

Ref: docs/HRT-integration.md + docs/DRP-integration.md
"""

import sys
sys.path.insert(0, 'python')

from pact.hrt_bridge import (
    pact_receipt_to_hrt,
    HRT_SCHEMA_URL,
    HrtPrincipal,
    HrtAuthorizationChain,
    receipt_format_owner,
)
from pact.drp_adapter import (
    DrpAuthorizationObject,
    DrpAuthorizationAdapter,
    MockLogClient,
)


def make_integration_receipt():
    """Build a realistic PACT receipt for the full-stack test."""
    return {
        "receipt_id": "pact-integration-001",
        "issued_at": "2026-06-24T11:00:00Z",
        "tool_call": {
            "tool_name": "bluesky.post",
            "tool_input_hash": "sha256:post001",
            "timestamp": "2026-06-24T11:00:00Z",
            "action_id": "action-integration-001",
        },
        "policy_commitment": {
            "policy_hash": "sha256:pactpolicy001",
            "log_id": "siglog-001",
            "merkle_root": "sha256:merkleroot001",
            "log_index": 1,
        },
        "proof": {
            "proof_type": "groth16",
            "image_id": "pact-v08",
            "public_inputs": ["sha256:pactpolicy001"],
        },
        "causal_binding": {
            "causal_hash": "sha256:causal001",
            "params_hash": "sha256:post001",
            "prev_commit_hash": "sha256:prevcommit",
        },
    }


class TestHrtDrpPactFullStack:
    """Full stack: HRT Principal → DRP Auth → PACT Policy → PACT Receipt → HRT AgentActionReceipt."""

    def test_hrt_principal_creation(self):
        principal = HrtPrincipal(
            principal_id="hrp:notbob-bob-lyons",
            human_did="did:web:boblyons.com",
            display_name="Bob Lyons",
        )
        d = principal.to_hrt_dict()
        assert d["principal_id"] == "hrp:notbob-bob-lyons"
        assert d["human_did"] == "did:web:boblyons.com"

    def test_hrt_authorization_chain_creation(self):
        chain = HrtAuthorizationChain(
            chain_id="chain-001",
            principal_id="hrp:notbob-bob-lyons",
            agent_id="did:pact:notbob-agent",
            delegated_scope=["bluesky.post", "filesystem.read"],
            valid_from="2026-06-24T00:00:00Z",
            valid_until="2026-06-25T00:00:00Z",
        )
        d = chain.to_hrt_dict()
        assert d["chain_id"] == "chain-001"
        assert d["principal_id"] == "hrp:notbob-bob-lyons"
        assert HRT_SCHEMA_URL in d["@context"]

    def test_drp_auth_object_creation(self):
        drp_auth = DrpAuthorizationObject(
            authorization_id="drp-auth-integration-001",
            authorizing_user_did="did:web:boblyons.com",
            operator_did="did:pact:notbob-agent",
            scope=["bluesky.post", "filesystem.read", "http.request"],
            time_window_start="2026-06-24T00:00:00Z",
            time_window_end="2026-06-25T00:00:00Z",
            model_state_hash="sha256:state001",
            instruction_hash="sha256:instr001",
        )
        assert drp_auth.authorization_id == "drp-auth-integration-001"
        assert "bluesky.post" in drp_auth.scope

    def test_drp_adapter_ingest_and_policy(self):
        drp_auth = DrpAuthorizationObject(
            authorization_id="drp-auth-integration-002",
            authorizing_user_did="did:web:boblyons.com",
            operator_did="did:pact:notbob-agent",
            scope=["bluesky.post", "filesystem.read"],
            time_window_start="2026-06-24T00:00:00Z",
            time_window_end="2026-06-25T00:00:00Z",
            model_state_hash="sha256:state001",
            instruction_hash="sha256:instr001",
        )
        log_client = MockLogClient()
        adapter = DrpAuthorizationAdapter(log_client, "did:pact:notbob-agent")
        adapter.ingested.append(drp_auth)
        pact_policy = adapter.to_pact_policy()
        assert "policy_hash" in pact_policy
        assert pact_policy["drp_authorization_id"] == "drp-auth-integration-002"

    def test_pact_receipt_to_hrt_agent_action_receipt(self):
        pact_receipt = make_integration_receipt()
        hrt = pact_receipt_to_hrt(
            pact_receipt,
            principal_id="hrp:notbob-bob-lyons",
            chain_id="drp-auth-integration-001",
        )
        assert HRT_SCHEMA_URL in hrt["@context"]
        assert hrt["type"] == "AgentActionReceipt"
        assert hrt["principal_id"] == "hrp:notbob-bob-lyons"
        assert hrt["action"]["tool_name"] == "bluesky.post"
        assert hrt["authorization_chain_id"] == "drp-auth-integration-001"
        assert hrt["pact_policy_commitment"]["policy_hash"] == "sha256:pactpolicy001"
        assert hrt["pact_zk_proof"]["proof_type"] == "groth16"
        assert hrt["pact_causal_binding"]["causal_hash"] == "sha256:causal001"

    def test_full_chain_hrt_to_hrt_agent_action_receipt(self):
        """
        Complete chain:
        HRT Principal + AuthorizationChain
          → DRP Authorization Object
          → PACT Policy (via DRP adapter)
          → PACT Receipt
          → HRT AgentActionReceipt
        """
        # Human principal
        principal = HrtPrincipal(
            principal_id="hrp:notbob-bob-lyons",
            human_did="did:web:boblyons.com",
            display_name="Bob Lyons",
        )

        # HRT AuthorizationChain (human → agent)
        chain = HrtAuthorizationChain(
            chain_id="chain-full-001",
            principal_id=principal.principal_id,
            agent_id="did:pact:notbob-agent",
            delegated_scope=["bluesky.post"],
            valid_from="2026-06-24T00:00:00Z",
            valid_until="2026-06-25T00:00:00Z",
        )
        assert chain.chain_id == "chain-full-001"

        # DRP Authorization Object (user → operator)
        drp_auth = DrpAuthorizationObject(
            authorization_id="drp-full-001",
            authorizing_user_did=principal.human_did,
            operator_did="did:pact:notbob-agent",
            scope=["bluesky.post"],
            time_window_start="2026-06-24T00:00:00Z",
            time_window_end="2026-06-25T00:00:00Z",
            model_state_hash="sha256:state001",
            instruction_hash="sha256:instr001",
        )

        # PACT Receipt (agent action)
        pact_receipt = make_integration_receipt()

        # HRT AgentActionReceipt (full chain anchored to human principal)
        hrt_receipt = pact_receipt_to_hrt(
            pact_receipt,
            principal_id=principal.principal_id,
            chain_id=drp_auth.authorization_id,
        )

        # Verify chain
        assert hrt_receipt["principal_id"] == principal.principal_id
        assert hrt_receipt["authorization_chain_id"] == drp_auth.authorization_id
        assert hrt_receipt["pact_causal_binding"] is not None
        assert receipt_format_owner() == "verifier"

    def test_receipt_format_owned_by_verifier(self):
        """The receipt format is owned by the verifier — agent cannot self-certify schema."""
        assert receipt_format_owner() == "verifier"
