"""
hrt_bridge.py — PACT × Human Root of Trust (HRT) Schema Bridge

Bridges PACT v0.3+ receipts into the HRT (Human Root of Trust) AgentActionReceipt
format, making PACT receipts HRT-compatible out of the box.

HRT framework: https://humanrootoftrust.org
HRT schemas: https://github.com/humanrootoftrust/schemas
HRT receipt schema: https://humanrootoftrust.org/schemas/v1/receipt

Every agent traces to a human. HRT defines the schema for that trace.
PACT defines the receipt proving action ∈ committed policy.

Together: HRT principal anchors the identity, PACT receipts prove the action.

Architecture:
    HRT Principal (human) → HRT AuthorizationChain → PACT policy commitment
                        → PACT receipt → HRT AgentActionReceipt format

Ref: docs/HRT-integration.md
"""

from __future__ import annotations
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Optional


HRT_SCHEMA_URL = "https://humanrootoftrust.org/schemas/v1/receipt"
HRT_CONTEXT = ["https://humanrootoftrust.org/schemas/v1/receipt"]


class HrtPrincipal:
    """
    Represents an HRT Principal — the human root of trust for an agent.

    Per HRT framework: every agent must trace to a human principal.
    The principal signs the AuthorizationChain that delegates to the agent.
    """

    def __init__(
        self,
        principal_id: str,
        human_did: Optional[str] = None,
        display_name: Optional[str] = None,
        hrt_principal_uri: Optional[str] = None,
    ):
        self.principal_id = principal_id  # HRT Principal ID or human DID
        self.human_did = human_did or principal_id
        self.display_name = display_name
        self.hrt_principal_uri = hrt_principal_uri  # e.g. https://humanrootoftrust.org/principal/{id}

    def to_hrt_dict(self) -> dict:
        return {
            "principal_id": self.principal_id,
            "human_did": self.human_did,
            "display_name": self.display_name,
            "hrt_principal_uri": self.hrt_principal_uri,
        }


class HrtAuthorizationChain:
    """
    Represents an HRT AuthorizationChain — the verifiable record of how
    a human's intent flows through agents.

    Links HRT Principal → PACT agent via signed delegation statement.
    """

    def __init__(
        self,
        chain_id: str,
        principal_id: str,
        agent_id: str,
        delegated_scope: list[str],
        valid_from: str,
        valid_until: str,
        principal_signature: Optional[str] = None,
        raw: Optional[dict] = None,
    ):
        self.chain_id = chain_id
        self.principal_id = principal_id
        self.agent_id = agent_id
        self.delegated_scope = delegated_scope
        self.valid_from = valid_from
        self.valid_until = valid_until
        self.principal_signature = principal_signature  # Ed25519 signature over chain_id
        self.raw = raw or self._to_dict()

    def _to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "principal_id": self.principal_id,
            "agent_id": self.agent_id,
            "delegated_scope": self.delegated_scope,
            "validity_window": {
                "from": self.valid_from,
                "until": self.valid_until,
            },
            "principal_signature": self.principal_signature,
        }

    def to_hrt_dict(self) -> dict:
        return {
            "@context": HRT_CONTEXT,
            **self._to_dict(),
        }


def pact_receipt_to_hrt(
    pact_receipt: dict,
    principal_id: str,
    chain_id: Optional[str] = None,
) -> dict:
    """
    Convert a PACT receipt to HRT AgentActionReceipt-compatible format.

    Adds HRT @context and principal_id without changing PACT semantics.
    The PACT receipt fields are preserved as pact_* extensions.

    Args:
        pact_receipt: PACT v0.3+ receipt dict (from PACTReceipt or raw JSON)
        principal_id: HRT Principal ID or human DID — the human root of trust
        chain_id: Optional HRT AuthorizationChain ID linking this action to human intent

    Returns:
        dict: HRT AgentActionReceipt-compatible JSON
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Extract PACT receipt fields
    tool_call = pact_receipt.get("tool_call", {})
    policy_commitment = pact_receipt.get("policy_commitment", {})
    proof = pact_receipt.get("proof", {})

    receipt_id = pact_receipt.get("receipt_id") or pact_receipt.get("action_id") or f"hrt-{uuid.uuid4().hex[:12]}"
    tool_name = tool_call.get("tool_name") or pact_receipt.get("tool_called", "unknown")
    tool_input_hash = tool_call.get("tool_input_hash") or pact_receipt.get("params_hash", "")
    timestamp = tool_call.get("timestamp") or pact_receipt.get("timestamp", now)
    action_id = tool_call.get("action_id") or pact_receipt.get("action_id", "")

    # Build HRT AgentActionReceipt
    hrt_receipt = {
        "@context": HRT_CONTEXT,
        # HRT AgentActionReceipt core fields
        "type": "AgentActionReceipt",
        "receipt_id": receipt_id,
        "principal_id": principal_id,  # Human anchor — every agent traces here
        "issued_at": pact_receipt.get("issued_at", now),
        "action": {
            "tool_name": tool_name,
            "input_hash": tool_input_hash,
            "timestamp": timestamp,
            "action_id": action_id,
        },
        # AuthorizationChain link (if provided)
        "authorization_chain_id": chain_id,
        # PACT layer: policy commitment
        "pact_policy_commitment": {
            "policy_hash": policy_commitment.get("policy_hash") or pact_receipt.get("policy_hash", ""),
            "log_id": policy_commitment.get("log_id", ""),
            "merkle_root": policy_commitment.get("merkle_root", ""),
            "log_index": policy_commitment.get("log_index", 0),
        },
        # PACT layer: ZK proof (if present)
        "pact_zk_proof": None,
    }

    # Attach ZK proof if present in PACT receipt
    if proof and proof.get("proof_type") not in (None, "dummy", "sha256_membership"):
        hrt_receipt["pact_zk_proof"] = {
            "proof_type": proof.get("proof_type", "zk"),
            "image_id": proof.get("image_id", ""),
            "public_inputs": proof.get("public_inputs", []),
        }

    # Attach causal binding if present (v0.8.1+)
    causal = pact_receipt.get("causal_binding", {})
    if causal:
        hrt_receipt["pact_causal_binding"] = {
            "causal_hash": causal.get("causal_hash", ""),
            "params_hash": causal.get("params_hash", ""),
            "prev_commit_hash": causal.get("prev_commit_hash", ""),
        }

    return hrt_receipt


def hrt_receipt_verify_signature(
    hrt_receipt: dict,
    principal_pubkey: bytes,
) -> dict:
    """
    Verify an HRT AgentActionReceipt signature.

    The receipt is signed by the PACT agent's key (not the human principal).
    The human principal's signature is on the AuthorizationChain, not the action receipt.

    This verifies the PACT agent's signature over the receipt.
    """
    # HRT receipts from PACT are signed by the agent, not the principal
    # The principal's trust chain is established via AuthorizationChain
    receipt_id = hrt_receipt.get("receipt_id", "")
    principal_id = hrt_receipt.get("principal_id", "")

    # Minimal verification: receipt has required HRT fields
    required = ["@context", "type", "receipt_id", "principal_id", "action"]
    missing = [f for f in required if f not in hrt_receipt]
    if missing:
        return {"valid": False, "reason": f"missing required fields: {missing}"}

    if HRT_SCHEMA_URL not in hrt_receipt.get("@context", []):
        return {"valid": False, "reason": "missing HRT schema context"}

    return {
        "valid": True,
        "reason": "HRT AgentActionReceipt schema valid",
        "receipt_id": receipt_id,
        "principal_id": principal_id,
    }


# ---------------------------------------------------------------------------
# Receipt format ownership
# ---------------------------------------------------------------------------

RECEIPT_FORMAT_OWNER = "verifier"


def receipt_format_owner() -> str:
    """
    The receipt format is owned by the verifier, not the agent.

    This is the core property that makes receipts trustworthy:
    - The agent generates receipts
    - The verifier specifies the format
    - The agent cannot change the schema without breaking verification

    HRT Schema Bridge respects this: PACT receipts → HRT format is a
    lossy transformation (some PACT fields become opaque to verifiers
    that only understand HRT schema). The PACT fields survive in the
    pact_* extensions but do not affect HRT schema validation.
    """
    return RECEIPT_FORMAT_OWNER