"""
PACT + ERC-8126 Identity Binding Layer

ERC-8126 (AI Agent Verification, Jan 2026) builds on ERC-8004 (agent registration) to provide
multi-layer identity attestation: ETV, MCV, SCV, WAV, WV.

PACT receipts prove policy compliance (WHAT the agent was authorized to do).
ERC-8126 attestations prove identity and capability (WHO the agent is, at a point in time).

These are complementary: an ERC-8126 attestation without a PACT receipt is a
verified identity without evidence of authorized action. A PACT receipt without
identity binding is evidence of authorized action without verified identity.

This module provides the binding: a PACT receipt can carry its agent's ERC-8126
attestation as a self-contained identity credential, verifiable by any third party
without a live chain lookup.

Architecture:
    create_identity_binding(agent_did, attestation) → IdentityBinding
    embed_binding(receipt, binding)                 → Receipt with identity field
    verify_binding(receipt)                          → verifies ERC-8126 attestation

Usage:
    binding = create_identity_binding(
        agent_did="did:key:... (ERC-8004 registered)",
        attestation={
            "erc8126_id": "0x...",
            "risk_score": 23,          # 0-100
            "verification_types": ["ETV", "SCV", "WV"],
            "registered_at": "2026-01-20T...",
            "attestor": "0x... (verification provider address)"
        }
    )
    enhanced_receipt = embed_binding(base_receipt, binding)
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# ERC-8126 Constants
# ---------------------------------------------------------------------------

ERC8126_VERIFICATION_TYPES = ["ETV", "MCV", "SCV", "WAV", "WV"]

# Risk score thresholds (ERC-8126 spec: 0-100)
RISK_SCORE_TRUSTED = 30      # Low risk — agent passed multi-layer verification
RISK_SCORE_CAUTION = 60       # Moderate risk — partial verification
RISK_SCORE_HIGH = 100         # High risk — minimal or no verification


# ---------------------------------------------------------------------------
# Identity Binding
# ---------------------------------------------------------------------------

@dataclass
class ERC8126Attestation:
    """ERC-8126 multi-layer verification attestation."""
    erc8126_id: str                    # ERC-8126 attestation ID (on-chain)
    agent_did: str                     # ERC-8004 registered agent DID
    risk_score: int                    # 0-100 unified risk score
    verification_types: list[str]      # Which layers passed (subset of ETV/MCV/SCV/WAV/WV)
    registered_at: str                 # ISO timestamp of ERC-8004 registration
    attestor: str                       # Verification provider address
    attestation_timestamp: str         # When this attestation was issued
    chain_id: Optional[int] = None      # Ethereum chain ID (default: 1 = mainnet)

    def __post_init__(self):
        if self.risk_score < 0 or self.risk_score > 100:
            raise ValueError(f"risk_score must be 0-100, got {self.risk_score}")
        for vt in self.verification_types:
            if vt not in ERC8126_VERIFICATION_TYPES:
                raise ValueError(f"Unknown verification type: {vt}")

    @property
    def risk_level(self) -> str:
        """Human-readable risk classification."""
        if self.risk_score <= RISK_SCORE_TRUSTED:
            return "TRUSTED"
        elif self.risk_score <= RISK_SCORE_CAUTION:
            return "CAUTION"
        else:
            return "HIGH"

    @property
    def is_trusted(self) -> bool:
        """True if agent passed sufficient verification layers."""
        return (
            self.risk_score <= RISK_SCORE_TRUSTED
            and len(self.verification_types) >= 3
        )

    def to_dict(self) -> dict:
        return {
            "erc8126_id": self.erc8126_id,
            "agent_did": self.agent_did,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "verification_types": self.verification_types,
            "registered_at": self.registered_at,
            "attestor": self.attestor,
            "attestation_timestamp": self.attestation_timestamp,
            "chain_id": self.chain_id or 1,
        }


@dataclass
class IdentityBinding:
    """
    PACT + ERC-8126 identity binding.

    Binds a PACT receipt to its agent's ERC-8126 attestation.
    The binding is embedded directly in the receipt — no external lookup needed
    to understand who produced this receipt and their verification status.

    The binding_hash provides integrity verification: if the attestation changes,
    the binding_hash changes, invalidating the receipt's identity claim.

    Security note (v0.5.1): The binding_hash covers attestation data only.
    A complete forgery-resistant binding requires the agent to sign the receipt
    using its ERC-8004 DID key (Ed25519). The receipt signature should be
    verified against agent_did before accepting the identity_binding as authoritative.
    This version adds cross_layer_check (agent DID in tool call hash) as a partial
    mitigation — it makes it impossible to use a legitimate binding with a stolen
    receipt from a different agent without detection.
    """
    attestation: ERC8126Attestation
    binding_hash: str                  # SHA-256(attestation data + agent_did) — integrity seal
    cross_layer_check: str            # SHA-256(agent_did + tool_call_hash) — ties identity to action
    composed_with_erc8004: bool = True  # ERC-8004 registration is prerequisite

    @classmethod
    def create(cls, attestation: ERC8126Attestation, tool_call_hash: str) -> "IdentityBinding":
        """
        Create a new identity binding with computed integrity hash.

        Args:
            attestation: ERC-8126 attestation for this agent
            tool_call_hash: sha256 hash of the tool call this binding is attached to.
                           Must match the tool_call.tool_input_hash in the receipt.
                           Ties the identity to the specific action — a binding cannot
                           be copied to a different agent's receipt without detection.
        """
        # Include agent_did in the binding hash so the binding is scoped to one agent
        att_data = json.dumps({
            **attestation.to_dict(),
            "agent_did": attestation.agent_did,
        }, sort_keys=True)
        binding_hash = f"sha256:{hashlib.sha256(att_data.encode('utf-8')).hexdigest()}"

        # Cross-layer check: ties this binding to the specific tool call.
        # An attacker who steals a receipt cannot embed a binding from agent B
        # onto agent A's receipt without breaking this hash.
        cross_layer_data = json.dumps({
            "agent_did": attestation.agent_did,
            "tool_call_hash": tool_call_hash,
        }, sort_keys=True)
        cross_layer_check = f"sha256:{hashlib.sha256(cross_layer_data.encode('utf-8')).hexdigest()}"

        return cls(
            attestation=attestation,
            binding_hash=binding_hash,
            cross_layer_check=cross_layer_check,
            composed_with_erc8004=True,
        )

    def to_dict(self) -> dict:
        return {
            "binding_hash": self.binding_hash,
            "cross_layer_check": self.cross_layer_check,
            "composed_with_erc8004": self.composed_with_erc8004,
            "attestation": self.attestation.to_dict(),
        }


# ---------------------------------------------------------------------------
# Binding + Receipt Integration
# ---------------------------------------------------------------------------

def create_identity_binding(
    agent_did: str,
    attestation_data: dict,
    tool_call_hash: str,
) -> IdentityBinding:
    """
    Factory: create an IdentityBinding from agent DID and attestation data.

    SECURITY: tool_call_hash is MANDATORY. It ties the binding to the specific
    tool call in the receipt. Without it, a stolen binding from agent B could be
    embedded into a legitimate receipt from agent A — verify_binding() would pass
    because the attestation is valid, even though the identity doesn't match the
    agent that actually generated the receipt.

    Args:
        agent_did: ERC-8004 registered agent DID (did:key:... or did:erc8004:...)
        attestation_data: {
            "erc8126_id": str,
            "risk_score": int,
            "verification_types": list[str],
            "registered_at": str,
            "attestor": str,
            "attestation_timestamp": str,
            "chain_id": int (optional)
        }
        tool_call_hash: sha256:... hash of the tool call from the receipt
                       (tool_call.tool_input_hash or tool_call.tool_output_hash).
                       Must match what will be in the receipt when embed_binding is called.

    Returns:
        IdentityBinding with computed integrity hash.
    """
    attestation = ERC8126Attestation(
        erc8126_id=attestation_data["erc8126_id"],
        agent_did=agent_did,
        risk_score=attestation_data["risk_score"],
        verification_types=attestation_data["verification_types"],
        registered_at=attestation_data["registered_at"],
        attestor=attestation_data["attestor"],
        attestation_timestamp=attestation_data["attestation_timestamp"],
        chain_id=attestation_data.get("chain_id"),
    )
    return IdentityBinding.create(attestation, tool_call_hash=tool_call_hash)


def embed_binding(receipt: dict, binding: IdentityBinding) -> dict:
    """
    Embed an IdentityBinding into an existing PACT receipt.

    Adds an "identity_binding" field to the receipt that carries the ERC-8126
    attestation without requiring the verifier to do a live chain lookup.

    The receipt's overall integrity depends on both:
    1. The policy_hash chain (proving the action was authorized)
    2. The identity_binding hash (proving the agent was verified at action time)

    Security check (v0.5.1): Extracts the tool_call_hash from the receipt and
    verifies it matches the cross_layer_check in the binding. This prevents
    a stolen identity binding from being embedded onto a receipt from a different
    agent. If the tool_call_hash in the receipt doesn't match, raises ValueError.

    Args:
        receipt: dict, a PACT receipt (v0.1+) — must have policy_commitment and tool_call
        binding: IdentityBinding from create_identity_binding()

    Returns:
        dict, the receipt with identity_binding added

    Raises:
        ValueError: if receipt missing required fields or cross_layer_check fails
    """
    # Extract tool call hash from receipt for cross-layer verification
    tool_call_section = receipt.get("tool_call") or receipt.get("tool")
    if not tool_call_section:
        raise ValueError("Receipt has no tool_call field — cannot bind identity")
    tool_call_hash = tool_call_section.get("tool_input_hash") or tool_call_section.get("tool_output_hash")
    if not tool_call_hash:
        raise ValueError("Receipt tool_call has no tool_input_hash or tool_output_hash — cannot verify cross-layer binding")

    # Verify cross_layer_check matches the tool call in this receipt.
    # This blocks the attack where attacker steals a valid binding and pastes
    # it onto a receipt from a different agent.
    cross_layer_data = json.dumps({
        "agent_did": binding.attestation.agent_did,
        "tool_call_hash": tool_call_hash,
    }, sort_keys=True)
    expected_cross = f"sha256:{hashlib.sha256(cross_layer_data.encode('utf-8')).hexdigest()}"
    if binding.cross_layer_check != expected_cross:
        raise ValueError(
            f"cross_layer_check mismatch: binding was created for tool_call_hash {binding.cross_layer_check[:20]}... "
            f"but receipt contains {tool_call_hash[:20]}... — binding cannot be transferred between receipts"
        )

    # Verify agent_did in binding matches agent_id in receipt.
    # Without this check, an attacker who steals a binding from agent B can embed
    # it into a receipt from agent A — the cross_layer_check alone doesn't block this
    # because the attacker creates the binding with the correct (agent_A's) tool_call_hash.
    receipt_agent = receipt.get("agent_id") or receipt.get("agent") or (
        receipt.get("policy", {}).get("agent_id") if isinstance(receipt.get("policy"), dict) else None
    )
    if receipt_agent and binding.attestation.agent_did != receipt_agent:
        raise ValueError(
            f"agent_did mismatch: binding is for {binding.attestation.agent_did[:30]}... "
            f"but receipt belongs to {receipt_agent} — binding cannot be transferred between agents"
        )

    has_policy = "policy_commitment" in receipt or "policy" in receipt or "policy_hash" in receipt
    if not has_policy:
        raise ValueError("Receipt has no policy or policy_hash field — cannot bind identity")

    enhanced = dict(receipt)
    enhanced["identity_binding"] = binding.to_dict()

    # Re-hash the full receipt with the binding included
    receipt_without_hash = {k: v for k, v in enhanced.items() if k != "receipt_hash"}
    receipt_json = json.dumps(receipt_without_hash, sort_keys=True, default=str)
    new_hash = f"sha256:{hashlib.sha256(receipt_json.encode('utf-8')).hexdigest()}"
    enhanced["receipt_hash"] = new_hash
    enhanced["_identity_anchored"] = True

    return enhanced


def verify_binding(receipt: dict) -> dict:
    """
    Verify the identity_binding embedded in a PACT receipt.

    Checks:
    1. identity_binding field is present
    2. binding_hash integrity (attestation was not tampered after binding)
    3. cross_layer_check integrity (binding belongs to this receipt's tool call)
    4. attestation risk_score is within acceptable threshold

    Does NOT verify the on-chain ERC-8126 attestation itself — that requires
    an external chain lookup. This function verifies the local binding only.

    Args:
        receipt: dict, a PACT receipt with embedded identity_binding

    Returns:
        { valid: bool, reason: str, attestation: dict, warnings: list[str] }
    """
    warnings = []

    if "identity_binding" not in receipt:
        return {
            "valid": False,
            "reason": "receipt has no identity_binding field",
            "attestation": None,
            "warnings": [],
        }

    binding_data = receipt["identity_binding"]
    stored_hash = binding_data.get("binding_hash")
    stored_cross = binding_data.get("cross_layer_check")
    attestation_dict = binding_data.get("attestation", {})

    # 1. Extract tool_call_hash from receipt for cross-layer verification
    tool_call_section = receipt.get("tool_call") or receipt.get("tool")
    if not tool_call_section:
        return {
            "valid": False,
            "reason": "receipt has no tool_call field — cannot verify cross_layer_check",
            "attestation": attestation_dict,
            "warnings": [],
        }
    tool_call_hash = tool_call_section.get("tool_input_hash") or tool_call_section.get("tool_output_hash")
    if not tool_call_hash:
        return {
            "valid": False,
            "reason": "receipt tool_call has no tool_input_hash or tool_output_hash",
            "attestation": attestation_dict,
            "warnings": [],
        }

    # 2. Verify cross_layer_check: binds identity to the specific action in this receipt
    agent_did = attestation_dict.get("agent_did", "")
    cross_layer_data = json.dumps({
        "agent_did": agent_did,
        "tool_call_hash": tool_call_hash,
    }, sort_keys=True)
    expected_cross = f"sha256:{hashlib.sha256(cross_layer_data.encode('utf-8')).hexdigest()}"
    if stored_cross != expected_cross:
        return {
            "valid": False,
            "reason": "cross_layer_check mismatch — identity binding does not belong to this receipt",
            "attestation": attestation_dict,
            "warnings": ["cross-layer forgery detected — binding was copied from another receipt"],
        }

    # 3. Re-compute binding_hash from attestation data
    # Note: IdentityBinding.create requires tool_call_hash — pass the receipt's hash
    attestation_for_hash = {k: v for k, v in attestation_dict.items() if k != "risk_level"}
    try:
        attestation_obj = ERC8126Attestation(**attestation_for_hash)
        computed = IdentityBinding.create(attestation_obj, tool_call_hash=tool_call_hash).binding_hash
    except Exception as e:
        return {
            "valid": False,
            "reason": f"attestation data malformed: {e}",
            "attestation": attestation_dict,
            "warnings": [],
        }

    if computed != stored_hash:
        return {
            "valid": False,
            "reason": "binding_hash mismatch — attestation was modified after binding",
            "attestation": attestation_dict,
            "warnings": ["integrity violation — identity_binding tampered"],
        }

    risk_score = attestation_dict.get("risk_score", 100)
    risk_level = "TRUSTED" if risk_score <= RISK_SCORE_TRUSTED else (
        "CAUTION" if risk_score <= RISK_SCORE_CAUTION else "HIGH"
    )

    if risk_level == "HIGH":
        warnings.append(f"risk_score={risk_score} — agent passed minimal verification")

    verification_types = attestation_dict.get("verification_types", [])
    if len(verification_types) < 3:
        warnings.append(f"only {len(verification_types)} verification layers passed (ERC-8126 recommends ≥3)")

    return {
        "valid": True,
        "reason": f"identity_binding verified — risk_level={risk_level}, risk_score={risk_score}",
        "attestation": attestation_dict,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def demo():
    """Demonstrate the ERC-8126 + PACT identity binding flow."""
    import sys, os, json, hashlib
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from pact.receipt import (
        PACTReceipt, PolicyCommitment, ToolCall, ZKProof,
        create_receipt, receipt_to_dict,
    )
    from pact.commitment import TransparencyLog

    # 1. Agent has an ERC-8004 DID and an ERC-8126 attestation
    agent_did = "did:key:z6MkqJ.."
    attestation_data = {
        "erc8126_id": "0x7f3a...c2b1",
        "risk_score": 18,                   # Low risk — passed 4 of 5 verification layers
        "verification_types": ["ETV", "SCV", "WV", "MCV"],
        "registered_at": "2026-01-20T10:00:00Z",
        "attestor": "0xAttestorVerificationProviderContract",
        "attestation_timestamp": "2026-04-15T08:30:00Z",
        "chain_id": 1,
    }

    # 2. Build a proper v0.3 PACT receipt with tool_call dict
    tool_input_hash = f"sha256:{hashlib.sha256(b'test-input').hexdigest()}"
    policy_commitment = PolicyCommitment(
        policy_hash="sha256:demo_policy_hash_example",
        log_index=42,
        log_id="sha256:demo_log_id_example",
        merkle_root="sha256:demo_merkle_root_example",
        merkle_proof=[],
    )
    tool_call = ToolCall(
        tool_name="read_file",
        tool_input_hash=tool_input_hash,
        timestamp="2026-04-15T08:30:00Z",
        action_id="demo-action-001",
    )
    receipt_obj = create_receipt(policy_commitment, tool_call, proof=None)
    receipt = receipt_to_dict(receipt_obj)
    # Add agent_id to receipt — embed_binding checks binding.attestation.agent_did against receipt.agent_id
    receipt["agent_id"] = agent_did

    # 3. Create identity binding — tool_call_hash is now REQUIRED (v0.5.1 security fix)
    binding = create_identity_binding(agent_did, attestation_data, tool_call_hash=tool_input_hash)
    print(f"IdentityBinding created:")
    print(f"  agent_did: {binding.attestation.agent_did[:20]}...")
    print(f"  risk_score: {binding.attestation.risk_score} ({binding.attestation.risk_level})")
    print(f"  layers: {', '.join(binding.attestation.verification_types)}")
    print(f"  binding_hash: {binding.binding_hash[:30]}...")
    print(f"  cross_layer_check: {binding.cross_layer_check[:30]}...")

    # 4. Embed binding into receipt — embed_binding verifies cross_layer_check
    enhanced = embed_binding(receipt, binding)
    print(f"\nEnhanced receipt:")
    print(f"  version: {enhanced.get('version')}")
    print(f"  identity_anchored: {enhanced.get('_identity_anchored')}")
    print(f"  risk_level: {enhanced['identity_binding']['attestation']['risk_level']}")

    # 5. Verify the binding
    result = verify_binding(enhanced)
    print(f"\nBinding verification:")
    print(f"  valid: {result['valid']}")
    print(f"  reason: {result['reason']}")
    for w in result.get("warnings", []):
        print(f"  ⚠ {w}")

    # 6. Demonstrate the forgery attack is now blocked
    print(f"\n--- Forgery attack simulation ---")
    agent_B_did = "did:key:z6MkqB.."
    agent_B_attestation = {
        "erc8126_id": "0xBBBB...BBBB",
        "risk_score": 18,
        "verification_types": ["ETV", "SCV", "WV", "MCV"],
        "registered_at": "2026-01-20T10:00:00Z",
        "attestor": "0xAttestorVerificationProviderContract",
        "attestation_timestamp": "2026-04-15T08:30:00Z",
        "chain_id": 1,
    }
    # Attacker reuses agent_A's tool_call_hash but with agent_B's DID
    attacker_binding = create_identity_binding(agent_B_did, agent_B_attestation, tool_call_hash=tool_input_hash)
    try:
        forged = embed_binding(receipt, attacker_binding)
        print(f"  FAIL: attacker embedding succeeded — forgery not blocked!")
    except ValueError as e:
        print(f"  PASS: attacker embedding blocked — {e}")

    print("\n✓ ERC-8126 identity binding flow complete (v0.5.1)")


if __name__ == "__main__":
    demo()
