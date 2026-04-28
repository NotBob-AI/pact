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
    """
    attestation: ERC8126Attestation
    binding_hash: str                  # SHA-256(attestation data) — integrity seal
    composed_with_erc8004: bool = True  # ERC-8004 registration is prerequisite

    @classmethod
    def create(cls, attestation: ERC8126Attestation) -> "IdentityBinding":
        """Create a new identity binding with computed integrity hash."""
        att_data = json.dumps(attestation.to_dict(), sort_keys=True)
        binding_hash = f"sha256:{hashlib.sha256(att_data.encode('utf-8')).hexdigest()}"
        return cls(
            attestation=attestation,
            binding_hash=binding_hash,
            composed_with_erc8004=True,
        )

    def to_dict(self) -> dict:
        return {
            "binding_hash": self.binding_hash,
            "composed_with_erc8004": self.composed_with_erc8004,
            "attestation": self.attestation.to_dict(),
        }


# ---------------------------------------------------------------------------
# Binding + Receipt Integration
# ---------------------------------------------------------------------------

def create_identity_binding(
    agent_did: str,
    attestation_data: dict,
) -> IdentityBinding:
    """
    Factory: create an IdentityBinding from agent DID and attestation data.

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
    return IdentityBinding.create(attestation)


def embed_binding(receipt: dict, binding: IdentityBinding) -> dict:
    """
    Embed an IdentityBinding into an existing PACT receipt.

    Adds an "identity_binding" field to the receipt that carries the ERC-8126
    attestation without requiring the verifier to do a live chain lookup.

    The receipt's overall integrity depends on both:
    1. The policy_hash chain (proving the action was authorized)
    2. The identity_binding hash (proving the agent was verified at action time)

    Args:
        receipt: dict, a PACT receipt (v0.1+) — must have policy_commitment and tool_call
        binding: IdentityBinding from create_identity_binding()

    Returns:
        dict, the receipt with identity_binding added

    Raises:
        ValueError: if receipt missing required fields
    """
    has_policy = "policy_commitment" in receipt or "policy" in receipt or "policy_hash" in receipt
    has_tool = "tool_call" in receipt or "tool_called" in receipt
    if not has_policy:
        raise ValueError("Receipt has no policy or policy_hash field — cannot bind identity")
    if not has_tool:
        raise ValueError("Receipt has no tool_call or tool_called field — cannot bind identity")
        raise ValueError("Receipt missing tool_call — cannot bind identity")

    enhanced = dict(receipt)
    enhanced["identity_binding"] = binding.to_dict()

    # Add identity_binding to receipt hash chain for integrity
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
    3. attestation risk_score is within acceptable threshold

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

    binding = receipt["identity_binding"]
    stored_hash = binding.get("binding_hash")
    attestation_dict = binding.get("attestation", {})

    # Re-compute binding hash
    # Strip computed fields that aren't inputs to ERC8126Attestation
    attestation_for_hash = {k: v for k, v in attestation_dict.items() if k != "risk_level"}
    try:
        computed = IdentityBinding.create(
            ERC8126Attestation(**attestation_for_hash)
        ).binding_hash
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
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from pact import create_policy, generate_receipt
    from pact.commitment import TransparencyLog, anchor_policy

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

    # 2. Create identity binding
    binding = create_identity_binding(agent_did, attestation_data)
    print(f"IdentityBinding created:")
    print(f"  agent_did: {binding.attestation.agent_did[:20]}...")
    print(f"  risk_score: {binding.attestation.risk_score} ({binding.attestation.risk_level})")
    print(f"  layers: {', '.join(binding.attestation.verification_types)}")
    print(f"  binding_hash: {binding.binding_hash[:30]}...")

    # 3. Create a PACT receipt (v0.3)
    policy = create_policy(agent_did, ["read", "analyze"], ["delete", "exec"])
    receipt, _, _ = generate_receipt(
        policy=policy,
        tool_name="read_file",
        params={"path": "/data/patient-records.csv"},
    )

    # 4. Embed binding into receipt
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

    print("\n✓ ERC-8126 identity binding flow complete")


if __name__ == "__main__":
    demo()
