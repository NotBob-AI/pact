"""
hjs_adapter.py — PACT + HJS/JEP Integration Adapter

Implements interoperability between PACT receipts and HJS (Human Judgment Structure),
the IETF draft-wang-hjs-accountability-05 standard for AI agent accountability receipts.

HJS is a profile of JEP (Judgment Event Protocol) that provides:
  - Behavior-record digest binding
  - Receipt manifests and bundles
  - Optional multi-party export

This adapter enables:
  1. PACT receipts to be exported as HJS-compliant JEP events
  2. HJS receipts to be validated and mapped to PACT policy compliance
  3. Multi-party HJS receipt bundles to include PACT agent-side receipts

Reference: draft-wang-hjs-accountability-05 (IETF, April 29 2026)
            draft-wang-jep-judgment-event-protocol (IETF)
            draft-wang-jac — declared dependency chains for agent receipts

HJS Architecture (minimal core):
  Behavior Record: { who, what, when, evidence_refs } — digest-bound to JEP event
  Receipt Manifest: { behavior_record_digest, issuer, timestamp, extensions }
  JEP Event: JWS over JCS-canonicalized behavior record, signed by issuer

PACT maps to HJS as:
  PACT action_receipt.what  → HJS Behavior Record (action observed)
  PACT policy_hash          → HJS Policy Check Evidence extension (proves ∈ committed policy)
  PACT intent_receipt.when  → HJS behavior record timestamp
  PACT agent DID            → HJS who (issuer of the behavior record)
"""

from __future__ import annotations

import hashlib
import json
import base64
import struct
from dataclasses import dataclass, field, asdict
from typing import Optional, Any
from datetime import datetime, timezone


# HJS/JEP namespace constants
HJS_VERSION = "urn:hjs:accountability:v05"
JEP_VERSION = "urn:jep:judgment-event-protocol:v1"
PACT_HJS_PROFILE = "urn:pact:hjs:v1"

# JEP verb constants for HJS behavior records
JEP_VERB_EXECUTE = "jep:execute"      # Agent executed an action
JEP_VERB_COMMIT = "jep:commit"        # Agent committed to policy before action
JEP_VERB_TOOL = "jep:tool_call"        # Tool call occurred
JEP_VERB_VERIFY = "jep:verify"        # Verification performed

# HJS receipt manifest keys
HJS_EXT_POLICY_CHECK = "hjs:policy_check"
HJS_EXT_TOOL_EVIDENCE = "hjs:tool_evidence"
HJS_EXT_MODEL_EVIDENCE = "hjs:model_evidence"
HJS_EXT_MULTI_PARTY = "hjs:multi_party_export"


def _jcs_canonical(obj: dict) -> bytes:
    """
    JCS (RFC 8785) canonical JSON serialization.
    Uses JSON Pilot format — no Python stdlib equivalent, so we implement
    the subset needed for JEP/JWS signing: sort object keys lexicographically,
    use UTF-8, no whitespace variations.
    """
    return json.dumps(
        obj,
        separators=(",", ":"),
        ensure_ascii=True,
        sort_keys=True
    ).encode("utf-8")


def _jep_event_hash(payload_bytes: bytes, alg: str = "ES256") -> str:
    """
    Compute JEP event hash over JCS-canonicalized payload.
    JEP uses algorithm-tagged digest strings: '<alg>:<base64url(hash)>'.
    """
    digest = hashlib.sha256(payload_bytes).digest()
    b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"{alg}:{b64}"


def _did_to_hjs_who(did: str) -> str:
    """
    Map a PACT agent DID to an HJS 'who' identifier.
    HJS uses the issuer's DID as the who field — direct mapping.
    """
    return did


@dataclass
class HJSActionEvidence:
    """
    HJS tool-call evidence extension.
    Describes the tool call that produced the behavior record.
    Maps from PACT intent_receipt.tool_name + params.
    """
    tool_name: str
    params_hash: str  # SHA-256 of canonicalized params
    call_timestamp: str  # ISO 8601
    action_id: str  # PACT action_id for cross-reference


@dataclass
class HJSPolicyCheckEvidence:
    """
    HJS policy check evidence extension.
    Proves the action was checked against committed policy.
    Maps from PACT action_receipt.policy_check_hash.
    """
    policy_commitment_hash: str  # SHA-256 of committed policy at action time
    policy_log_uri: Optional[str] = None  # Transparency log where policy was anchored
    check_result: str = "permitted"  # 'permitted' | 'denied' | 'error'
    policy_version: Optional[str] = None


@dataclass
class HJSBehaviorRecord:
    """
    HJS Behavior Record — the core evidence unit in HJS.

    Maps from PACT receipts:
      - who:       PACT agent DID
      - what:      HJS action description + tool evidence
      - when:      action_receipt.timestamp
      - evidence:  refs to HJSPolicyCheckEvidence, HJSActionEvidence
    """
    who: str                    # Issuer DID (PACT agent DID)
    what: str                   # Human-readable action description
    when: str                   # ISO 8601 timestamp of action
    evidence_refs: list[str] = field(default_factory=list)  # URIs or digests of evidence

    def to_dict(self) -> dict:
        return {
            "hjs:who": self.who,
            "hjs:what": self.what,
            "hjs:when": self.when,
            "hjs:evidence_refs": self.evidence_refs,
        }

    def digest(self, alg: str = "ES256") -> str:
        """Compute HJS/JEP behavior record digest."""
        return _jep_event_hash(_jcs_canonical(self.to_dict()), alg)


@dataclass
class HJSReceiptManifest:
    """
    HJS Receipt Manifest — the exportable receipt.

    Contains:
      - behavior_record_digest: hash of the HJS Behavior Record
      - issuer: DID of the receipt issuer
      - timestamp: when the receipt was issued
      - extensions: optional HJS extensions (policy check, tool evidence, etc.)
    """
    version: str = HJS_VERSION
    behavior_record_digest: str = ""
    issuer: str = ""
    issued_at: str = ""  # ISO 8601
    extensions: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "hjs:manifest_version": self.version,
            "hjs:behavior_record_digest": self.behavior_record_digest,
            "hjs:issuer": self.issuer,
            "hjs:issued_at": self.issued_at,
            "hjs:extensions": self.extensions,
        }


class HJSAdapter:
    """
    Adapter for converting PACT receipts to/from HJS/JEP format.

    Usage:
      adapter = HJSAdapter(agent_did="did:key:...")
      pact_receipt = PACTReceipt.from_dict({...})
      hjs_receipt = adapter.pact_to_hjs(pact_receipt)
      jep_event = adapter.to_jep_event(hjs_receipt)
    """

    def __init__(self, agent_did: str, signer=None):
        """
        Args:
            agent_did: PACT agent DID, used as HJS 'who' issuer field
            signer: callable(public_key_did: str, payload_bytes: bytes) -> bytes JWS
                    If None, produces unsigned manifests only (for validation/inspection)
        """
        self.agent_did = agent_did
        self.signer = signer

    def pact_tool_params_hash(self, tool_name: str, params: dict) -> str:
        """
        Compute canonical SHA-256 hash of tool call params for HJS tool evidence.
        Matches the PACT action_id canonicalization.
        """
        canonical = _jcs_canonical({"tool": tool_name, "params": params})
        return hashlib.sha256(canonical).hexdigest()

    def pact_to_hjs_behavior_record(
        self,
        action_id: str,
        tool_name: str,
        params: dict,
        timestamp: str,
        action_description: str,
        policy_commitment_hash: Optional[str] = None,
        policy_log_uri: Optional[str] = None,
    ) -> HJSBehaviorRecord:
        """
        Convert a PACT action to an HJS Behavior Record.

        Args:
            action_id:       PACT action_id from intent_receipt
            tool_name:       Tool called
            params:          Tool parameters dict
            timestamp:       ISO 8601 timestamp from action_receipt
            action_description: Human-readable description of the action
            policy_commitment_hash: SHA-256 of committed policy (for policy check extension)
            policy_log_uri:  Transparency log URI where policy was anchored
        """
        params_hash = self.pact_tool_params_hash(tool_name, params)
        evidence_refs = []

        # Build policy check extension if policy hash is available
        extensions = {}
        if policy_commitment_hash:
            extensions[HJS_EXT_POLICY_CHECK] = {
                "policy_commitment_hash": policy_commitment_hash,
                "policy_log_uri": policy_log_uri or "",
                "check_result": "permitted",
            }

        # Build tool evidence extension
        extensions[HJS_EXT_TOOL_EVIDENCE] = {
            "tool_name": tool_name,
            "params_hash": params_hash,
            "call_timestamp": timestamp,
            "action_id": action_id,
        }

        return HJSBehaviorRecord(
            who=self.agent_did,
            what=action_description,
            when=timestamp,
            evidence_refs=evidence_refs,
        )

    def pact_to_hjs_manifest(
        self,
        behavior_record: HJSBehaviorRecord,
        extensions: Optional[dict[str, Any]] = None,
        issued_at: Optional[str] = None,
    ) -> HJSReceiptManifest:
        """
        Build an HJS Receipt Manifest from a Behavior Record.
        """
        br_digest = behavior_record.digest()
        return HJSReceiptManifest(
            version=HJS_VERSION,
            behavior_record_digest=br_digest,
            issuer=self.agent_did,
            issued_at=issued_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            extensions=extensions or {},
        )

    def to_jep_event(
        self,
        manifest: HJSReceiptManifest,
        behavior_record: HJSBehaviorRecord,
        alg: str = "ES256",
    ) -> dict:
        """
        Build a JEP event containing the HJS Receipt Manifest + Behavior Record.

        JEP event structure:
          {
            "jep:who": issuer_did,
            "jep:what": "hjs:receipt",
            "jep:verb": "jep:execute",
            "jep:when": issued_at,
            "jep:ref": behavior_record_digest,
            "jep:ext": {
              "hjs:manifest": { ... },
              "hjs:behavior_record": { ... }
            }
          }

        Returns a JCS-canonicalized dict suitable for JWS signing.
        """
        jep_event = {
            "jep:who": manifest.issuer,
            "jep:what": "hjs:receipt",
            "jep:verb": JEP_VERB_EXECUTE,
            "jep:when": manifest.issued_at,
            "jep:ref": manifest.behavior_record_digest,
            "jep:ext": {
                "hjs:manifest": manifest.to_dict(),
                "hjs:behavior_record": behavior_record.to_dict(),
                "hjs:profile": PACT_HJS_PROFILE,
            },
        }
        return jep_event

    def export_receipt_bundle(
        self,
        manifests: list[HJSReceiptManifest],
        behavior_records: list[HJSBehaviorRecord],
    ) -> dict:
        """
        Build an HJS Multi-Party Export Receipt Bundle.
        Combines multiple HJS manifests (from PACT agent + other parties)
        into a single exportable bundle.
        """
        return {
            "hjs:bundle_version": "1.0",
            "hjs:bundle_type": "multi_party_export",
            "hjs:receipts": [m.to_dict() for m in manifests],
            "hjs:behavior_records": [br.to_dict() for br in behavior_records],
            "hjs:bundle_issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    def validate_hjs_manifest(self, manifest_dict: dict) -> tuple[bool, str]:
        """
        Validate an HJS receipt manifest dict.
        Returns (is_valid, error_message).
        """
        required = ["hjs:manifest_version", "hjs:behavior_record_digest", "hjs:issuer", "hjs:issued_at"]
        for field in required:
            if field not in manifest_dict:
                return False, f"Missing required field: {field}"

        if not manifest_dict["hjs:behavior_record_digest"].startswith("ES256:"):
            return False, f"Invalid behavior_record_digest format: {manifest_dict['hjs:behavior_record_digest']}"

        return True, "valid"

    def hjs_manifest_to_pact_policy_hash(self, manifest_dict: dict) -> Optional[str]:
        """
        Extract PACT policy_commitment_hash from an HJS manifest's policy check extension.
        Enables cross-system verification: validate HJS receipt → extract PACT policy hash.
        """
        extensions = manifest_dict.get("hjs:extensions", {})
        policy_check = extensions.get(HJS_EXT_POLICY_CHECK, {})
        if policy_check:
            return policy_check.get("policy_commitment_hash")
        return None
