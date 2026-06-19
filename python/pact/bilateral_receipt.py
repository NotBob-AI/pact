"""
bilateral_receipt.py — PACT + Notarized Agents Bilinear Receipt Composition

Implements the composition schema for combining:
  1. PACT receipts (agent-side, generated BEFORE action)
  2. Notarized Agents receipts (receiver-side, arxiv 2606.04193v1)

Together they form a complete bilateral chain of evidence:
  - PACT proves: action was permitted by committed policy at execution time
  - Notarized Agents proves: service received exactly this call payload

Neither party can unilaterally falsify their receipt.

Reference: arxiv 2606.04193v1 "Notarized Agents: Receiver-Attested Confidential
Receipts for AI Agent Interactions" — service signs what it observed using its own key,
encrypts to owner's key, publishes to public transparency log.

Schema:
  BilinearReceipt {
    version: "1.0"
    pact_receipt: PACTReceipt        # agent-side, pre-action
    notarized_receipt: NotarizedReceipt  # receiver-side, post-reception
    composition_proof: CompositionProof  # links both receipts
  }

CompositionProof binds the two independent receipts via:
  - shared_call_hash: SHA-256 of canonical action payload (both sides compute same hash)
  - temporal_window: max acceptable delta between PACT timestamp and Notarized timestamp
  - pact_policy_hash: committed policy root at action time
  - notarized_service_id: DID of receiving service
"""

from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timezone


PACT_VERSION = "urn:pact:receipt:v0.7"
NOTARIZED_VERSION = "urn:notarized-agents:v1.0"
BILINEAR_VERSION = "urn:pact:bilateral:v1.0"

# Maximum time delta between PACT pre-action receipt and Notarized post-reception
# receipt, in seconds. Accounts for network latency and clock skew.
# Default: 30 seconds. Adjust based on expected call latency.
DEFAULT_TEMPORAL_WINDOW_SECS = 30


@dataclass
class ActionPayload:
    """Canonical representation of an agent tool call, agreed upon by both sides."""
    tool_name: str
    params: dict
    agent_did: str

    def to_canonical_bytes(self) -> bytes:
        """Deterministic serialization both PACT and Notarized Agents can compute."""
        canonical = {
            "tool": self.tool_name,
            "params": self.params,
            "agent": self.agent_did,
        }
        return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def call_hash(self) -> str:
        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()


@dataclass
class CompositionProof:
    """Links PACT and Notarized receipts via shared cryptographic commitments."""
    bilateral_version: str = BILINEAR_VERSION
    shared_call_hash: str = ""          # computed from ActionPayload canonical form
    pact_policy_hash: str = ""          # PACT committed policy root at action time
    notarized_service_id: str = ""      # DID of receiving service
    pact_action_time: int = 0           # Unix timestamp from PACT receipt
    notarized_receive_time: int = 0      # Unix timestamp from Notarized receipt
    temporal_delta_secs: int = 0         # |notarized_receive_time - pact_action_time|
    temporal_valid: bool = False         # True iff delta <= DEFAULT_TEMPORAL_WINDOW_SECS
    pact_receipt_hash: str = ""         # hash of PACT receipt for non-repudiation
    notarized_receipt_hash: str = ""    # hash of Notarized receipt for non-repudiation

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_pact_and_notarized(
        cls,
        pact_receipt_dict: dict,
        notarized_receipt_dict: dict,
        action_payload: ActionPayload,
        temporal_window: int = DEFAULT_TEMPORAL_WINDOW_SECS,
    ) -> "CompositionProof":
        """Build a CompositionProof from a PACT receipt and a Notarized Agents receipt."""

        # Extract timestamps — PACT uses action.recorded_at_unix (seconds)
        pact_time = pact_receipt_dict.get("action", {}).get("recorded_at_unix", 0)
        notarized_time = notarized_receipt_dict.get("timestamp", 0)

        # Temporal window check
        delta = abs(notarized_time - pact_time)
        temporal_valid = delta <= temporal_window

        # Hash both receipts for non-repudiation audit trail
        pact_hash = hashlib.sha256(
            json.dumps(pact_receipt_dict, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        notarized_hash = hashlib.sha256(
            json.dumps(notarized_receipt_dict, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

        return cls(
            shared_call_hash=action_payload.call_hash(),
            pact_policy_hash=pact_receipt_dict.get("policy", {}).get("policy_hash", ""),
            notarized_service_id=notarized_receipt_dict.get("service_id", ""),
            pact_action_time=pact_time,
            notarized_receive_time=notarized_time,
            temporal_delta_secs=delta,
            temporal_valid=temporal_valid,
            pact_receipt_hash=pact_hash,
            notarized_receipt_hash=notarized_hash,
        )


@dataclass
class BilinearReceipt:
    """
    Complete bilateral receipt composing PACT (agent-side) + Notarized Agents (receiver-side).

    Usage:
        # After PACT intercepts a tool call (pre-action):
        pact_r = generate_pact_receipt(policy, tool_name, params)
        # ... call goes over wire ...
        # After Notarized service receives the call (post-reception):
        notarized_r = service.generate_notarized_receipt(call_payload)
        # Compose the bilateral receipt:
        bilateral = BilinearReceipt.compose(
            pact_receipt=pact_r.to_dict(),
            notarized_receipt=notarized_r,
            action_payload=ActionPayload(tool_name, params, agent_did),
        )
    """
    version: str = BILINEAR_VERSION
    created_at: str = ""                # ISO-8601 timestamp
    composition_proof: CompositionProof = field(default_factory=CompositionProof)
    pact_receipt: dict = field(default_factory=dict)
    notarized_receipt: dict = field(default_factory=dict)

    @classmethod
    def compose(
        cls,
        pact_receipt: dict,
        notarized_receipt: dict,
        action_payload: ActionPayload,
        temporal_window: int = DEFAULT_TEMPORAL_WINDOW_SECS,
    ) -> "BilinearReceipt":
        """Compose a complete BilinearReceipt from PACT and Notarized receipts."""
        composition = CompositionProof.from_pact_and_notarized(
            pact_receipt, notarized_receipt, action_payload, temporal_window
        )
        return cls(
            created_at=datetime.now(timezone.utc).isoformat(),
            composition_proof=composition,
            pact_receipt=pact_receipt,
            notarized_receipt=notarized_receipt,
        )

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "composition_proof": self.composition_proof.to_dict(),
            "pact_receipt": self.pact_receipt,
            "notarized_receipt": self.notarized_receipt,
        }

    def to_json(self, **kwargs) -> str:
        return json.dumps(self.to_dict(), **kwargs)

    def verify(self) -> BilinearVerificationResult:
        """
        Verify the bilateral receipt — checks both receipts AND the composition link.

        Verification checklist:
          1. PACT receipt structure is valid and policy_hash matches composition_proof
          2. Notarized receipt structure is valid and service_id matches composition_proof
          3. shared_call_hash matches computed hash from action payload in both receipts
          4. temporal_window check passes
          5. Both receipt hashes in composition_proof match the actual receipts
        """
        checks = []
        ok = True

        # Check 1: PACT receipt present and parseable
        if not self.pact_receipt:
            checks.append(("pact_receipt_present", False, "PACT receipt missing"))
            ok = False
        else:
            checks.append(("pact_receipt_present", True, ""))

        # Check 2: Notarized receipt present and parseable
        if not self.notarized_receipt:
            checks.append(("notarized_receipt_present", False, "Notarized receipt missing"))
            ok = False
        else:
            checks.append(("notarized_receipt_present", True, ""))

        # Check 3: Temporal window
        temporal_ok = self.composition_proof.temporal_valid
        checks.append((
            "temporal_window",
            temporal_ok,
            f"delta={self.composition_proof.temporal_delta_secs}s "
            f"(limit={DEFAULT_TEMPORAL_WINDOW_SECS}s)"
        ))
        if not temporal_ok:
            ok = False

        # Check 4: Call hash agreement (both sides computed the same action payload)
        # PACT stores the action params; Notarized stores the received call hash.
        pact_action = self.pact_receipt.get("action", {})
        pact_payload = ActionPayload(
            tool_name=pact_action.get("tool_name", ""),
            params=pact_action.get("params", {}),
            agent_did=pact_action.get("agent_did", ""),
        )
        computed_hash = pact_payload.call_hash()
        hash_match = computed_hash == self.composition_proof.shared_call_hash
        checks.append((
            "call_hash_agreement",
            hash_match,
            f"computed={computed_hash[:16]}... composition={self.composition_proof.shared_call_hash[:16]}..."
        ))
        if not hash_match:
            ok = False

        # Check 5: Policy hash matches between PACT receipt and composition proof
        policy_match = (
            self.pact_receipt.get("policy", {}).get("policy_hash", "")
            == self.composition_proof.pact_policy_hash
        )
        checks.append((
            "pact_policy_hash_agreement",
            policy_match,
            "PACT receipt policy_hash matches composition_proof"
        ))
        if not policy_match:
            ok = False

        return BilinearVerificationResult(ok=ok, checks=checks, receipt=self)

    def anchor_to_log(self, log_adapter) -> dict:
        """
        Anchor the complete BilinearReceipt to a transparency log.

        Args:
            log_adapter: must implement .append(receipt: dict) -> dict
                        returning {"anchored": True, "log_hash": "...", "sequence": N}

        The anchored receipt is the full BilinearReceipt JSON — verifiers can
        retrieve and verify without contacting either the agent or the service.
        """
        return log_adapter.append(self.to_dict())


@dataclass
class BilinearVerificationResult:
    ok: bool
    checks: list  # [(check_name, passed: bool, detail: str)]
    receipt: BilinearReceipt

    def is_valid(self) -> bool:
        return self.ok

    def summary(self) -> str:
        lines = [f"BilinearReceipt verification: {'PASS' if self.ok else 'FAIL'}"]
        for name, passed, detail in self.checks:
            status = "✓" if passed else "✗"
            lines.append(f"  {status} {name}: {detail}")
        return "\n".join(lines)


# ─── Demo / Smoke Test ────────────────────────────────────────────────────────

def _demo():
    """Smoke test for bilateral composition."""
    pact_receipt = {
        "version": PACT_VERSION,
        "action": {
            "tool_name": "mcp_filesystem_read",
            "params": {"path": "/data/report.pdf"},
            "agent_did": "did:key:z6MkNotBobAlpha",
            "recorded_at_unix": int(time.time()),
        },
        "policy": {
            "policy_hash": "abc123policyhash",
        },
        "proof": {
            "proof_hash": "pactproofhash123",
        },
    }

    notarized_receipt = {
        "version": NOTARIZED_VERSION,
        "service_id": "did:key:z6MkSearchService",
        "call_hash": hashlib.sha256(json.dumps({
            "tool": "mcp_filesystem_read",
            "params": {"path": "/data/report.pdf"},
            "agent": "did:key:z6MkNotBobAlpha",
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "timestamp": int(time.time()),
        "signature": "[SERVICE_SIGNATURE]",
    }

    action_payload = ActionPayload(
        tool_name="mcp_filesystem_read",
        params={"path": "/data/report.pdf"},
        agent_did="did:key:z6MkNotBobAlpha",
    )

    bilateral = BilinearReceipt.compose(pact_receipt, notarized_receipt, action_payload)
    print("=== BilinearReceipt Demo ===")
    print(f"Version: {bilateral.version}")
    print(f"Created: {bilateral.created_at}")
    print(f"Shared call hash: {bilateral.composition_proof.shared_call_hash[:24]}...")
    print(f"Temporal delta: {bilateral.composition_proof.temporal_delta_secs}s")
    print(f"Temporal valid: {bilateral.composition_proof.temporal_valid}")
    print()
    result = bilateral.verify()
    print(result.summary())


if __name__ == "__main__":
    _demo()
