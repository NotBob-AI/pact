"""
PACT v0.7 — Receipt Generator
Bridges PolicySpec (v0.6) → Receipt (v0.3) → Commitment (v0.2).
The missing integration layer between policy authoring and cryptographic receipt.

Usage:
    gen = ReceiptGenerator(agent_id="notbob", principal_did="did:web:notbob.ai")
    receipt, outcome = gen.generate_receipt("web_search", {"query": "test"})
    anchored = gen.anchor_receipt(receipt, transparency_log)
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from .policy_spec import PolicySpec, create_policy_spec
from .receipt import (
    PACTReceipt, PolicyCommitment, ToolCall, ZKProof,
    PACT_RECEIPT_VERSION,
)
from .commitment import TransparencyLog, anchor_policy


# ---------------------------------------------------------------------------
# Outcome
# ---------------------------------------------------------------------------

class ToolOutcome:
    """Result of a tool call authorization check."""
    PERMITTED = "permitted"
    DENIED = "denied"
    UNKNOWN = "unknown"  # tool not in allowed or denied list


# ---------------------------------------------------------------------------
# Receipt Generator
# ---------------------------------------------------------------------------

class ReceiptGenerator:
    """
    Generates PACT receipts from PolicySpec + tool call.
    
    Integrates:
      - PolicySpec (v0.6): policy definition and tool permission check
      - ToolCall (v0.3): tool invocation record  
      - ZKProof (v0.3): proof of membership (DUMMY for now)
      - PolicyCommitment (v0.2): anchored to transparency log
    """
    
    def __init__(
        self,
        agent_id: str,
        principal_did: str,
        transparency_log: Optional[TransparencyLog] = None,
    ):
        self.agent_id = agent_id
        self.principal_did = principal_did
        self._policy_specs: dict[str, PolicySpec] = {}
        self._committed_policies: dict[str, dict] = {}  # policy_hash → committed entry
        self.transparency_log = transparency_log or TransparencyLog()
    
    def register_policy(
        self,
        allowed_tools: list[str],
        denied_tools: list[str],
        constraints: Optional[dict] = None,
        prior_policy_hash: Optional[str] = None,
    ) -> PolicySpec:
        """
        Create and register a new policy spec.
        Returns the PolicySpec. Call anchor_policy() separately to commit it.
        """
        spec = create_policy_spec(
            agent_id=self.agent_id,
            principal_did=self.principal_did,
            allowed_tools=allowed_tools,
            denied_tools=denied_tools,
            constraints=constraints,
            prior_policy_hash=prior_policy_hash,
        )
        self._policy_specs[spec.compute_hash()] = spec
        return spec
    
    def anchor_policy(self, spec: PolicySpec) -> dict:
        """
        Anchor a PolicySpec to the transparency log.
        Returns the committed policy entry with log_index, log_id, merkle_root.
        """
        policy_hash = spec.compute_hash()
        # anchor_policy returns {anchor, entry} — extract both
        result = anchor_policy(
            policy=spec.to_dict(),
            log=self.transparency_log,
        )
        anchor = result["anchor"]
        entry = result["entry"]
        # Store with full anchor info for receipt generation
        self._committed_policies[policy_hash] = anchor
        return anchor
    
    def _get_active_policy_hash(self) -> str:
        """Get the most recently committed policy hash."""
        if not self._committed_policies:
            raise RuntimeError("No policy committed. Call anchor_policy() first.")
        # Return the most recent entry (highest log_index)
        latest = max(self._committed_policies.values(), key=lambda e: e.get("log_index", 0))
        return latest["policy_hash"]
    
    def check_tool(self, tool_name: str, policy_hash: Optional[str] = None) -> Tuple[str, Optional[str]]:
        """
        Check if a tool is permitted under the active or specified policy.
        
        Returns: (outcome: str, reason: Optional[str])
          - (PERMITTED, None) if allowed
          - (DENIED, reason) if denied
          - (UNKNOWN, "tool not in policy") if not found in allowed or denied
        """
        ph = policy_hash or self._get_active_policy_hash()
        spec = self._policy_specs.get(ph)
        if not spec:
            raise RuntimeError(f"Policy {ph[:20]}... not found in local registry.")
        
        result = spec.tool_is_permitted(tool_name)
        if result is True:
            return ToolOutcome.PERMITTED, None
        elif result is False:
            return ToolOutcome.DENIED, f"tool '{tool_name}' is explicitly denied"
        else:
            return ToolOutcome.UNKNOWN, f"tool '{tool_name}' not in allowed or denied list"
    
    def generate_receipt(
        self,
        tool_name: str,
        tool_params: dict,
        policy_hash: Optional[str] = None,
        include_output: bool = False,
        tool_output: Optional[str] = None,
    ) -> Tuple[PACTReceipt, str]:
        """
        Generate a PACT receipt for a tool call.
        
        Args:
            tool_name: Name of the tool being called
            tool_params: Parameters passed to the tool
            policy_hash: Policy to use (default: active policy)
            include_output: Whether to include output hash in receipt
            tool_output: Raw output string (required if include_output=True)
        
        Returns: (receipt: PACTReceipt, outcome: str)
        
        Raises:
            RuntimeError: If no policy is committed
        """
        ph = policy_hash or self._get_active_policy_hash()
        committed = self._committed_policies.get(ph)
        if not committed:
            raise RuntimeError(f"Policy {ph[:20]}... not committed. Call anchor_policy() first.")
        
        # Check tool permission
        outcome, reason = self.check_tool(tool_name, ph)
        
        # Build ToolCall record
        params_json = json.dumps(tool_params, sort_keys=True)
        params_hash = "sha256:" + hashlib.sha256(params_json.encode()).hexdigest()
        
        tool_call = ToolCall(
            tool_name=tool_name,
            tool_input_hash=params_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            action_id=str(uuid.uuid4()),
            tool_output_hash=(
                "sha256:" + hashlib.sha256(tool_output.encode()).hexdigest()
                if include_output and tool_output
                else None
            ),
        )
        
        # Build PolicyCommitment (Layer 1)
        policy_commitment = PolicyCommitment(
            policy_hash=ph,
            log_index=committed["log_index"],
            log_id=committed["log_id"],
            merkle_root=committed["merkle_root"],
            merkle_proof=committed.get("merkle_proof", []),
        )
        
        # Build ZKProof (DUMMY for v0.7 — real proof wired in v0.3)
        tool_name_hash = "sha256:" + hashlib.sha256(tool_name.encode()).hexdigest()
        zk_proof = ZKProof(
            proof_type="DUMMY_ZK_PROOF",
            image_id="pact-v0.7-dummy",
            seal="DUMMY_PROOF",
            public_inputs={
                "policy_hash": ph,
                "merkle_root": committed["merkle_root"],
                "log_index": committed["log_index"],
                "tool_name_hash": tool_name_hash,
                "timestamp": tool_call.timestamp,
            },
        )
        # Pass as 'proof' to match dataclass field name
        proof_arg = zk_proof
        
        # Assemble receipt — use factory function to match actual schema
        from .receipt import create_receipt
        receipt = create_receipt(
            policy_commitment=policy_commitment,
            tool_call=tool_call,
            proof=zk_proof,
        )
        # Attach outcome fields (stored alongside receipt, not in dataclass)
        receipt.outcome = outcome  # type: ignore
        receipt.outcome_reason = reason  # type: ignore
        
        return receipt, outcome
    
    def receipt_to_dict(self, receipt: PACTReceipt) -> dict:
        """Serialize a PACTReceipt to a dict for JSON encoding."""
        from .receipt import receipt_to_dict as _receipt_to_dict
        d = _receipt_to_dict(receipt)
        # Add outcome fields if present
        if hasattr(receipt, 'outcome'):
            d['outcome'] = receipt.outcome
        if hasattr(receipt, 'outcome_reason'):
            d['outcome_reason'] = receipt.outcome_reason
        return d


# ---------------------------------------------------------------------------
# Smoke Test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Create generator
    gen = ReceiptGenerator(
        agent_id="notbob",
        principal_did="did:web:notbob.ai",
    )
    
    # Register + anchor policy
    spec = gen.register_policy(
        allowed_tools=["web_search", "web_fetch", "memory_search", "exec"],
        denied_tools=["delete", "rm", "system"],
        constraints={"max_calls_per_hour": 100},
    )
    committed = gen.anchor_policy(spec)
    print(f"Policy committed at log_index={committed['log_index']}")
    print(f"Policy hash: {spec.compute_hash()[:40]}...")
    
    # Generate permitted receipt
    receipt, outcome = gen.generate_receipt(
        tool_name="web_search",
        tool_params={"query": "critical minerals 2026"},
    )
    print(f"\nPermitted call receipt:")
    print(f"  outcome={outcome}")
    print(f"  action_id={receipt.tool_call.action_id[:8]}...")
    print(f"  log_index={receipt.policy_commitment.log_index}")
    
    # Generate denied receipt
    receipt2, outcome2 = gen.generate_receipt(
        tool_name="delete",
        tool_params={"path": "/etc/passwd"},
    )
    print(f"\nDenied call receipt:")
    print(f"  outcome={outcome2}")
    print(f"  reason={receipt2.outcome_reason}")
    
    # Serialize
    print(f"\nSerialized receipt keys: {list(gen.receipt_to_dict(receipt).keys())}")
    print("All tests passed.")
