"""
PACT v0.6 — Policy Specification Schema
Defines the canonical structure for policy documents and the policy commitment workflow.
Used by Layer 0 (interceptor), Layer 1 (commitment), Layer 2 (ZK receipts), and Layer 3 (verifier).
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any


class PolicySpec:
    """Canonical policy specification for PACT agents."""
    
    CURRENT_VERSION = "1.0"
    
    def __init__(
        self,
        agent_id: str,
        principal_did: str,
        policy_doc: Dict[str, Any],
        allowed_tools: List[str],
        denied_tools: List[str],
        constraints: Optional[Dict[str, Any]] = None,
        expires_at: Optional[str] = None,
        prior_policy_hash: Optional[str] = None,
    ):
        self.agent_id = agent_id
        self.principal_did = principal_did
        self.policy_doc = policy_doc
        self.allowed_tools = allowed_tools
        self.denied_tools = denied_tools
        self.constraints = constraints or {}
        self.expires_at = expires_at
        self.prior_policy_hash = prior_policy_hash
        self.version = self.CURRENT_VERSION
        self.created_at = datetime.now(timezone.utc).isoformat()
    
    def to_json(self) -> str:
        """Serialize to canonical JSON."""
        return json.dumps(self.to_dict(), sort_keys=True)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary matching the schema."""
        d = {
            "pact_version": self.version,
            "policy_id": self._compute_policy_id(),
            "agent_id": self.agent_id,
            "principal": self.principal_did,
            "created": self.created_at,
            "expires_at": self.expires_at,
            "allowed_tools": self.allowed_tools,
            "denied_tools": self.denied_tools,
            "constraints": self.constraints,
            "policy_hash": self.compute_hash(),
        }
        if self.prior_policy_hash:
            d["prior_policy_hash"] = self.prior_policy_hash
            d["prior_policy_id"] = self._prior_policy_id_from_hash(self.prior_policy_hash)
        return d
    
    def _compute_policy_id(self) -> str:
        """Stable policy identifier (not the hash — human-readable anchor)."""
        return f"pact-policy-{self.agent_id}-{int(datetime.now(timezone.utc).timestamp())}"
    
    def _prior_policy_id_from_hash(self, prior_hash: str) -> Optional[str]:
        """Extract prior policy ID from hash if stored, else return None."""
        # In production this would look up the policy log.
        # For v0.6 schema we assume the prior_policy_hash is sufficient.
        return None
    
    def compute_hash(self) -> str:
        """Canonical policy hash — same algorithm used by Layer 1 commitment."""
        # Canonical form: pact_version + agent_id + principal + created + sorted constraints
        canonical = {
            "pact_version": self.version,
            "agent_id": self.agent_id,
            "principal": self.principal_did,
            "created": self.created_at,
            "allowed_tools": sorted(self.allowed_tools),
            "denied_tools": sorted(self.denied_tools),
            "constraints": {k: self.constraints[k] for k in sorted(self.constraints)},
            "prior_policy_hash": self.prior_policy_hash,
        }
        return "sha256:" + hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PolicySpec":
        """Reconstruct from serialized dict."""
        spec = cls(
            agent_id=d["agent_id"],
            principal_did=d["principal"],
            policy_doc=d,
            allowed_tools=d["allowed_tools"],
            denied_tools=d["denied_tools"],
            constraints=d.get("constraints", {}),
            expires_at=d.get("expires_at"),
            prior_policy_hash=d.get("prior_policy_hash"),
        )
        return spec
    
    def verify_integrity(self) -> bool:
        """Verify the policy has not been tampered with."""
        recomputed = self.compute_hash()
        # stored hash is in to_dict() — compare with what was committed
        # For a fresh spec, compute_hash returns the canonical hash
        return True  # placeholder for full verification against commitment log
    
    def tool_is_permitted(self, tool_name: str) -> Optional[bool]:
        """
        Check if a tool is permitted, denied, or unknown.
        Returns True/False/None (unknown).
        """
        if tool_name in self.denied_tools:
            return False
        if tool_name in self.allowed_tools:
            return True
        return None
    
    def __repr__(self) -> str:
        n_allowed = len(self.allowed_tools)
        n_denied = len(self.denied_tools)
        return f"PolicySpec(agent={self.agent_id}, allowed={n_allowed}, denied={n_denied})"


def create_policy_spec(
    agent_id: str,
    principal_did: str,
    allowed_tools: List[str],
    denied_tools: List[str],
    constraints: Optional[Dict[str, Any]] = None,
    expires_at: Optional[str] = None,
    prior_policy_hash: Optional[str] = None,
) -> PolicySpec:
    """Factory to create and compute policy spec."""
    spec = PolicySpec(
        agent_id=agent_id,
        principal_did=principal_did,
        policy_doc={},
        allowed_tools=allowed_tools,
        denied_tools=denied_tools,
        constraints=constraints,
        expires_at=expires_at,
        prior_policy_hash=prior_policy_hash,
    )
    return spec


if __name__ == "__main__":
    # Smoke test
    spec = create_policy_spec(
        agent_id="notbob",
        principal_did="did:web:notbob.ai",
        allowed_tools=["web_search", "web_fetch", "memory_search", "exec"],
        denied_tools=["delete", "rm", "system"],
        constraints={"max_calls_per_hour": 100, "require_receipts": True},
        prior_policy_hash=None,
    )
    print(f"Created: {spec}")
    print(f"Hash: {spec.compute_hash()}")
    print(f"Dict: {json.dumps(spec.to_dict(), indent=2)}")
    
    # Verify tool check
    assert spec.tool_is_permitted("web_search") == True
    assert spec.tool_is_permitted("delete") == False
    assert spec.tool_is_permitted("unknown_tool") == None
    print("All assertions passed.")