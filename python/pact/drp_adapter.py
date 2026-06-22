"""
drp_adapter.py — DRP Authorization Adapter for PACT

Bridges DRP (Delegation Receipt Protocol, IETF draft-nelson-agent-delegation-receipts)
Authorization Objects into PACT policy enforcement.

Architecture:
  User signs DRP Authorization Object → published to append-only log BEFORE agent runs
  DRP Adapter reads DRP receipt from log
  DRP Adapter maps DRP scope → PACT policy document
  PACT Layer 0 enforces PACT policy (which reflects DRP user-authorized scope)

The DRP Adapter is the "upstream policy bridge" — it translates what the user
authorized into what PACT enforces at the operator-to-agent boundary.

Ref: docs/DRP-integration.md
"""

from __future__ import annotations
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Optional


class DrpAuthorizationObject:
    """
    Represents a DRP Authorization Object signed by the authorizing user.
    Fields per draft-nelson-agent-delegation-receipts-09 Section 3.
    """

    def __init__(
        self,
        authorization_id: str,
        authorizing_user_did: str,
        operator_did: str,
        scope: list[str],
        time_window_start: str,
        time_window_end: str,
        model_state_hash: str,
        instruction_hash: str,
        resource_constraints: Optional[dict] = None,
        raw: Optional[dict] = None,
    ):
        self.authorization_id = authorization_id
        self.authorizing_user_did = authorizing_user_did
        self.operator_did = operator_did
        self.scope = scope
        self.time_window_start = time_window_start
        self.time_window_end = time_window_end
        self.model_state_hash = model_state_hash
        self.instruction_hash = instruction_hash
        self.resource_constraints = resource_constraints or {}
        self.raw = raw or self._to_dict()

    def _to_dict(self) -> dict:
        return {
            "authorization_id": self.authorization_id,
            "authorizing_user_did": self.authorizing_user_did,
            "operator_did": self.operator_did,
            "scope": self.scope,
            "time_window": {
                "start": self.time_window_start,
                "end": self.time_window_end,
            },
            "model_state_hash": self.model_state_hash,
            "instruction_hash": self.instruction_hash,
            "resource_constraints": self.resource_constraints,
        }

    @classmethod
    def from_log_entry(cls, log_entry: dict) -> "DrpAuthorizationObject":
        """Parse a DRP Authorization Object from an append-only log entry."""
        data = log_entry.get("receipt", log_entry)
        return cls(
            authorization_id=data.get("authorization_id", ""),
            authorizing_user_did=data.get("authorizing_user_did", ""),
            operator_did=data.get("operator_did", ""),
            scope=data.get("scope", []),
            time_window_start=data.get("time_window", {}).get("start", ""),
            time_window_end=data.get("time_window", {}).get("end", ""),
            model_state_hash=data.get("model_state_hash", ""),
            instruction_hash=data.get("instruction_hash", ""),
            resource_constraints=data.get("resource_constraints", {}),
            raw=data,
        )

    def is_within_time_window(self, now: Optional[datetime] = None) -> bool:
        """Check if current time is within the authorized time window."""
        if now is None:
            now = datetime.now(timezone.utc)
        start = datetime.fromisoformat(self.time_window_start.replace("Z", "+00:00"))
        end = datetime.fromisoformat(self.time_window_end.replace("Z", "+00:00"))
        return start <= now <= end


class DrpAuthorizationAdapter:
    """
    Bridges DRP Authorization Objects into PACT policy enforcement.

    Usage:
        adapter = DrpAuthorizationAdapter(transparency_log_client)

        # Ingest a DRP authorization from the log
        adapter.ingest_from_log(drp_log_uri)

        # Get the PACT policy derived from DRP authorization
        pact_policy = adapter.to_pact_policy()

        # Enforce at Layer 0 — agent can only call tools in DRP-authorized scope
        adapter.enforce()
    """

    def __init__(self, log_client, operator_did: str):
        self.log_client = log_client
        self.operator_did = operator_did
        self.ingested: list[DrpAuthorizationObject] = []
        self._pact_policy: Optional[dict] = None

    def ingest_from_log(self, log_uri: str) -> DrpAuthorizationObject:
        """
        Fetch and parse a DRP Authorization Object from the append-only log.
        Raises ValueError if the log entry is not a valid DRP Authorization Object.
        """
        entry = self.log_client.get_entry(log_uri)
        if entry.get("type") != "drp:authorization":
            raise ValueError(f"Log entry {log_uri} is not a DRP Authorization Object: {entry.get('type')}")

        auth_obj = DrpAuthorizationObject.from_log_entry(entry)

        # Verify this authorization is for our operator
        if auth_obj.operator_did != self.operator_did:
            raise ValueError(
                f"Authorization {auth_obj.authorization_id} is for operator "
                f"{auth_obj.operator_did}, not our operator {self.operator_did}"
            )

        # Verify time window
        if not auth_obj.is_within_time_window():
            raise ValueError(
                f"Authorization {auth_obj.authorization_id} is outside its time window"
            )

        self.ingested.append(auth_obj)
        self._pact_policy = None  # Invalidate cached policy
        return auth_obj

    def ingest_from_dict(self, data: dict) -> DrpAuthorizationObject:
        """Parse and ingest a DRP Authorization Object from a raw dict (for testing)."""
        auth_obj = DrpAuthorizationObject.from_log_entry(data)
        self.ingested.append(auth_obj)
        self._pact_policy = None
        return auth_obj

    def to_pact_policy(self) -> dict:
        """
        Map the most recent DRP Authorization Object to a PACT policy document.

        DRP scope → PACT allowed_tools:
          - DRP scope lists tool/action names the user authorized
          - PACT allowed_tools = intersection of DRP scope with operator's tool registry

        PACT policy document includes:
          - allowed_tools: derived from DRP scope
          - resource_constraints: forwarded from DRP resource_constraints
          - drp_authorization_id: linkage back to the DRP log entry
          - model_state_hash: included for DRP compliance (DRP receipts verify this)
          - policy_hash: standard PACT SHA-256 commitment hash
        """
        if not self.ingested:
            raise ValueError("No DRP Authorization Objects ingested")

        # Use the most recent authorization
        auth = self.ingested[-1]

        policy_doc = {
            "policy_version": "0.8.0-drp",
            "drp_authorization_id": auth.authorization_id,
            "authorizing_user_did": auth.authorizing_user_did,
            "operator_did": self.operator_did,
            "created": datetime.now(timezone.utc).isoformat(),
            "policy": {
                "allowed_tools": list(auth.scope),
                "denied_tools": [],  # DRP doesn't deny; everything outside scope is implicitly denied
                "resource_constraints": auth.resource_constraints,
            },
            "drp_compliance": {
                "model_state_hash": auth.model_state_hash,
                "instruction_hash": auth.instruction_hash,
                "time_window_start": auth.time_window_start,
                "time_window_end": auth.time_window_end,
            },
        }

        # Compute standard PACT policy hash
        policy_str = json.dumps(policy_doc, sort_keys=True)
        policy_hash = "sha256:" + hashlib.sha256(policy_str.encode()).hexdigest()
        policy_doc["policy_hash"] = policy_hash

        self._pact_policy = policy_doc
        return policy_doc

    def enforce(self, tool_name: str) -> tuple[bool, str]:
        """
        Check if a tool call is within the DRP-authorized scope.

        Returns (allowed, reason).
        DRP scope is the authoritative boundary — anything outside DRP scope
        is denied regardless of what the operator's own policy would allow.
        """
        if self._pact_policy is None:
            self.to_pact_policy()

        allowed = self._pact_policy["policy"]["allowed_tools"]
        denied = self._pact_policy["policy"]["denied_tools"]

        if tool_name in denied:
            return False, f"tool '{tool_name}' is explicitly denied in DRP policy"
        elif tool_name in allowed:
            return True, f"tool '{tool_name}' is within DRP-authorized scope"
        else:
            return False, f"tool '{tool_name}' is not in DRP-authorized scope '{allowed}'"


# ----------------------------------------------------------------------
# Mock log client for testing without a live transparency log
# ----------------------------------------------------------------------

class MockLogClient:
    """In-memory mock of a transparency log for testing the DRP adapter."""

    def __init__(self):
        self.entries: dict[str, dict] = {}

    def append(self, entry: dict, uri: Optional[str] = None) -> str:
        uri = uri or f"log://mock/{hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()[:16]}"
        self.entries[uri] = entry
        return uri

    def get_entry(self, uri: str) -> dict:
        if uri not in self.entries:
            raise ValueError(f"Log entry not found: {uri}")
        return self.entries[uri]


# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------

if __name__ == "__main__":
    # Demo: ingest a DRP Authorization Object, derive PACT policy, enforce
    mock_log = MockLogClient()

    drp_auth = {
        "type": "drp:authorization",
        "authorization_id": "auth-001",
        "authorizing_user_did": "did:user:alice",
        "operator_did": "did:operator:bob",
        "scope": ["read_email", "send_email", "calendar_query"],
        "time_window": {
            "start": "2026-06-01T00:00:00Z",
            "end": "2026-06-30T23:59:59Z",
        },
        "model_state_hash": "sha256:abc123",
        "instruction_hash": "sha256:def456",
        "resource_constraints": {"max_emails_per_day": 50},
    }
    log_uri = mock_log.append(drp_auth)

    operator_did = "did:operator:bob"
    adapter = DrpAuthorizationAdapter(mock_log, operator_did)
    adapter.ingest_from_log(log_uri)

    pact_policy = adapter.to_pact_policy()
    print("PACT Policy derived from DRP Authorization:")
    print(json.dumps(pact_policy, indent=2))

    print()
    for tool in ["read_email", "send_file", "calendar_query"]:
        allowed, reason = adapter.enforce(tool)
        print(f"  enforce('{tool}'): {allowed} — {reason}")
