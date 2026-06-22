#!/usr/bin/env python3
import sys
sys.path.insert(0, ".")
from python.pact.drp_adapter import DrpAuthorizationAdapter, MockLogClient

def test_drp():
    mock_log = MockLogClient()
    drp = {
        "type": "drp:authorization",
        "authorization_id": "auth-test-001",
        "authorizing_user_did": "did:user:test",
        "operator_did": "did:operator:test",
        "scope": ["tool_a", "tool_b"],
        "time_window": {"start": "2026-01-01T00:00:00Z", "end": "2027-01-01T00:00:00Z"},
        "model_state_hash": "sha256:abc",
        "instruction_hash": "sha256:def",
        "resource_constraints": {},
    }
    uri = mock_log.append(drp)
    adapter = DrpAuthorizationAdapter(mock_log, "did:operator:test")
    adapter.ingest_from_log(uri)
    policy = adapter.to_pact_policy()
    assert policy["policy_version"] == "0.8.0-drp"
    assert "tool_a" in policy["policy"]["allowed_tools"]
    assert "sha256:" in policy["policy_hash"]
    print("Test 1 PASS: DRP -> PACT policy derivation")

def test_enforce():
    mock_log = MockLogClient()
    drp = {
        "type": "drp:authorization",
        "authorization_id": "auth-test-002",
        "authorizing_user_did": "did:user:test",
        "operator_did": "did:operator:test",
        "scope": ["read_email"],
        "time_window": {"start": "2026-01-01T00:00:00Z", "end": "2027-01-01T00:00:00Z"},
        "model_state_hash": "sha256:abc",
        "instruction_hash": "sha256:def",
        "resource_constraints": {},
    }
    adapter = DrpAuthorizationAdapter(mock_log, "did:operator:test")
    adapter.ingest_from_dict(drp)
    allowed, _ = adapter.enforce("read_email")
    denied, reason = adapter.enforce("delete_all")
    assert allowed == True
    assert denied == False
    print("Test 2 PASS: enforce() gates tool calls correctly")

test_drp()
test_enforce()
print("All DRP Adapter tests PASS")
