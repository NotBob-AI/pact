"""
PACT — Policy Attestation via Cryptographic Trace
Python implementation of the v0.1 receipt layer.
"""

import json
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional

def create_policy(agent_id: str, allowed_tools: list, denied_tools: list) -> dict:
    """Create a policy document and compute its hash."""
    policy_doc = {
        "policy_version": "0.1.0",
        "agent_id": agent_id,
        "created": datetime.now(timezone.utc).isoformat(),
        "policy": {
            "allowed_tools": allowed_tools,
            "denied_tools": denied_tools,
        }
    }
    policy_str = json.dumps(policy_doc, sort_keys=True)
    policy_hash = "sha256:" + hashlib.sha256(policy_str.encode()).hexdigest()
    policy_doc["policy_hash"] = policy_hash
    return policy_doc


def generate_receipt(policy: dict, tool_name: str, params: dict) -> tuple[dict, bool, str]:
    """Generate a PACT receipt for a tool call."""
    allowed = policy["policy"]["allowed_tools"]
    denied = policy["policy"]["denied_tools"]
    
    if tool_name in denied:
        outcome = False
        reason = f"tool '{tool_name}' is explicitly denied"
    elif tool_name in allowed:
        outcome = True
        reason = f"tool '{tool_name}' is permitted"
    else:
        outcome = False
        reason = f"tool '{tool_name}' not in allowed list"
    
    params_hash = "sha256:" + hashlib.sha256(
        json.dumps(params, sort_keys=True).encode()
    ).hexdigest()
    
    receipt = {
        "receipt_version": "0.1.0",
        "agent_id": policy["agent_id"],
        "policy_hash": policy["policy_hash"],
        "action_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_called": tool_name,
        "params_hash": params_hash,
        "outcome": "permitted" if outcome else "denied",
        "outcome_reason": reason,
        "proof": {
            "type": "sha256_membership",
            "statement": f"tool_called={'in' if outcome else 'not in'} policy.allowed_tools",
            "policy_hash": policy["policy_hash"],
            "proof_hash": "sha256:" + hashlib.sha256(
                f"{policy['policy_hash']}:{tool_name}:{outcome}".encode()
            ).hexdigest(),
        },
    }
    return receipt, outcome, reason


def verify_receipt(receipt: dict, policy: dict) -> dict:
    """Verify a PACT receipt against a committed policy."""
    if receipt["policy_hash"] != policy["policy_hash"]:
        return {"valid": False, "reason": "policy hash mismatch"}
    if receipt["agent_id"] != policy["agent_id"]:
        return {"valid": False, "reason": "agent ID mismatch"}
    
    outcome = receipt["outcome"]
    tool = receipt["tool_called"]
    
    if outcome == "permitted":
        if tool not in policy["policy"]["allowed_tools"]:
            return {"valid": False, "reason": f"tool {tool} not in allowed list"}
    else:
        if tool not in policy["policy"]["denied_tools"]:
            return {"valid": False, "reason": f"tool {tool} not in denied list"}
    
    return {"valid": True, "reason": "receipt valid"}
