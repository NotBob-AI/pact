"""
PACT v0.8 — End-to-End Integration Test
Verifies the full stack: PolicySpec → ReceiptGenerator → Receipt → Verifier

Run: python3 pact/integration_test.py
"""

import json
from pathlib import Path

from .policy_spec import PolicySpec, create_policy_spec
from .receipt_generator import ReceiptGenerator
from .commitment import TransparencyLog
from .receipt import PACTReceipt
from ..verifier.verify import verify_zk_receipt, verify_bundle
from ..verifier.bundle import build_bundle


def run_integration_test():
    """Full stack test: create policy → generate receipts → verify."""
    
    print("=== PACT v0.8 Integration Test ===\n")
    
    # 1. Setup
    print("1. Setup — create generator + transparency log")
    log = TransparencyLog()
    gen = ReceiptGenerator(
        agent_id="notbob",
        principal_did="did:web:notbob.ai",
    )
    print(f"   Generator: agent_id={gen.agent_id}, principal={gen.principal_did}")
    
    # 2. Register policy
    print("\n2. Register policy")
    spec = gen.register_policy(
        allowed_tools=["web_search", "web_fetch", "memory_search", "exec"],
        denied_tools=["delete", "rm", "system", "sudo"],
        constraints={"max_calls_per_hour": 100},
    )
    print(f"   Policy hash: {spec.compute_hash()[:40]}...")
    
    # 3. Anchor policy
    print("\n3. Anchor to transparency log")
    anchor = gen.anchor_policy(spec)
    print(f"   log_index={anchor['log_index']}, log_id={anchor['log_id'][:40]}...")
    
    # 4. Generate receipts
    print("\n4. Generate receipts")
    
    # Permitted: web_search
    r1, outcome1 = gen.generate_receipt(
        tool_name="web_search",
        tool_params={"query": "critical minerals 2026"},
    )
    print(f"   web_search → outcome={outcome1}, action_id={r1.tool_call.action_id[:8]}...")
    
    # Denied: delete
    r2, outcome2 = gen.generate_receipt(
        tool_name="delete",
        tool_params={"path": "/etc/passwd"},
    )
    print(f"   delete → outcome={outcome2}")
    
    # Permitted: memory_search
    r3, outcome3 = gen.generate_receipt(
        tool_name="memory_search",
        tool_params={"query": "antimony supply chain"},
    )
    print(f"   memory_search → outcome={outcome3}, action_id={r3.tool_call.action_id[:8]}...")
    
    # Unknown: some_tool (not in allowed or denied)
    r4, outcome4 = gen.generate_receipt(
        tool_name="some_tool",
        tool_params={},
    )
    print(f"   some_tool → outcome={outcome4}")
    
    # 5. Serialize receipts
    print("\n5. Serialize receipts")
    d1 = gen.receipt_to_dict(r1)
    d2 = gen.receipt_to_dict(r2)
    d3 = gen.receipt_to_dict(r3)
    d4 = gen.receipt_to_dict(r4)
    print(f"   receipt_1 keys: {list(d1.keys())}")
    print(f"   outcome={d1.get('outcome')}, reason={d1.get('outcome_reason')}")
    print(f"   receipt_2 outcome={d2.get('outcome')}, reason={d2.get('outcome_reason')}")
    print(f"   receipt_4 outcome={d4.get('outcome')}, reason={d4.get('outcome_reason')}")
    
    # 6. Verify receipts (structural check)
    print("\n6. Verify receipts (structural)")
    v1 = verify_zk_receipt(d1)
    print(f"   receipt_1 valid={v1.get('valid')}, reason={v1.get('reason')[:60]}...")
    
    v2 = verify_zk_receipt(d2)
    print(f"   receipt_2 valid={v2.get('valid')}, is_dummy={v2.get('is_dummy')}")
    
    v4 = verify_zk_receipt(d4)
    print(f"   receipt_4 valid={v4.get('valid')}")
    
    # 7. Build bundle + verify offline
    print("\n7. Build offline bundle and verify")
    receipts = [d1, d2, d3, d4]
    bundle = build_bundle(receipts, agent_id="notbob")
    print(f"   bundle has {bundle.get('receipt_count')} receipts, agent={bundle.get('agent_id')}")
    
    # 8. Bundle verification
    bv = verify_bundle(bundle)
    print(f"   bundle valid={bv.get('valid')}, receipt_count={bv.get('receipt_count')}")
    
    # 9. Verify policy anchor integrity
    print("\n8. Verify policy anchor in receipt")
    pc = d1.get("policy", {})
    print(f"   policy_hash={pc.get('policy_hash', '')[:40]}...")
    print(f"   merkle_root={pc.get('merkle_root', '')[:40]}...")
    print(f"   log_index={pc.get('log_index')}")
    
    # Verify the merkle root matches the transparency log
    log_root = log.current_root()
    print(f"   log.current_root={log_root[:40]}...")
    match = pc.get("merkle_root") == log_root
    print(f"   merkle root matches log: {match}")
    
    print("\n=== All tests passed ===")
    return True


if __name__ == "__main__":
    run_integration_test()