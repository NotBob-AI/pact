#!/usr/bin/env python3
"""
PACT v0.3 — Full Workflow Demo

Demonstrates the complete PACT v0.3 receipt lifecycle:
  1. Commit a policy to a mock transparency log
  2. Generate a ZK receipt for a permitted tool call
  3. Verify the receipt

Run:
  python3 pact-workflow-demo.py

No RISC Zero toolchain required — runs in DUMMY_PROOF mode.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "python"))

from pact.zk_receipt_generator import build_zk_receipt, verify_zk_receipt

# ---------------------------------------------------------------------------
# Step 1: Policy and Mock Transparency Log
# ---------------------------------------------------------------------------

AGENT_POLICY = {
    "version": "1.0",
    "agent_id": "notbob-prod-001",
    "policy_hash": "sha256:demo_policy_hash_not_real",
    "committed_at": datetime.now(timezone.utc).isoformat(),
    "policy": {
        "allowed_tools": ["search_web", "read", "browser", "web_fetch"],
        "denied_tools": ["exec", "write"],
        "max_actions_per_session": 100,
        "require_receipts": True,
    },
    "anchor": {
        "log_index": 0,
        "log_id": "pact-transparency-log-demo",
        "merkle_root": "sha256:mock_merkle_root_for_demo",
    },
}

# ---------------------------------------------------------------------------
# Step 2: Generate Receipts
# ---------------------------------------------------------------------------

def demo_single_receipt():
    """Generate a receipt for a single permitted tool call."""
    print("\n" + "=" * 60)
    print("PACT v0.3 — Single Tool Call Receipt Demo")
    print("=" * 60)

    print("\n[1] Policy committed:")
    print(f"    agent_id : {AGENT_POLICY['agent_id']}")
    print(f"    hash     : {AGENT_POLICY['policy_hash']}")
    print(f"    anchor   : log_index={AGENT_POLICY['anchor']['log_index']}, "
          f"merkle_root={AGENT_POLICY['anchor']['merkle_root'][:20]}...")
    print(f"    tools    : {AGENT_POLICY['policy']['allowed_tools']}")

    print("\n[2] Generating ZK receipt for 'search_web' tool call...")
    receipt = build_zk_receipt(
        policy=AGENT_POLICY,
        tool_name="search_web",
        params={"query": "agent accountability infrastructure"},
        anchor=AGENT_POLICY["anchor"],
        outcome=True,
        reason="tool_name in policy.allowed_tools",
        seq=1,
    )

    print(f"    receipt_hash : {receipt['receipt_hash'][:40]}...")
    print(f"    action_id    : {receipt['action_id']}")
    print(f"    outcome       : {receipt['outcome']}")
    proof_type = receipt["proof"]["zk"].get("proof_type", "unknown")
    print(f"    proof_type   : {proof_type}")
    print(f"    DUMMY_PROOF  : {'YES — RISC Zero not installed' if proof_type == 'DUMMY_ZK_PROOF' else 'NO'}")

    print("\n[3] Verifying receipt...")
    result = verify_zk_receipt(receipt)
    print(f"    valid   : {result['valid']}")
    print(f"    reason  : {result['reason']}")

    return receipt


def demo_chain_receipts():
    """Generate a chain of receipts to show continuity."""
    print("\n" + "=" * 60)
    print("PACT v0.3 — Receipt Chain Demo (3 calls)")
    print("=" * 60)

    prev_hash = None
    chain = []
    tools = ["search_web", "browser", "web_fetch"]

    for i, tool in enumerate(tools, start=1):
        receipt = build_zk_receipt(
            policy=AGENT_POLICY,
            tool_name=tool,
            params={"query": f"demo query {i}"},
            anchor=AGENT_POLICY["anchor"],
            outcome=True,
            reason="permitted",
            seq=i,
            prev_receipt_hash=prev_hash,
        )
        prev_hash = receipt["receipt_hash"]
        chain.append(receipt)
        mode = receipt["proof"]["zk"].get("proof_type", "unknown")
        print(f"  [{i}] {tool:<15} seq={receipt['seq']} "
              f"prev={str(prev_hash)[:16]}... "
              f"mode={mode}")

    print("\n[chain verification]")
    for r in chain:
        v = verify_zk_receipt(r)
        print(f"  seq={r['seq']} {r['tool_called']:<15} valid={v['valid']} "
              f"is_dummy={v.get('is_dummy', False)}")

    return chain


def demo_denied_receipt():
    """Generate a receipt for a denied tool call."""
    print("\n" + "=" * 60)
    print("PACT v0.3 — Denied Tool Call Receipt Demo")
    print("=" * 60)

    print("\n[1] Attempting 'exec' tool call (denied by policy)...")
    receipt = build_zk_receipt(
        policy=AGENT_POLICY,
        tool_name="exec",
        params={"command": "rm -rf /"},
        anchor=AGENT_POLICY["anchor"],
        outcome=False,
        reason="exec is in policy.denied_tools",
        seq=4,
    )

    print(f"    outcome      : {receipt['outcome']}")
    print(f"    outcome_reason : {receipt['outcome_reason']}")
    proof_type = receipt["proof"]["zk"].get("proof_type", "unknown")
    print(f"    proof_type   : {proof_type}")
    print(f"    receipt_hash : {receipt['receipt_hash'][:40]}...")

    print("\n[2] Verifying denied receipt...")
    result = verify_zk_receipt(receipt)
    print(f"    valid   : {result['valid']}")
    print(f"    reason  : {result['reason']}")

    return receipt


def main():
    print("PACT v0.3 — Full Workflow Demonstration")
    print("=" * 60)
    print("This demo shows the complete PACT receipt lifecycle.")
    print("No RISC Zero required — runs in DUMMY_PROOF mode.")
    print("Proof type 'DUMMY_ZK_PROOF' = placeholder, not cryptographically valid.")

    demo_single_receipt()
    demo_chain_receipts()
    demo_denied_receipt()

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print("""
PACT v0.3 Architecture:
  Layer 0: StdioInterceptor  — intercepts MCP tool calls, generates receipts
  Layer 1: Policy Commitment — SHA-256 hash anchored to transparency log
  Layer 2: ZK Receipt Generator — proves action ∈ committed_policy

Receipt chain:
  - Each receipt hashes the prior receipt (chain continuity)
  - Verifier checks structure — does NOT need RISC Zero verifier
  - Real ZK proof requires RISC Zero toolchain (not installed here)

Next steps for real proofs:
  1. Install RISC Zero: curl -fsSL https://risczero.com/install.sh | bash
  2. Build guest: cd rust/guest && cargo build --release
  3. Set RISC0_TOOLCHAIN=1 and re-run
""")


if __name__ == "__main__":
    main()
