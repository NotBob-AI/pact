#!/usr/bin/env python3
"""
fhe_receipt_demo.py — PACT v0.5 FHE Receipt Demo

Demonstrates the full PACT v0.3 (ZK receipts) + v0.5 (FHE behavioral history)
composition. FHE layer: prove behavioral compliance without revealing
which tools were called.

FHE crossed the practical threshold in 2026:
  - Zama Concrete: Python/sklearn TFHE wrapper (Q2 2026)
  - Fhenix fhevm: Latticeworks FHE EVM on mainnet
  - KuCoin FHE: encrypted smart contracts processing encrypted ops/sec

Usage:
    python3 fhe_receipt_demo.py                 # run full demo
    python3 fhe_receipt_demo.py --count 3       # generate N FHE receipts
    python3 fhe_receipt_demo.py --verify        # verify generated receipts
"""

import argparse
import hashlib
import json
import random
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from pact.fhe_receipt import (
    FHEHistoryEnvelope,
    FHEReceipt,
    FHEReceiptProof,
    create_fhe_envelope,
    generate_fhe_receipt,
    generate_fhe_stub_proof,
    verify_fhe_receipt,
    fhe_receipt_to_dict,
    fhe_receipt_to_json,
    fhe_envelope_to_dict,
)
from pact.receipt import (
    create_receipt as create_pact_receipt,
    PolicyCommitment,
    ToolCall,
    ZKProof,
    receipt_to_dict,
)


# ---------------------------------------------------------------------------
# Simulated encrypted tool-call hashes
# In production these are real FHE ciphertext strings from Zama Concrete
# ---------------------------------------------------------------------------

FAKE_FHE_CT_PREFIXES = [
    "fhe_ct_aabbccdd",
    "fhe_ct_eeff0011",
    "fhe_ct_22334455",
    "fhe_ct_deadbeef",
    "fhe_ct_cafebabe",
    "fhe_ct_8badf00d",
    "fhe_ct_0badf00d",
    "fhe_ct_facade00",
]

SAMPLE_AGENTS = [
    "did:key:z6Mk_notbob_fhe_agent_001",
    "did:key:z6Mk_notbob_fhe_agent_002",
]

MOCK_POLICY_HASH = "sha256:" + "a" * 64


def _fake_fhe_ciphertext(n: int) -> str:
    """Generate a fake FHE ciphertext string for demo purposes."""
    prefix = random.choice(FAKE_FHE_CT_PREFIXES)
    suffix = uuid.uuid4().hex
    return f"{prefix}_{suffix}_ct"


def _mock_merkle_proof() -> list[dict]:
    zero, one = "0" * 64, "1" * 64
    return [
        {"hash": "sha256:" + zero, "side": "left"},
        {"hash": "sha256:" + one, "side": "right"},
    ]


def _build_v03_zk_receipt(agent_id: str, tool_name: str, policy_hash: str) -> dict:
    """Build a mock PACT v0.3 ZK receipt to embed in FHE receipt."""
    commitment = PolicyCommitment(
        policy_hash=policy_hash,
        log_index=1,
        log_id="sha256:" + "b" * 64,
        merkle_root="sha256:" + "c" * 64,
        merkle_proof=_mock_merkle_proof(),
    )

    action_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    tool_input_hash = "sha256:" + hashlib.sha256(
        json.dumps({"tool": tool_name, "args": {}}, sort_keys=True).encode()
    ).hexdigest()

    tool_call = ToolCall(
        tool_name=tool_name,
        tool_input_hash=tool_input_hash,
        timestamp=timestamp,
        action_id=action_id,
    )

    zk_proof = ZKProof(
        proof_type="DUMMY_ZK_PROOF",
        image_id="sha256:" + "f" * 64,
        seal="DUMMY_SEAL:",
        public_inputs={
            "policy_hash": policy_hash,
            "merkle_root": commitment.merkle_root,
            "log_index": commitment.log_index,
            "tool_name_hash": tool_input_hash,
            "timestamp": timestamp,
        },
    )

    receipt = create_pact_receipt(
        policy_commitment=commitment,
        tool_call=tool_call,
        proof=zk_proof,
    )
    result = receipt_to_dict(receipt)
    result["receipt_version"] = "0.3"
    result["action_id"] = action_id
    result["agent_id"] = agent_id
    result["outcome"] = "permitted"
    result["policy_hash"] = policy_hash
    result["tool_called"] = tool_name
    result["statement"] = f"tool {tool_name} permitted under policy {policy_hash[:16]}..."
    return result


# ---------------------------------------------------------------------------
# FHE Receipt Generation
# ---------------------------------------------------------------------------

def generate_fhe_demo_receipt(
    agent_id: str = None,
    trace_length: int = None,
    outcome: str = "permitted",
) -> dict:
    """
    Generate a full PACT v0.5 FHE receipt composable with v0.3 ZK receipts.

    Flow:
        1. Simulate N encrypted tool-call ciphertexts
        2. Build FHEHistoryEnvelope (encrypted trace commitment)
        3. Generate FHE receipt (proof over encrypted trace)
        4. Embed PACT v0.3 ZK receipt (plaintext tool membership)
        5. Return combined receipt dict

    The composition proves: "this agent called tool X (ZK receipt), and the
    full encrypted trace of N steps is consistent with committed policy
    (FHE receipt) — without revealing the other N-1 tool calls."
    """
    if agent_id is None:
        agent_id = random.choice(SAMPLE_AGENTS)
    if trace_length is None:
        trace_length = random.randint(2, 6)

    policy_hash = MOCK_POLICY_HASH

    # Step 1: Simulate FHE ciphertexts from encrypted tool-call trace
    encrypted_hashes = [_fake_fhe_ciphertext(i) for i in range(trace_length)]

    # Step 2: Build FHE envelope
    envelope = create_fhe_envelope(
        agent_id=agent_id,
        policy_hash=policy_hash,
        encrypted_tool_hashes=encrypted_hashes,
    )

    # Step 3: Build embedded v0.3 ZK receipt (tool X in this trace)
    tool_names = ["read_file", "write_file", "search_web", "http_request", "exec_command"]
    tool_name = random.choice(tool_names)
    zk_receipt = _build_v03_zk_receipt(agent_id, tool_name, policy_hash)

    # Step 4: Generate FHE receipt (proves trace compliance without revealing trace)
    fhe_receipt = generate_fhe_receipt(envelope, zk_receipt=zk_receipt)

    # Step 5: Return as dict
    result = fhe_receipt_to_dict(fhe_receipt)
    # stripped before serialization
    return result


def verify_fhe_demo_receipt(receipt: dict) -> dict:
    """Verify an FHE demo receipt and its embedded ZK receipt."""
    # Strip demo-only fields before constructing FHEReceipt
    safe = {k: v for k, v in receipt.items() if not k.startswith("_")}
    # Convert nested fhe_proof dict to FHEReceiptProof dataclass
    if "fhe_proof" in safe and isinstance(safe["fhe_proof"], dict):
        safe["fhe_proof"] = FHEReceiptProof(**safe["fhe_proof"])
    result = verify_fhe_receipt(FHEReceipt(**safe))

    # Also verify embedded v0.3 ZK receipt if present
    zk_ref = receipt.get("zk_receipt_ref")
    if zk_ref:
        result["zk_receipt"] = {
            "receipt_id": zk_ref.get("receipt_id"),
            "tool": zk_ref.get("tool_called"),
            "agent_id": zk_ref.get("agent_id"),
            "policy_hash": zk_ref.get("policy_hash"),
            "outcome": zk_ref.get("outcome"),
        }

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="PACT v0.5 FHE Receipt Demo")
    parser.add_argument(
        "--count", "-n", type=int, default=1,
        help="Number of FHE receipts to generate (default: 1)"
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=Path("./fhe-receipts"),
        help="Output directory (default: ./fhe-receipts)"
    )
    parser.add_argument(
        "--verify", action="store_true",
        help="Verify existing FHE receipts from output dir"
    )
    parser.add_argument(
        "--agent-id", type=str, default=None,
        help="Override agent DID"
    )
    parser.add_argument(
        "--trace-length", type=int, default=None,
        help="Override number of encrypted steps in trace"
    )
    args = parser.parse_args()

    output_dir = args.output
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.verify:
        # Verify all FHE receipts in output dir
        print(f"[FHE] Verifying FHE receipts in {output_dir}")
        receipt_files = sorted(output_dir.glob("*.json"))
        if not receipt_files:
            print("  No FHE receipts found. Run without --verify first.")
            return

        all_valid = True
        for f in receipt_files:
            receipt = json.loads(f.read_text())
            result = verify_fhe_demo_receipt(receipt)
            status = "✅" if result["valid"] else "❌"
            print(f"  {status} {receipt.get('receipt_id', '?')[:16]}... "
                  f"[{result.get('trace_length', 0)} steps] policy={receipt.get('policy_hash', '')[:24]}...")
            if "stub_warning" in result:
                print(f"       ⚠ {result['stub_warning']}")
            if "zk_receipt" in result:
                zk = result["zk_receipt"]
                print(f"       ZK: tool={zk.get('tool')} outcome={zk.get('outcome')}")
            if not result["valid"]:
                all_valid = False
                if "reason" in result:
                    print(f"       FAIL: {result['reason']}")

        print()
        status = "✅ ALL VALID" if all_valid else "❌ SOME INVALID"
        print(f"[FHE] {status}")
        return

    # Generate FHE receipts
    print(f"[FHE] Generating {args.count} FHE receipt(s)")
    print(f"      Composition: PACT v0.3 ZK receipt + v0.5 FHE behavioral history")
    print(f"      Output: {output_dir.absolute()}")
    print()

    for i in range(args.count):
        receipt = generate_fhe_demo_receipt(
            agent_id=args.agent_id,
            trace_length=args.trace_length,
        )
        receipt_id = receipt.get("receipt_id")
        out_path = output_dir / f"{receipt_id}.json"
        with open(out_path, "w") as f:
            json.dump(receipt, f, indent=2)

        zk = receipt.get("zk_receipt_ref", {})
        trace_len = receipt.get("trace_length", "?")
        tool = zk.get("tool_called", "?")
        outcome = zk.get("outcome", "?")
        print(f"  [{i+1}/{args.count}] {receipt_id[:16]}... "
              f"[{trace_len} encrypted steps] tool={tool} outcome={outcome}")

    print()
    print("[FHE] Done. FHE receipts written.")
    print(f"      Composition: each receipt embeds a PACT v0.3 ZK receipt")
    print(f"                 + FHE proof over encrypted behavioral trace")
    print(f"                 Verifier learns: tool membership, compliance, trace length")
    print(f"                 Verifier does NOT learn: which other tools were called")
    print()
    print(f"      To verify: python3 fhe_receipt_demo.py --verify --output {output_dir}")
    print(f"      To bundle: python3 bundle.py create {output_dir} -o {output_dir.name}-bundle.json")


if __name__ == "__main__":
    main()