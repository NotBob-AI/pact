#!/usr/bin/env python3
"""
receipt_generator.py — PACT v0.3 Sample Receipt Generator

Generates test/sample PACT receipts for development, testing, and demo.
Demonstrates the full v0.3 receipt format matching the canonical receipt schema.

Usage:
    python3 receipt_generator.py                       # generate 1 sample receipt
    python3 receipt_generator.py --count 5            # generate N receipts
    python3 receipt_generator.py --output ./my-receipts/   # custom output dir

Each receipt includes policy commitment with mock Merkle proof and DUMMY ZK proof.
Run verification: python3 verify.py -d ./my-receipts/
"""

import argparse
import hashlib
import json
import random
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Add pact package to path  (.../python/verifier/ -> .../python/)
sys.path.insert(0, str(Path(__file__).parent.parent))

from pact.receipt import (
    create_receipt as create_pact_receipt,
    PACTReceipt,
    PolicyCommitment,
    ToolCall,
    ZKProof,
    receipt_to_dict,
)


# ---------------------------------------------------------------------------
# Mock Merkle proof (8-leaf tree, 4 levels)
# ---------------------------------------------------------------------------

def _mock_merkle_proof() -> list[dict]:
    zero, one, two, three = "0" * 64, "1" * 64, "2" * 64, "3" * 64
    return [
        {"hash": "sha256:" + zero, "side": "left"},
        {"hash": "sha256:" + one, "side": "right"},
        {"hash": "sha256:" + two, "side": "left"},
        {"hash": "sha256:" + three, "side": "right"},
    ]


# ---------------------------------------------------------------------------
# Sample tool definitions
# ---------------------------------------------------------------------------

SAMPLE_TOOLS = [
    ("read_file", {"path": "/tmp/example.txt"}),
    ("write_file", {"path": "/tmp/output.json", "content": '{"key": "value"}'}),
    ("search_web", {"query": "agent accountability infrastructure"}),
    ("send_email", {"to": "alice@example.com", "subject": "Status update"}),
    ("http_request", {"url": "https://api.example.com/data", "method": "GET"}),
    ("exec_command", {"cmd": "ls -la", "timeout": 30}),
    ("mcp_tool_call", {"server": "filesystem", "tool": "read", "args": {}}),
    ("mcp_tool_call", {"server": "http", "tool": "fetch", "args": {}}),
]

SAMPLE_AGENTS = [
    "did:key:z6Mk_notbob_demo_agent_001",
    "did:key:z6Mk_notbob_demo_agent_002",
    "did:key:z6Mk_notbob_demo_agent_003",
]


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

def generate_sample_receipt(
    agent_id: str = None,
    tool_name: str = None,
    tool_args: dict = None,
    outcome: str = "permitted",
) -> dict:
    """
    Generate a single sample PACT v0.3 receipt dict.

    Args:
        agent_id:  Agent DID (random from SAMPLE_AGENTS if None)
        tool_name: Tool name (random from SAMPLE_TOOLS if None)
        tool_args: Tool args dict (extracted from SAMPLE_TOOLS if None)
        outcome:   "permitted" or "denied"

    Returns:
        Full PACT receipt as a JSON-serializable dict
    """
    if agent_id is None:
        agent_id = random.choice(SAMPLE_AGENTS)

    if tool_name is None:
        tool_name, tool_args = random.choice(SAMPLE_TOOLS)

    # Build policy commitment
    commitment = PolicyCommitment(
        policy_hash="sha256:" + "a" * 64,
        log_index=1,
        log_id="sha256:" + "b" * 64,
        merkle_root="sha256:" + "c" * 64,
        merkle_proof=_mock_merkle_proof(),
    )

    # Build tool call
    action_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    tool_input_hash = "sha256:" + hashlib.sha256(
        json.dumps({"tool": tool_name, "args": tool_args}, sort_keys=True).encode()
    ).hexdigest()

    tool_call = ToolCall(
        tool_name=tool_name,
        tool_input_hash=tool_input_hash,
        timestamp=timestamp,
        action_id=action_id,
        tool_output_hash=None,
    )

    # Build ZK proof (DUMMY mode for sample receipts)
    zk_proof = ZKProof(
        proof_type="DUMMY_ZK_PROOF",
        image_id="sha256:" + "f" * 64,
        seal="DUMMY_SEAL:",
        public_inputs={
            "policy_hash": commitment.policy_hash,
            "merkle_root": commitment.merkle_root,
            "log_index": commitment.log_index,
            "tool_name_hash": tool_input_hash,
            "timestamp": tool_call.timestamp,
        },
    )

    # Assemble receipt using the canonical dataclass factory
    receipt = create_pact_receipt(
        policy_commitment=commitment,
        tool_call=tool_call,
        proof=zk_proof,
    )

    # Serialize to dict
    result = receipt_to_dict(receipt)

    # Add PACT top-level fields
    result["receipt_version"] = result.get("version", "0.3")
    result["action_id"] = result.get("receipt_id", action_id)
    result["agent_id"] = agent_id
    result["outcome"] = outcome
    result["policy_hash"] = commitment.policy_hash
    # Add flat fields that verify.py expects for v0.1 compat
    result["tool_called"] = tool_call.tool_name
    result["statement"] = "tool " + tool_name + " " + outcome + " under policy " + commitment.policy_hash[:16] + "..."
    result["receipt_hash"] = "sha256:" + hashlib.sha256(
        json.dumps(result, sort_keys=True).encode()
    ).hexdigest()

    return result


def save_receipt(receipt: dict, output_dir: Path) -> Path:
    """Save a receipt dict to a JSON file."""
    output_dir.mkdir(parents=True, exist_ok=True)
    action_id = receipt.get("action_id", str(uuid.uuid4()))
    out_path = output_dir / f"{action_id}.json"
    with open(out_path, "w") as f:
        json.dump(receipt, f, indent=2)
    return out_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="PACT v0.3 Sample Receipt Generator")
    parser.add_argument(
        "--count", "-n", type=int, default=1,
        help="Number of sample receipts to generate (default: 1)"
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=Path("./sample-receipts"),
        help="Output directory (default: ./sample-receipts)"
    )
    parser.add_argument(
        "--agent-id", type=str, default=None,
        help="Override agent DID"
    )
    parser.add_argument(
        "--tool", type=str, default=None,
        help="Override tool name"
    )
    parser.add_argument(
        "--outcome", choices=["permitted", "denied"], default="permitted",
        help="Receipt outcome (default: permitted)"
    )
    args = parser.parse_args()

    print(f"[receipt_generator] Generating {args.count} sample receipt(s)")
    print(f"                    Output: {args.output.absolute()}")

    for i in range(args.count):
        receipt = generate_sample_receipt(
            agent_id=args.agent_id,
            tool_name=args.tool,
            outcome=args.outcome,
        )
        out_path = save_receipt(receipt, args.output)
        tool = receipt.get("tool_call", {}).get("tool_name", "unknown")
        oid = receipt.get("action_id", "?")[:8]
        print(f"  [{i+1}/{args.count}] {oid}... [{tool}] outcome={receipt.get('outcome')}")

    print(f"\n[receipt_generator] Done. {args.count} receipt(s) written.")
    print(f"                    Run: python3 verify.py -d {args.output}")
    print(f"                    Or: pact-cli.py verify --receipt {args.output}/<action_id>.json")


if __name__ == "__main__":
    main()