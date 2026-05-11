#!/usr/bin/env python3
"""
PACT v0.9 — CLI Tool

Usage:
    pact-cli.py generate --policy policy.json --tool TOOL_NAME [--params params.json]
    pact-cli.py verify   --receipt receipt.json
    pact-cli.py status
    pact-cli.py diagnose
    pact-cli.py bundle-create receipts_dir [--output bundle.json]
    pact-cli.py bundle-verify bundle.json
    pact-cli.py run [--agent-id NAME] [--output-dir DIR]

Examples:
    pact-cli.py generate --policy my-policy.json --tool search_web
    pact-cli.py verify --receipt /tmp/pact-zk-proof.json
    pact-cli.py diagnose
    pact-cli.py bundle-create ./receipts --output audit-bundle.json
    pact-cli.py run --agent-id notbob --output-dir /tmp/pact-demo
"""

import argparse
import json
import sys
from pathlib import Path

# Add pact package to path
sys.path.insert(0, str(Path(__file__).parent / "python"))

from pact.zk_host import (
    generate_zk_receipt,
    verify_zk_receipt,
    _check_risc0_environment,
    DUMMY_PROOF,
)
from pact.receipt_generator import ReceiptGenerator
from pact.policy_spec import PolicySpec
from pact.commitment import TransparencyLog
from verifier.bundle import build_bundle, verify_bundle
from verifier.verify import verify_zk_receipt as vr


def cmd_generate(args):
    """Generate a ZK receipt for a tool call."""
    # Load policy
    with open(args.policy) as f:
        policy = json.load(f)

    # Build anchor from policy
    anchor = policy.get("anchor", {})
    if not anchor:
        print("[error] Policy must have an 'anchor' field with log_index, log_id, merkle_root", file=sys.stderr)
        sys.exit(1)

    # Load params if provided
    params = None
    if args.params:
        with open(args.params) as f:
            params = json.load(f)

    # Merkle proof from policy or file
    merkle_proof = policy.get("merkle_proof", [])
    if args.merkle_proof:
        with open(args.merkle_proof) as f:
            merkle_proof = json.load(f)

    import asyncio
    receipt = asyncio.run(generate_zk_receipt(policy, args.tool, anchor, merkle_proof, params))

    output_path = Path(args.output) if args.output else Path("/tmp/pact-zk-receipt.json")
    with open(output_path, "w") as f:
        json.dump(receipt, f, indent=2)

    print(f"ZK receipt written to {output_path}")
    stub = receipt.get("proof", {}).get("stub", False)
    print(f"  policy: {receipt['public']['policy_hash'][:24]}...")
    print(f"  tool:   {args.tool}")
    print(f"  mode:   {'STUB (DUMMY_PROOF)' if stub else 'LIVE ZK PROOF'}")

    if stub:
        print("\n[WARNING] Stub receipt — RISC Zero not available. Not cryptographically valid.")

    return 0


def cmd_verify(args):
    """Verify a ZK receipt."""
    with open(args.receipt) as f:
        receipt = json.load(f)

    result = verify_zk_receipt(receipt)
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


def cmd_status(args):
    """Show PACT system status."""
    env = _check_risc0_environment()
    print("PACT v0.3 Status")
    print("-" * 40)
    print(f"  RISC Zero binary:     {'✓' if env['rz_binary'] else '✗'}")
    print(f"  Guest binary:          {'✓' if env['guest_binary'] else '✗'}")
    print(f"  Image ID file:          {'✓' if env['image_id_file'] else '✗'}")
    print(f"  RISC Zero available:   {'✓' if env['risc0_available'] else '✗'}")
    print(f"  DUMMY_PROOF mode:       {'ON' if DUMMY_PROOF else 'OFF'}")

    if env["diagnosis"]:
        print("\nDiagnositcs:")
        for d in env["diagnosis"]:
            print(f"  - {d}")

    print()
    return 0


def cmd_diagnose(args):
    """Run full diagnostic on RISC Zero environment."""
    env = _check_risc0_environment()
    print("RISC Zero Environment Diagnostics")
    print("=" * 50)

    checks = [
        ("RISC Zero CLI (rz or cargo-risczero)", env["rz_binary"]),
        ("Guest binary", env["guest_binary"]),
        ("Image ID file", env["image_id_file"]),
        ("Overall availability", env["risc0_available"]),
    ]

    for label, result in checks:
        print(f"  {'✓' if result else '✗'} {label}")

    if env["diagnosis"]:
        print("\nIssues found:")
        for d in env["diagnosis"]:
            print(f"  → {d}")
        print("\nTo fix, run:")
        print("  curl -fsSL https://risczero.com/install.sh | bash")
        print("  source ~/.risc0/env")
        print("  cd rust/guest && cargo build --release")
    else:
        print("\n[OK] RISC Zero environment is ready.")

    return 0


def cmd_bundle_create(args):
    """Create an offline-verifiable receipt bundle."""
    receipts_dir = Path(args.receipts_dir)
    if not receipts_dir.exists():
        print(f"[error] Directory not found: {receipts_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Building bundle from {receipts_dir}...")
    bundle = build_bundle(receipts_dir)

    output_path = Path(args.output) if args.output else receipts_dir / "bundle.json"
    with open(output_path, "w") as f:
        json.dump(bundle, f, indent=2)

    print(f"Bundle written to {output_path}")
    print(f"  agent_id:  {bundle['agent_id']}")
    print(f"  receipts:  {len(bundle['receipts'])}")
    print(f"  first:     {bundle['chain_integrity']['first_receipt_hash'][:24]}...")
    print(f"  last:      {bundle['chain_integrity']['last_receipt_hash'][:24]}...")
    return 0


def cmd_bundle_verify(args):
    """Verify an offline receipt bundle."""
    with open(args.bundle) as f:
        bundle = json.load(f)

    result = verify_bundle(bundle)
    print(f"Bundle Verification: {'✓ VALID' if result['valid'] else '✗ INVALID'}")
    print(f"  agent_id:  {result.get('agent_id')}")
    print(f"  policy:    {result.get('policy_hash', 'N/A')[:24]}...")
    print(f"  receipts:  {len(result.get('results', []))}")

    invalid = [r for r in result.get('results', []) if not r.get('verification', {}).get('valid')]
    if invalid:
        print(f"\n  ✗ {len(invalid)} invalid receipt(s):")
        for r in invalid:
            print(f"    - {r.get('action_id', '?')[:16]}... ({r.get('tool')})")

    chain_breaks = [r for r in result.get('results', []) if r.get('chain_breaking')]
    if chain_breaks:
        print(f"\n  ✗ {len(chain_breaks)} chain-breaking receipt(s):")
        for r in chain_breaks:
            print(f"    - {r.get('action_id', '?')[:16]}...")

    return 0 if result['valid'] else 1


def cmd_run_receipts(args):
    """Run the full integration test and generate a demo bundle."""
    receipts_dir = Path(args.output_dir)
    receipts_dir.mkdir(parents=True, exist_ok=True)

    print("=== PACT Integration Test + Bundle Demo ===\n")

    log = TransparencyLog()
    gen = ReceiptGenerator(
        agent_id=args.agent_id or "notbob",
        principal_did="did:web:notbob.ai",
    )
    print(f"Generator: agent_id={gen.agent_id}")

    spec = gen.register_policy(
        allowed_tools=["web_search", "web_fetch", "memory_search", "exec"],
        denied_tools=["delete", "rm", "system", "sudo"],
        constraints={"max_calls_per_hour": 100},
    )
    print(f"Policy registered: {spec.compute_hash()[:24]}...")

    anchor = gen.anchor_policy(spec)
    print(f"Policy anchored: log_index={anchor['log_index']}")

    # Generate receipts
    receipts_generated = []
    tools_to_test = [
        ("web_search", {"query": "critical minerals 2026"}),
        ("memory_search", {"query": "PACT accountability"}),
        ("delete", {"path": "/etc/passwd"}),  # denied
        ("web_fetch", {"url": "https://notbob.ai"}),
    ]

    for tool_name, params in tools_to_test:
        receipt, outcome = gen.generate_receipt(tool_name, params)
        out_marker = "✓" if outcome == "permitted" else "✗"
        print(f"  {out_marker} {tool_name}: {outcome}")

        # Save receipt
        receipt_path = receipts_dir / f"{receipt.tool_call.action_id}.json"
        with open(receipt_path, "w") as f:
            json.dump(receipt.to_dict(), f, indent=2)
        receipts_generated.append(receipt_path)

    print(f"\n{len(receipts_generated)} receipts written to {receipts_dir}")

    # Build bundle
    bundle = build_bundle(receipts_dir)
    bundle_path = receipts_dir / "bundle.json"
    with open(bundle_path, "w") as f:
        json.dump(bundle, f, indent=2)
    print(f"Bundle written to {bundle_path}")

    # Verify
    result = verify_bundle(bundle)
    print(f"\nBundle verification: {'✓ VALID' if result['valid'] else '✗ INVALID'}")
    return 0


def main():
    parser = argparse.ArgumentParser(prog="pact-cli.py", description="PACT v0.3 CLI")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("status", help="Show PACT system status")
    sub.add_parser("diagnose", help="Diagnose RISC Zero environment")

    gen = sub.add_parser("generate", help="Generate a ZK receipt")
    gen.add_argument("--policy", required=True, help="Path to committed policy JSON")
    gen.add_argument("--tool", required=True, help="Tool name being called")
    gen.add_argument("--params", help="Path to tool params JSON (optional)")
    gen.add_argument("--merkle-proof", help="Path to Merkle proof JSON (optional)")
    gen.add_argument("--output", help="Output path (default: /tmp/pact-zk-receipt.json)")

    ver = sub.add_parser("verify", help="Verify a ZK receipt")
    ver.add_argument("--receipt", required=True, help="Path to receipt JSON")

    bcreate = sub.add_parser("bundle-create", help="Create an offline receipt bundle")
    bcreate.add_argument("receipts_dir", help="Directory containing receipt .json files")
    bcreate.add_argument("--output", "-o", help="Output bundle path (default: receipts_dir/bundle.json)")

    bverify = sub.add_parser("bundle-verify", help="Verify an offline receipt bundle")
    bverify.add_argument("bundle", help="Path to bundle .json file")

    run = sub.add_parser("run", help="Run full integration test + generate demo bundle")
    run.add_argument("--agent-id", help="Agent ID (default: notbob)")
    run.add_argument("--output-dir", default="/tmp/pact-demo-receipts", help="Receipts output dir")

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        return 0

    commands = {
        "generate": cmd_generate,
        "verify": cmd_verify,
        "status": cmd_status,
        "diagnose": cmd_diagnose,
        "bundle-create": cmd_bundle_create,
        "bundle-verify": cmd_bundle_verify,
        "run": cmd_run_receipts,
    }

    return commands[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
