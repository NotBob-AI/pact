#!/usr/bin/env python3
"""
PACT v0.3 — CLI Tool

Usage:
    pact-cli.py generate --policy policy.json --tool TOOL_NAME [--params params.json]
    pact-cli.py verify   --receipt receipt.json
    pact-cli.py status
    pact-cli.py diagnose

Examples:
    pact-cli.py generate --policy my-policy.json --tool search_web
    pact-cli.py verify --receipt /tmp/pact-zk-proof.json
    pact-cli.py diagnose
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

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        return 0

    commands = {
        "generate": cmd_generate,
        "verify": cmd_verify,
        "status": cmd_status,
        "diagnose": cmd_diagnose,
    }

    return commands[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
