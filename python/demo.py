#!/usr/bin/env python3
"""
demo.py — PACT End-to-End Demo CLI + Optional Verifier API Server

Simulates a policy commitment, intercepts tool calls, generates receipts
(v0.1 Ed25519 + v0.3 ZK), and verifies them.

With --serve: starts the PACT Verifier REST API alongside the demo so
third parties can audit receipts without agent cooperation.

Usage:
    # Demo only (receipt generation + local verification)
    python3 demo.py [--zk] [--verbose]

    # Full integration demo (generates receipts + serves verifier API)
    python3 demo.py --serve [--port 8080]

    # Verbose full demo
    python3 demo.py --serve --verbose

Integration flow demonstrated:
    [1] Create + commit policy to transparency log
    [2] Simulate 3 tool calls (2 allowed, 1 denied)
    [3] Generate v0.1 Ed25519 receipts for each
    [4] Generate v0.3 ZK receipts (DUMMY_PROOF — RISC Zero tooling待)
    [5] Save receipts to /tmp/pact-demo/receipts/ (verifier API reads from here)
    [6] Start verifier API and demonstrate third-party audit via HTTP
    [7] Show curl commands for external verification

Requirements:
    pip install cryptography flask  # flask only needed for --serve
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Resolve pact package relative to this file
_PACT_ROOT = Path(__file__).parent
sys.path.insert(0, str(_PACT_ROOT))

from pact import create_policy, generate_receipt, verify_receipt
from pact.transparency import register_policy


RECEIPTS_DIR = Path("/tmp/pact-demo/receipts")
DEMO_PORT = 8080


def sha256_hex(data: str) -> str:
    return f"sha256:{hashlib.sha256(data.encode('utf-8')).hexdigest()}"


def clear_receipts():
    """Wipe demo receipts directory for a clean run."""
    if RECEIPTS_DIR.exists():
        shutil.rmtree(RECEIPTS_DIR)
    RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[SETUP] Receipts dir: {RECEIPTS_DIR}")


def save_receipt(receipt: dict):
    """Save receipt to disk for verifier API consumption."""
    action_id = receipt["action_id"]
    path = RECEIPTS_DIR / f"{action_id}.json"
    with open(path, "w") as f:
        json.dump(receipt, f, indent=2)
    print(f"       Receipt saved: {path.name}")


def run_receipt_chain(agent_id: str, policy: dict, anchor: dict,
                      use_zk: bool = True, verbose: bool = False):
    """
    Simulate a sequence of tool calls and generate receipts for each.
    Returns list of (tool_name, receipt, outcome) tuples.
    """
    print()
    print("[CHAIN] Simulating tool call sequence...")
    print()

    calls = [
        ("read_file",  {"path": "/data/report.pdf", "offset": 0, "limit": 100}, True),
        ("search_web", {"query": "decentralized identity 2026", "limit": 5},        True),
        ("send_email", {"to": "alice@example.com", "subject": "report ready"},      True),
        ("execute_code", {"code": "rm -rf /"},                                    False),  # denied
    ]

    results = []
    for i, (tool_name, tool_params, expected_allowed) in enumerate(calls, 1):
        print(f"  [{i}] Intercepted: {tool_name}({tool_params})")
        receipt, outcome, reason = generate_receipt(policy, tool_name, tool_params)
        print(f"       outcome: {outcome} — {reason}")

        # Save to disk for verifier API
        save_receipt(receipt)

        # Generate ZK receipt alongside v0.1
        zk_info = None
        if use_zk and expected_allowed:
            try:
                from pact.zk_host import generate_stub_receipt, build_public_inputs
                anchor_dict = {
                    "log_index": anchor.get("index", 0),
                    "log_id": anchor.get("entry_id", anchor.get("log_id", "local")),
                    "merkle_root": anchor.get("merkle_root", policy["policy_hash"]),
                }
                pub_inputs = build_public_inputs(policy, tool_name, anchor_dict, tool_params)
                zk_receipt = generate_stub_receipt(pub_inputs, policy, tool_name)
                zk_info = f"ZK proof_type={zk_receipt['proof_type']}"
                print(f"       {zk_info}")
            except Exception as e:
                print(f"       ZK skipped: {e}")

        # Verify immediately (local check)
        result = verify_receipt(receipt, policy)
        status = "✓" if result["valid"] else "✗"
        print(f"       verified: {status} {result['reason']}")

        if verbose and not expected_allowed:
            print(f"       receipt: {json.dumps(receipt, indent=4)[:300]}...")

        results.append((tool_name, receipt, outcome, zk_info))
        print()

    return results


def start_verifier_api(port: int):
    """
    Start the PACT Verifier REST API in a background thread.
    Returns the thread handle.
    """
    # Patch RECEIPTS_DIR for the verifier module (import path: verifier.verify)
    sys.path.insert(0, str(_PACT_ROOT / "verifier"))
    import verify as verify_module
    verify_module.RECEIPTS_DIR = RECEIPTS_DIR

    from flask import Flask
    from verify import verify_receipt as vr

    app = Flask(__name__)

    @app.route("/health")
    def health():
        return {"status": "ok", "service": "pact-verifier", "receipts_dir": str(RECEIPTS_DIR)}

    @app.route("/agent/<agent_id>/receipts")
    def get_agent_receipts(agent_id: str):
        receipts = []
        for rf in sorted(RECEIPTS_DIR.glob("*.json")):
            try:
                r = json.loads(rf.read_text())
                result = vr(r)
                receipts.append({
                    "action_id": r.get("action_id"),
                    "receipt_version": r.get("receipt_version", "0.1"),
                    "tool_called": r.get("tool_called"),
                    "policy_hash": r.get("policy_hash"),
                    "outcome": r.get("outcome"),
                    "verification": result,
                })
            except (json.JSONDecodeError, IOError):
                continue
        receipts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return {"agent_id": agent_id, "count": len(receipts), "receipts": receipts}

    @app.route("/receipt/<action_id>")
    def get_receipt(action_id: str):
        rf = RECEIPTS_DIR / f"{action_id}.json"
        if not rf.exists():
            return {"error": "not found", "action_id": action_id}, 404
        r = json.loads(rf.read_text())
        result = vr(r)
        return {
            "receipt_version": r.get("receipt_version", "0.1"),
            "tool_called": r.get("tool_called"),
            "agent_id": r.get("agent_id"),
            "policy_hash": r.get("policy_hash"),
            "outcome": r.get("outcome"),
            "verification": result,
        }

    @app.route("/receipt/verify", methods=["POST"])
    def verify_body():
        body = request.get_json(force=True)
        r = body.get("receipt")
        if not r:
            from flask import request
            return {"error": "missing 'receipt'"}, 400
        result = vr(r)
        return {
            "receipt_version": r.get("receipt_version", "0.1"),
            "tool_called": r.get("tool_called"),
            "outcome": r.get("outcome"),
            "verification": result,
        }

    from flask import request
    import os
    # Pass receipts dir to the env so the standalone verifier_api.py also uses it
    os.environ["PACT_RECEIPTS_DIR"] = str(RECEIPTS_DIR)
    thread = threading.Thread(target=lambda: app.run(host="0.0.0.0", port=port, debug=False), daemon=True)
    thread.start()
    return thread


def demonstrate_verifier_api(base_url: str, agent_id: str, results: list):
    """Make HTTP calls to the running verifier API to demonstrate third-party audit."""
    import urllib.request
    import urllib.error

    print()
    print("[API] Demonstrating third-party verification via HTTP...")
    print()

    # Give server a moment to start
    time.sleep(0.5)

    allowed_results = [(t, r) for t, r, o, z in results if o == "allowed"]

    # 1. Health check
    try:
        with urllib.request.urlopen(f"{base_url}/health", timeout=5) as resp:
            health = json.loads(resp.read())
            print(f"  [GET /health] {health}")
    except Exception as e:
        print(f"  [GET /health] ERROR: {e}")
        return

    print()

    # 2. List all receipts for agent
    try:
        with urllib.request.urlopen(f"{base_url}/agent/{agent_id}/receipts", timeout=5) as resp:
            data = json.loads(resp.read())
            print(f"  [GET /agent/{agent_id}/receipts]")
            print(f"       count: {data['count']}")
            for rx in data.get("receipts", [])[:3]:
                print(f"       - {rx['tool_called']}: verified={rx['verification'].get('valid')}")
    except Exception as e:
        print(f"  [GET /agent/{agent_id}/receipts] ERROR: {e}")

    print()

    # 3. Fetch individual receipt
    if allowed_results:
        tool_name, receipt = allowed_results[0]
        action_id = receipt["action_id"]
        try:
            with urllib.request.urlopen(f"{base_url}/receipt/{action_id}", timeout=5) as resp:
                data = json.loads(resp.read())
                print(f"  [GET /receipt/{action_id}]")
                print(f"       tool: {data['tool_called']}")
                print(f"       version: {data['receipt_version']}")
                print(f"       verified: {data['verification'].get('valid')}")
                print(f"       reason: {data['verification'].get('reason', '')[:80]}")
        except Exception as e:
            print(f"  [GET /receipt/{action_id}] ERROR: {e}")

    print()
    print("[API] curl commands for external verification:")
    print()
    if allowed_results:
        action_id = allowed_results[0][1]["action_id"]
        print(f"  # Check receipt for {allowed_results[0][0]}:")
        print(f"  curl -s {base_url}/receipt/{action_id} | jq .")
        print()
    print(f"  # List all receipts for demo agent:")
    print(f"  curl -s {base_url}/agent/{agent_id}/receipts | jq .")
    print()


def run_demo(use_zk: bool = True, serve: bool = False, port: int = DEMO_PORT,
             verbose: bool = False):
    print("=" * 60)
    print("PACT End-to-End Demo")
    if serve:
        print(f"(with Verifier API on port {port})")
    print("=" * 60)
    print()

    agent_id = "did:key:z6Mkdemo123456789"

    # Clean receipts dir
    clear_receipts()

    # ── Layer 1: Create + commit policy ──────────────────────────────────────
    policy = create_policy(
        agent_id=agent_id,
        allowed_tools=["read_file", "search_web", "send_email"],
        denied_tools=["delete_file", "execute_code", "access_credentials"],
    )
    policy_hash = policy["policy_hash"]
    print(f"[1] Policy created for agent: {agent_id}")
    print(f"    Allowed: {policy['policy']['allowed_tools']}")
    print(f"    Denied:  {policy['policy']['denied_tools']}")
    print(f"    Hash:    {policy_hash}")
    print()

    # ── Layer 1: Anchor to transparency log ───────────────────────────────────
    policy_str = json.dumps(policy, sort_keys=True)
    anchor = register_policy(policy_str, agent_id)
    entry_id = anchor.get("entry_id", anchor.get("index", "local"))
    print(f"[2] Policy anchored — entry_id: {entry_id}")
    print(f"    Merkle root: {anchor.get('merkle_root', 'n/a')}")
    print()

    # ── Start verifier API (background thread) ────────────────────────────────
    base_url = f"http://localhost:{port}"
    api_thread = None
    if serve:
        print(f"[API] Starting PACT Verifier REST API on port {port}...")
        api_thread = start_verifier_api(port)
        print(f"       API running: {base_url}")
        print(f"       Health:     {base_url}/health")
        print()

    # ── Layer 2: Generate receipt chain ─────────────────────────────────────
    results = run_receipt_chain(agent_id, policy, anchor, use_zk=use_zk, verbose=verbose)

    # ── Show full receipt JSON if verbose ────────────────────────────────────
    if verbose:
        allowed_results = [(t, r) for t, r, o, z in results if o == "allowed"]
        if allowed_results:
            print("[VERBOSE] Sample receipt JSON:")
            print(json.dumps(allowed_results[0][1], indent=2))
            print()

    # ── Demonstrate verifier API ─────────────────────────────────────────────
    if serve and api_thread:
        demonstrate_verifier_api(base_url, agent_id, results)

    # ── Summary ──────────────────────────────────────────────────────────────
    all_results = [(t, o) for t, r, o, z in results]
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Policy hash:    {policy_hash}")
    print(f"  Anchored at:    {entry_id}")
    print(f"  Total calls:    {len(results)}")
    print(f"  Allowed:        {sum(1 for _,o in all_results if o == 'allowed')}")
    print(f"  Denied:         {sum(1 for _,o in all_results if o == 'denied')}")
    if serve:
        print(f"  Verifier API:   {base_url}")
        print(f"  Receipts dir:   {RECEIPTS_DIR}")
    print("=" * 60)
    print()
    print("Demo complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PACT End-to-End Demo CLI")
    parser.add_argument("--no-zk", dest="zk", action="store_false",
                        help="Skip ZK receipt generation (v0.1 only)")
    parser.add_argument("--serve", action="store_true",
                        help="Start PACT Verifier REST API alongside demo")
    parser.add_argument("--port", type=int, default=DEMO_PORT,
                        help=f"Verifier API port (default: {DEMO_PORT})")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show full receipt JSON")
    args = parser.parse_args()

    run_demo(use_zk=args.zk, serve=args.serve, port=args.port, verbose=args.verbose)
