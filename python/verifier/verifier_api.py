#!/usr/bin/env python3
"""
verifier_api.py — PACT Verifier REST API
Third parties verify receipts against committed policy without agent cooperation.

Usage:
    python3 verifier_api.py [--port 8080] [--receipts-dir /path/to/receipts]

Endpoints:
    GET  /receipt/:action_id     — verify a specific receipt
    POST /receipt/verify         — verify a raw receipt body
    GET  /agent/<agent_id>/receipts — list all receipts for an agent
    GET  /health                 — health check

No auth required — verification is public by design.
ZK receipts: structural check only (full ZK verification requires RISC0 runtime).
Ed25519 receipts: full cryptographic verification.
"""

import json
import argparse
import os
from pathlib import Path
from flask import Flask, request, jsonify
from verify import verify_receipt

app = Flask(__name__)

# Allow override via CLI flag or environment variable
DEFAULT_RECEIPTS_DIR = Path("/receipts")
RECEIPTS_DIR = None  # Set in main() after arg parsing


def get_receipts_dir():
    """Resolve receipts directory with priority: CLI flag > env > default."""
    if RECEIPTS_DIR:
        return RECEIPTS_DIR
    env_dir = os.environ.get("PACT_RECEIPTS_DIR")
    if env_dir:
        return Path(env_dir)
    return DEFAULT_RECEIPTS_DIR


@app.route("/health")
def health():
    receipts_dir = get_receipts_dir()
    return jsonify({
        "status": "ok",
        "service": "pact-verifier",
        "receipts_dir": str(receipts_dir),
        "receipts_exist": receipts_dir.exists() if receipts_dir.is_absolute() else False,
    })


@app.route("/agent/<agent_id>/receipts")
def get_agent_receipts(agent_id: str):
    """
    List all verified receipts for an agent_id.
    v0.4: third parties query accountability without agent cooperation.
    Returns receipts sorted by timestamp, most recent first.

    Note: receipts are stored as {action_id}.json. This route scans the
    configured receipts directory for any .json file whose payload
    contains the matching agent_id field.
    """
    receipts_dir = get_receipts_dir()
    if not receipts_dir.exists():
        return jsonify({
            "error": f"receipts directory not found: {receipts_dir}",
            "agent_id": agent_id,
        }), 500

    receipts = []
    for receipt_file in receipts_dir.glob("*.json"):
        try:
            receipt = json.loads(receipt_file.read_text())
            if receipt.get("agent_id") != agent_id:
                continue
            result = verify_receipt(receipt)
            receipts.append({
                "action_id": receipt.get("action_id"),
                "receipt_version": receipt.get("receipt_version", "0.1"),
                "tool_called": receipt.get("tool_called"),
                "policy_hash": receipt.get("policy_hash"),
                "timestamp": receipt.get("timestamp"),
                "outcome": receipt.get("outcome"),
                "verification": result,
            })
        except (json.JSONDecodeError, IOError):
            continue

    receipts.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    return jsonify({
        "agent_id": agent_id,
        "count": len(receipts),
        "receipts": receipts,
        "receipts_dir": str(receipts_dir),
    })


@app.route("/receipt/<action_id>")
def get_receipt(action_id: str):
    """Load and verify a receipt by action_id."""
    receipts_dir = get_receipts_dir()
    receipt_file = receipts_dir / f"{action_id}.json"
    if not receipt_file.exists():
        return jsonify({"error": "receipt not found", "action_id": action_id}), 404

    receipt = json.loads(receipt_file.read_text())
    result = verify_receipt(receipt)
    return jsonify({
        "action_id": action_id,
        "receipt_version": receipt.get("receipt_version", "0.1"),
        "tool_called": receipt.get("tool_called"),
        "agent_id": receipt.get("agent_id"),
        "policy_hash": receipt.get("policy_hash"),
        "outcome": receipt.get("outcome"),
        "verification": result,
    })


@app.route("/receipt/verify", methods=["POST"])
def verify_receipt_body():
    """
    Verify a raw receipt body.
    Body: {"receipt": {...}}
    Returns verification result.
    """
    body = request.get_json(force=True)
    receipt = body.get("receipt")
    if not receipt:
        return jsonify({"error": "missing 'receipt' field in body"}), 400

    result = verify_receipt(receipt)
    return jsonify({
        "receipt_version": receipt.get("receipt_version", "0.1"),
        "tool_called": receipt.get("tool_called"),
        "agent_id": receipt.get("agent_id"),
        "policy_hash": receipt.get("policy_hash"),
        "outcome": receipt.get("outcome"),
        "verification": result,
    })


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PACT Verifier REST API")
    parser.add_argument("--port", type=int, default=8080,
                        help="Port to serve on (default: 8080)")
    parser.add_argument("--receipts-dir", type=str, default=None,
                        help="Directory containing receipt JSON files (default: /receipts)")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                        help="Host to bind to (default: 0.0.0.0)")
    args = parser.parse_args()

    global RECEIPTS_DIR
    if args.receipts_dir:
        RECEIPTS_DIR = Path(args.receipts_dir)
    else:
        env_dir = os.environ.get("PACT_RECEIPTS_DIR")
        if env_dir:
            RECEIPTS_DIR = Path(env_dir)

    print(f"[verifier_api] Starting on {args.host}:{args.port}")
    print(f"[verifier_api] Receipts dir: {get_receipts_dir()}")
    app.run(host=args.host, port=args.port, debug=False)
