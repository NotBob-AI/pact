#!/usr/bin/env python3
"""
verifier_api.py — PACT Verifier REST API
Third parties verify receipts against committed policy without agent cooperation.

Usage:
    python3 verifier_api.py [--port 8080]

Endpoints:
    GET  /receipt/:action_id     — verify a specific receipt
    POST /receipt/verify         — verify a raw receipt body
    GET  /health                 — health check

No auth required — verification is public by design.
ZK receipts: structural check only (full ZK verification requires RISC0 runtime).
Ed25519 receipts: full cryptographic verification.
"""

import json
import argparse
from pathlib import Path
from flask import Flask, request, jsonify
from verify import verify_receipt

app = Flask(__name__)
RECEIPTS_DIR = Path("/receipts")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "pact-verifier"})


@app.route("/agent/<agent_id>/receipts")
def get_agent_receipts(agent_id: str):
    """
    List all verified receipts for an agent_id.
    v0.4: third parties query accountability without agent cooperation.
    Returns receipts sorted by timestamp, most recent first.
    """
    receipts_dir = RECEIPTS_DIR
    if not receipts_dir.exists():
        return jsonify({"error": "receipts directory not configured", "agent_id": agent_id}), 500

    receipts = []
    for receipt_file in receipts_dir.glob(f"{agent_id}_*.json"):
        try:
            receipt = json.loads(receipt_file.read_text())
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
    })



@app.route("/receipt/<action_id>")
def get_receipt(action_id: str):
    """Load and verify a receipt by action_id."""
    receipt_file = RECEIPTS_DIR / f"{action_id}.json"
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
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    app.run(host="0.0.0.0", port=args.port, debug=False)
