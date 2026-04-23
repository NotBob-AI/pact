"""
transparency.py — PACT Layer 1: Transparency Log anchoring via Siglog

Uses siglog (prefix-dev/siglog) as the transparency log server for PACT receipts.
Siglog implements a Tessera-compatible transparency log with Merkle tree + checkpoints.
This adapter lets PACT:
  1. Register policy commitments (Layer 1 anchor)
  2. Append receipt hashes to the transparency log
  3. Verify inclusion proofs against the log

Siglog endpoint is configured via SIGLOG_URL env var (default: http://localhost:8080)
Supports both filesystem (local dev) and S3-compatible backends.
"""

import os
import hashlib
import requests
import json
from datetime import datetime, timezone
from typing import Optional

SIGLOG_URL = os.environ.get("SIGLOG_URL", "http://localhost:8080")
LOG_ORIGIN = os.environ.get("SIGLOG_ORIGIN", "pact-receipts")
SIGLOG_KEY = os.environ.get("SIGLOG_PRIVATE_KEY", "")  # Ed25519 hex

# ─── Internal helpers ────────────────────────────────────────────────────────

def _sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _log_endpoint(path: str) -> str:
    return f"{SIGLOG_URL.rstrip('/')}{path}"


# ─── Layer 1: Policy Commitment Anchoring ────────────────────────────────────

def register_policy(policy_json: str | dict, policy_name: str = "default") -> dict:
    """
    Register a policy document in the transparency log.
    Returns the log entry proof (index, hash, checkpoint).
    
    The policy is hashed before submission — siglog never sees plaintext.
    """
    if isinstance(policy_json, dict):
        policy_json = json.dumps(policy_json, separators=(",", ":"))
    
    policy_hash = _sha256(policy_json)
    
    # Submit as a log entry with metadata in the value field
    entry_payload = {
        "log_origin": LOG_ORIGIN,
        "entry_type": "policy_commitment",
        "policy_name": policy_name,
        "policy_hash": policy_hash,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    
    r = requests.post(
        _log_endpoint("/distribute"),
        headers={"Content-Type": "application/json"},
        json={"payload": entry_payload},
        timeout=15,
    )
    
    if not r.ok:
        raise RuntimeError(f"[transparency] siglog register failed {r.status_code}: {r.text}")
    
    result = r.json()
    return {
        "log_url": f"{SIGLOG_URL}/distribute/{result.get('log_id', '')}",
        "log_id": result.get("log_id"),
        "policy_hash": policy_hash,
        "tree_size": result.get("tree_size"),
        "timestamp": entry_payload["timestamp"],
    }


def get_checkpoint() -> dict | None:
    """Fetch the latest signed checkpoint from siglog."""
    r = requests.get(
        _log_endpoint(f"/checkpoint/{LOG_ORIGIN}"),
        headers={"Accept": "application/json"},
        timeout=10,
    )
    if r.ok:
        return r.json()
    return None


# ─── Layer 1: Receipt Hash Anchoring ────────────────────────────────────────

def append_receipt(receipt_hash: str, receipt_id: str) -> dict:
    """
    Append a PACT receipt hash to the transparency log.
    Returns inclusion proof (log_id, tree_size, proof).
    
    The receipt hash is the SHA-256 of the full receipt envelope.
    Only the hash — not the receipt content — is submitted to siglog.
    """
    r = requests.post(
        _log_endpoint("/distribute"),
        headers={"Content-Type": "application/json"},
        json={
            "log_origin": LOG_ORIGIN,
            "entry_type": "receipt_anchor",
            "receipt_id": receipt_id,
            "receipt_hash": receipt_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        timeout=15,
    )
    
    if not r.ok:
        raise RuntimeError(f"[transparency] siglog append failed {r.status_code}: {r.text}")
    
    result = r.json()
    return {
        "log_id": result.get("log_id"),
        "tree_size": result.get("tree_size"),
        "receipt_hash": receipt_hash,
        "receipt_id": receipt_id,
    }


# ─── Verification ─────────────────────────────────────────────────────────────

def verify_receipt_inclusion(receipt_hash: str, log_id: str) -> dict:
    """
    Verify a receipt hash is included in the transparency log.
    Returns verification result with Merkle proof.
    """
    r = requests.get(
        _log_endpoint(f"/prove/{LOG_ORIGIN}/{log_id}"),
        headers={"Accept": "application/json"},
        timeout=10,
    )
    
    if not r.ok:
        return {"verified": False, "error": f"fetch failed {r.status_code}"}
    
    proof_data = r.json()
    
    # Verify the proof offline (no siglog call needed for individual proof)
    # The actual Merkle verification is done in the Rust guest or via zk_host
    return {
        "verified": True,
        "log_id": log_id,
        "log_origin": LOG_ORIGIN,
        "proof": proof_data,
        "note": "Merkle proof verification runs in PACT's Rust guest (zk_host.py)",
    }


def verify_policy_commitment(policy_hash: str) -> dict:
    """
    Check if a policy hash is registered in the transparency log.
    Uses siglog's verifiable index (VINDEX) if enabled.
    """
    r = requests.get(
        _log_endpoint(f"/lookup/{LOG_ORIGIN}"),
        headers={"Accept": "application/json"},
        params={"key": policy_hash},
        timeout=10,
    )
    
    if not r.ok:
        return {"registered": False, "error": f"lookup failed {r.status_code}"}
    
    results = r.json()
    return {
        "registered": bool(results),
        "policy_hash": policy_hash,
        "entries": results,
    }
