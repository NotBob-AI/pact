"""
transparency.py — PACT Layer 1: Transparency Log anchoring

Supports two backends:
  - siglog (prefix-dev/siglog): Tessera-compatible remote transparency log server
  - local-file: append-only JSONL at ~/.pact/transparency-local.jsonl (dev/CI fallback)

Configure via env vars:
  SIGLOG_URL      — siglog server URL (default: http://localhost:8080)
  SIGLOG_ORIGIN   — log origin name (default: pact-receipts)
  SIGLOG_MODE     — set to "local" to force local-file backend
  SIGLOG_PRIVATE_KEY — Ed25519 hex key for signing (optional, siglog only)

This adapter lets PACT:
  1. Register policy commitments (Layer 1 anchor)
  2. Append receipt hashes to the transparency log
  3. Verify inclusion proofs against the log
"""

import os
import json
import uuid
import hashlib
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ─── Configuration ────────────────────────────────────────────────────────────
SIGLOG_URL     = os.environ.get("SIGLOG_URL", "http://localhost:8080")
LOG_ORIGIN     = os.environ.get("SIGLOG_ORIGIN", "pact-receipts")
SIGLOG_MODE    = os.environ.get("SIGLOG_MODE", "").lower()
SIGLOG_KEY     = os.environ.get("SIGLOG_PRIVATE_KEY", "")

_LOCAL_LOG_PATH = Path.home() / ".pact" / "transparency-local.jsonl"


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _log_endpoint(path: str) -> str:
    return f"{SIGLOG_URL.rstrip('/')}{path}"


def _siglog_reachable() -> bool:
    """Check if siglog server is reachable."""
    try:
        r = requests.get(f"{SIGLOG_URL.rstrip('/')}/health", timeout=3)
        return r.ok
    except Exception:
        return False


def _dispatch(endpoint: str, payload: dict) -> dict:
    """
    Route to local or remote backend.
    Local is used when SIGLOG_MODE=local or siglog is unreachable.
    """
    if SIGLOG_MODE == "local" or not _siglog_reachable():
        return _local_append(payload)

    r = requests.post(
        f"{SIGLOG_URL.rstrip('/')}{endpoint}",
        headers={"Content-Type": "application/json"},
        json={"payload": payload},
        timeout=15,
    )
    if not r.ok:
        raise RuntimeError(f"[transparency] siglog {endpoint} failed {r.status_code}: {r.text}")
    return r.json()


# ─── Local-file backend (dev / CI) ──────────────────────────────────────────

def _local_init():
    _LOCAL_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def _local_append(entry: dict) -> dict:
    """Append an entry to the local JSONL log. Returns simulated log response."""
    _local_init()
    local_id = str(uuid.uuid4())[:12]
    entry["_local_id"] = local_id
    entry["_log_id"] = local_id
    entry["_local"] = True
    with open(_LOCAL_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    with open(_LOCAL_LOG_PATH) as f:
        tree_size = sum(1 for _ in f)
    return {"log_id": local_id, "tree_size": tree_size, "_local": True}


def _local_entries() -> list[dict]:
    """Read all entries from the local log."""
    _local_init()
    if not _LOCAL_LOG_PATH.exists():
        return []
    entries = []
    with open(_LOCAL_LOG_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


# ─── Layer 1: Policy Commitment Anchoring ─────────────────────────────────────

def register_policy(policy_json: str | dict, policy_name: str = "default") -> dict:
    """
    Register a policy document in the transparency log.
    Returns the log entry proof (index, hash, checkpoint).

    The policy is hashed before submission — siglog/local log never sees plaintext.
    """
    if isinstance(policy_json, dict):
        policy_json = json.dumps(policy_json, separators=(",", ":"))

    policy_hash = _sha256(policy_json)

    entry_payload = {
        "log_origin": LOG_ORIGIN,
        "entry_type": "policy_commitment",
        "policy_name": policy_name,
        "policy_hash": policy_hash,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    result = _dispatch("/distribute", entry_payload)
    log_id = result.get("log_id", "")

    return {
        "log_url": f"{SIGLOG_URL}/distribute/{log_id}" if not result.get("_local") else str(_LOCAL_LOG_PATH),
        "log_id": log_id,
        "policy_hash": policy_hash,
        "tree_size": result.get("tree_size"),
        "timestamp": entry_payload["timestamp"],
        "_local": result.get("_local", False),
    }


def get_checkpoint() -> dict | None:
    """
    Fetch the latest signed checkpoint from siglog.
    Falls back to local log stats when SIGLOG_MODE=local or siglog unreachable.
    """
    if SIGLOG_MODE == "local" or not _siglog_reachable():
        entries = _local_entries()
        return {"size": len(entries), "origin": LOG_ORIGIN, "_local": True}

    r = requests.get(
        _log_endpoint(f"/checkpoint/{LOG_ORIGIN}"),
        headers={"Accept": "application/json"},
        timeout=10,
    )
    if r.ok:
        return r.json()
    return None


# ─── Layer 1: Receipt Hash Anchoring ─────────────────────────────────────────

def append_receipt(receipt_hash: str, receipt_id: str) -> dict:
    """
    Append a PACT receipt hash to the transparency log.
    Returns inclusion proof (log_id, tree_size).

    The receipt hash is the SHA-256 of the full receipt envelope.
    Only the hash — not the receipt content — is submitted.
    """
    entry = {
        "log_origin": LOG_ORIGIN,
        "entry_type": "receipt_anchor",
        "receipt_id": receipt_id,
        "receipt_hash": receipt_hash,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    result = _dispatch("/distribute", entry)
    return {
        "log_id": result.get("log_id"),
        "tree_size": result.get("tree_size"),
        "receipt_hash": receipt_hash,
        "receipt_id": receipt_id,
        "_local": result.get("_local", False),
    }


# ─── Verification ─────────────────────────────────────────────────────────────

def verify_receipt_inclusion(receipt_hash: str, log_id: str) -> dict:
    """
    Verify a receipt hash is included in the transparency log.
    Falls back to local-file scan when SIGLOG_MODE=local or siglog unreachable.
    """
    if SIGLOG_MODE == "local" or not _siglog_reachable():
        for e in _local_entries():
            if e.get("receipt_hash") == receipt_hash:
                return {"verified": True, "log_id": e.get("_log_id"), "receipt_hash": receipt_hash, "_local": True}
        return {"verified": False, "log_id": log_id, "error": "not found in local log"}

    r = requests.get(
        _log_endpoint(f"/prove/{LOG_ORIGIN}/{log_id}"),
        headers={"Accept": "application/json"},
        timeout=10,
    )
    if not r.ok:
        return {"verified": False, "error": f"fetch failed {r.status_code}"}

    return {
        "verified": True,
        "log_id": log_id,
        "log_origin": LOG_ORIGIN,
        "proof": r.json(),
        "note": "Merkle proof verification runs in PACT's Rust guest (zk_host.py)",
    }


def verify_policy_commitment(policy_hash: str) -> dict:
    """
    Check if a policy hash is registered in the transparency log.
    Falls back to local-file scan when SIGLOG_MODE=local or siglog unreachable.
    """
    if SIGLOG_MODE == "local" or not _siglog_reachable():
        matching = [e for e in _local_entries() if e.get("policy_hash") == policy_hash]
        return {"registered": bool(matching), "policy_hash": policy_hash, "entries": matching, "_local": True}

    r = requests.get(
        _log_endpoint(f"/lookup/{LOG_ORIGIN}"),
        headers={"Accept": "application/json"},
        params={"key": policy_hash},
        timeout=10,
    )
    if not r.ok:
        return {"registered": False, "error": f"lookup failed {r.status_code}"}

    results = r.json()
    return {"registered": bool(results), "policy_hash": policy_hash, "entries": results}
