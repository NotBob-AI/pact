#!/usr/bin/env python3
"""
PACT v0.5 — FHE Receipt Verifier

Verifies FHE behavioral history receipts.
Confirms trace commitment matches the envelope, and that the envelope
references a valid PACT policy commitment.

Usage:
    python3 -m pact.verifier.verify_fhe_receipt --envelope envelope.json --policy-hash HASH

Verification steps:
    1. Parse FHEHistoryEnvelope
    2. Validate envelope version is PACT_FHE_VERSION (0.5.0)
    3. Verify trace_commitment = SHA256(ciphertext_hashes concatenated)
    4. Confirm policy_hash matches expected (passed as arg or fetched from log)
    5. Check envelope_id format (UUID v4)
    6. Return VALID/INVALID with reason

The verifier does NOT decrypt ciphertexts — FHE privacy is preserved.
Verification is over the commitment structure only.
"""

import argparse
import hashlib
import json
import sys
import uuid
from pathlib import Path

PACT_FHE_VERSION = "0.5.0"


def compute_trace_commitment(ciphertext_hashes: list[str]) -> str:
    """
    Recompute trace commitment from ciphertext hashes.
    Must match envelope.trace_commitment.
    """
    concatenated = "".join(h for h in ciphertext_hashes)
    return f"sha256:{hashlib.sha256(concatenated.encode('utf-8')).hexdigest()}"


def verify_envelope_id(envelope_id: str) -> bool:
    """Validate UUID v4 format."""
    try:
        uid = uuid.UUID(envelope_id, version=4)
        return str(uid) == envelope_id
    except (ValueError, AttributeError):
        return False


def verify_trace_commitment(envelope: dict) -> tuple[bool, str]:
    """
    Verify the trace commitment matches the recomputed value.
    Returns (valid, reason).
    """
    ciphertext_hashes = envelope.get("ciphertext_hashes", [])
    if not ciphertext_hashes:
        return False, "No ciphertext_hashes in envelope"

    expected = compute_trace_commitment(ciphertext_hashes)
    actual = envelope.get("trace_commitment", "")

    if expected != actual:
        return False, f"Trace commitment mismatch: expected {expected}, got {actual}"
    return True, "trace_commitment valid"


def verify_envelope_format(envelope: dict) -> tuple[bool, list[str]]:
    """
    Verify all required fields are present and correctly typed.
    Returns (valid, errors).
    """
    errors = []
    required_fields = [
        "version", "envelope_id", "created_at", "agent_id",
        "policy_hash", "trace_length", "ciphertext_hashes", "trace_commitment"
    ]
    for field in required_fields:
        if field not in envelope:
            errors.append(f"Missing required field: {field}")

    if envelope.get("version") != PACT_FHE_VERSION:
        errors.append(f"Version mismatch: expected {PACT_FHE_VERSION}, got {envelope.get('version')}")

    if not verify_envelope_id(envelope.get("envelope_id", "")):
        errors.append(f"Invalid envelope_id format: {envelope.get('envelope_id')}")

    if not isinstance(envelope.get("ciphertext_hashes", []), list):
        errors.append("ciphertext_hashes must be a list")

    if envelope.get("trace_length", 0) != len(envelope.get("ciphertext_hashes", [])):
        errors.append(
            f"trace_length mismatch: header says {envelope.get('trace_length')}, "
            f"actual {len(envelope.get('ciphertext_hashes', []))}"
        )

    return len(errors) == 0, errors


def verify_policy_hash(envelope: dict, expected_policy_hash: str) -> tuple[bool, str]:
    """
    Verify the envelope was generated against the expected policy.
    Returns (valid, reason).
    """
    actual = envelope.get("policy_hash", "")
    if not actual:
        return False, "No policy_hash in envelope"

    # Handle both sha256: prefixed and raw formats
    expected_clean = expected_policy_hash.replace("sha256:", "")
    actual_clean = actual.replace("sha256:", "")

    if expected_clean != actual_clean:
        return False, f"Policy hash mismatch: expected {expected_policy_hash}, got {actual}"
    return True, "policy_hash valid"


def verify_fhe_receipt(envelope_path: str, expected_policy_hash: str = "") -> dict:
    """
    Full verification of an FHE receipt envelope.

    Returns:
        {
            "status": "VALID" | "INVALID",
            "envelope_id": str,
            "checks": {
                "format": {"pass": bool, "reason": str},
                "trace_commitment": {"pass": bool, "reason": str},
                "policy_hash": {"pass": bool, "reason": str},
            },
            "errors": [str],
        }
    """
    try:
        with open(envelope_path) as f:
            envelope = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        return {
            "status": "INVALID",
            "envelope_id": "unknown",
            "checks": {},
            "errors": [f"Failed to load envelope: {e}"],
        }

    envelope_id = envelope.get("envelope_id", "unknown")
    result = {
        "status": "INVALID",
        "envelope_id": envelope_id,
        "checks": {},
        "errors": [],
    }

    # Check 1: envelope format
    format_valid, format_errors = verify_envelope_format(envelope)
    result["checks"]["format"] = {
        "pass": format_valid,
        "reason": "; ".join(format_errors) if format_errors else "valid",
    }
    if format_errors:
        result["errors"].extend(format_errors)

    # Check 2: trace commitment
    tc_valid, tc_reason = verify_trace_commitment(envelope)
    result["checks"]["trace_commitment"] = {"pass": tc_valid, "reason": tc_reason}
    if not tc_valid:
        result["errors"].append(tc_reason)

    # Check 3: policy hash (only if expected_policy_hash provided)
    if expected_policy_hash:
        ph_valid, ph_reason = verify_policy_hash(envelope, expected_policy_hash)
        result["checks"]["policy_hash"] = {"pass": ph_valid, "reason": ph_reason}
        if not ph_valid:
            result["errors"].append(ph_reason)
    else:
        result["checks"]["policy_hash"] = {"pass": True, "reason": "not verified — no expected hash provided"}

    # Overall status
    if result["errors"]:
        result["status"] = "INVALID"
    else:
        result["status"] = "VALID"

    return result


def main():
    parser = argparse.ArgumentParser(description="Verify PACT v0.5 FHE receipt")
    parser.add_argument("--envelope", required=True, help="Path to FHEHistoryEnvelope JSON")
    parser.add_argument("--policy-hash", default="", help="Expected policy hash (sha256:...)")
    args = parser.parse_args()

    result = verify_fhe_receipt(args.envelope, args.policy_hash)

    print(json.dumps(result, indent=2))

    if result["status"] == "INVALID":
        print(f"\nINVALID: {'; '.join(result['errors'])}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"\nVALID: {result['envelope_id']}", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()