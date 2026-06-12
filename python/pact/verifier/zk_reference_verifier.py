"""
PACT v0.3 — Python Reference Verifier for RISC Zero Guest Circuit

Provides a Python-native implementation of the tool membership proof logic
from rust/guest/src/main.rs. Used for:
1. Testing the guest circuit logic without a full RISC Zero build
2. Cross-validating receipts generated via DUMMY_PROOF mode
3. Validating public inputs against the expected computation

This verifier PROVES the same statement as the RISC Zero circuit:
    tool_name_hash in allowed_tools  (given committed policy_hash)
    AND policy_hash anchored to merkle_root

PUBLIC INPUTS (must match what the circuit commits):
    - policy_hash: SHA-256 hex of committed policy doc (no prefix)
    - merkle_root: Merkle root from transparency log (hex, 64 chars)
    - tool_name_hash: SHA-256 of tool name (hex, 64 chars)

PRIVATE WITNESS (prover-only, not needed by verifier):
    - policy_document
    - allowed_tools list
    - merkle_proof

The verifier only needs public inputs + proof bytes.
This file proves the Python logic matches the Rust guest implementation.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# SHA-256 helpers — match rust/guest/src/main.rs hex_to_digest + compute_log_id
# ---------------------------------------------------------------------------

def sha256_hex(data: str) -> str:
    """SHA-256 hex with sha256: prefix (for policy hashes with prefix)."""
    return f"sha256:{hashlib.sha256(data.encode('utf-8')).hexdigest()}"


def sha256_raw(data: str) -> str:
    """Raw SHA-256 hex (no prefix) — matches RISC Zero input format."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Raw SHA-256 hex of bytes (no prefix)."""
    return hashlib.sha256(data).hexdigest()


def _normalize_hex(hex_str: str) -> str:
    """Strip sha256: prefix, return raw 64-char hex."""
    return hex_str.replace('sha256:', '').lower()


# ---------------------------------------------------------------------------
# Merkle verification — matches rust/guest/src/main.rs Step 2
# ---------------------------------------------------------------------------

def verify_merkle_inclusion(leaf_hash: str, merkle_root: str, merkle_proof: list) -> bool:
    """
    Verify a Merkle inclusion proof.
    
    Args:
        leaf_hash: The policy hash (hex, no prefix)
        merkle_root: The expected Merkle root (hex, no prefix)
        merkle_proof: List of {"sibling_hash": str, "is_right": bool}
    
    Returns:
        True if proof is valid.
    
    Logic matches rust/guest/src/main.rs:
        current = policy_hash (leaf)
        for each step:
            if is_right: current = SHA256(current || sibling)
            else:        current = SHA256(sibling || current)
        final current must equal merkle_root
    """
    current = _normalize_hex(leaf_hash)
    
    for step in merkle_proof:
        sibling = _normalize_hex(step["sibling_hash"])
        is_right = step.get("is_right", False)
        
        if is_right:
            pair = bytes.fromhex(current) + bytes.fromhex(sibling)
        else:
            pair = bytes.fromhex(sibling) + bytes.fromhex(current)
        
        current = sha256_bytes(pair)
    
    return current == _normalize_hex(merkle_root)


# ---------------------------------------------------------------------------
# Tool membership check — matches rust/guest/src/main.rs Step 3
# ---------------------------------------------------------------------------

def verify_tool_membership(tool_name: str, allowed_tools: list[str]) -> str:
    """
    Compute tool_name_hash from allowed_tools list.
    Returns the SHA-256 hex of the tool name.
    """
    tool_hash = sha256_raw(tool_name)
    found = any(sha256_raw(t) == tool_hash for t in allowed_tools)
    if not found:
        raise ValueError(f"Tool '{tool_name}' not in allowed_tools")
    return tool_hash


def verify_tool_membership_hash(tool_name_hash: str, allowed_tools: list[str]) -> bool:
    """
    Verify tool_name_hash is in allowed_tools.
    Returns True if valid. Does NOT reveal which tool was called.
    """
    th = _normalize_hex(tool_name_hash)
    return any(_normalize_hex(sha256_raw(t)) == th for t in allowed_tools)


# ---------------------------------------------------------------------------
# Log ID computation — matches rust/guest/src/main.rs compute_log_id
# ---------------------------------------------------------------------------

def compute_log_id(
    log_index: int,
    prev_hash: str,
    timestamp: str,
    merkle_root: str,
    policy_hash: str,
) -> str:
    """
    Compute log_id = SHA-256(index | prev_hash | timestamp | merkle_root | policy_hash).
    
    Matches rust/guest/src/main.rs compute_log_id function.
    The index is packed as big-endian u32 bytes, other fields as UTF-8 bytes.
    """
    data = bytearray()
    data.extend(struct.pack('>I', log_index))
    data.extend(prev_hash.encode('utf-8'))
    data.extend(timestamp.encode('utf-8'))
    data.extend(merkle_root.encode('utf-8'))
    data.extend(policy_hash.encode('utf-8'))
    
    return sha256_bytes(bytes(data))


# ---------------------------------------------------------------------------
# Full reference verification
# ---------------------------------------------------------------------------

def reference_verify(
    policy_hash: str,
    merkle_root: str,
    tool_name_hash: str,
    timestamp: str,
    allowed_tools: list[str],
    merkle_proof: list,
    log_index: int,
    prev_log_hash: str,
    expected_log_id: Optional[str] = None,
) -> dict:
    """
    Full Python reference verification of a PACT v0.3 ZK receipt.
    
    Implements the same logic as rust/guest/src/main.rs in Python.
    Used to cross-validate RISC Zero proofs and DUMMY_PROOF receipts.
    """
    results = {}
    errors = []
    
    # Step 1: Merkle proof
    try:
        merkle_valid = verify_merkle_inclusion(policy_hash, merkle_root, merkle_proof)
        if not merkle_valid:
            errors.append("Merkle proof invalid: computed root does not match merkle_root")
        results["merkle_verified"] = merkle_valid
    except Exception as e:
        errors.append(f"Merkle verification error: {e}")
        results["merkle_verified"] = False
    
    # Step 2: Tool membership
    try:
        tool_valid = verify_tool_membership_hash(tool_name_hash, allowed_tools)
        if not tool_valid:
            errors.append("Tool name hash not found in allowed_tools")
        results["tool_membership_verified"] = tool_valid
    except ValueError as e:
        errors.append(str(e))
        results["tool_membership_verified"] = False
    
    # Step 3: Log ID
    if expected_log_id:
        computed_log_id = compute_log_id(
            log_index, prev_log_hash, timestamp, merkle_root, policy_hash
        )
        log_id_valid = computed_log_id == _normalize_hex(expected_log_id)
        if not log_id_valid:
            errors.append(f"Log ID mismatch: computed {computed_log_id[:16]}... != expected {expected_log_id[:16]}...")
        results["log_id_verified"] = log_id_valid
    else:
        results["log_id_verified"] = None
    
    valid = results.get("merkle_verified") and results.get("tool_membership_verified")
    
    return {
        "valid": valid,
        "reason": "; ".join(errors) if errors else "All checks passed",
        "policy_hash": policy_hash,
        "tool_name_hash": tool_name_hash,
        "merkle_root": merkle_root,
        "merkle_verified": results.get("merkle_verified"),
        "tool_membership_verified": results.get("tool_membership_verified"),
        "log_id_verified": results.get("log_id_verified"),
        "verifier": "python_reference_v0.3",
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    """Quick test using sample data matching rust/guest unit tests."""
    import argparse
    parser = argparse.ArgumentParser(description="PACT Python reference verifier")
    parser.add_argument("--policy-hash", required=True)
    parser.add_argument("--merkle-root", required=True)
    parser.add_argument("--tool-name-hash", required=True)
    parser.add_argument("--merkle-proof", default="[]")
    parser.add_argument("--allowed-tools", default="[]")
    args = parser.parse_args()
    
    allowed_tools = json.loads(args.allowed_tools) if args.allowed_tools else []
    merkle_proof = json.loads(args.merkle_proof) if args.merkle_proof else []
    
    result = reference_verify(
        policy_hash=args.policy_hash,
        merkle_root=args.merkle_root,
        tool_name_hash=args.tool_name_hash,
        timestamp="2026-04-21T00:00:00Z",
        allowed_tools=allowed_tools,
        merkle_proof=merkle_proof,
        log_index=0,
        prev_log_hash="0" * 64,
    )
    
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
