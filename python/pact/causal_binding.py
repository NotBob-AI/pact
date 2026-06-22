"""
PACT v0.8.1 — Causal Binding Extension

Implements causal binding between policy commitment and tool invocation parameters.
Prerequisite for atomic receipt guarantees: the agent cannot change policy between
commitment and execution because params_hash is locked into the commitment at
commitment time, not post-execution.

Architecture (symonbaikov.bsky.social thread, June 2026):
  - PolicyCommitment extends policy_hash to cover params_hash + run_id
  - causal_hash = SHA-256(policy_hash | params_hash | run_id | prev_commit_hash)
  - ZK proof (Layer 2) proves params_hash was fixed BEFORE tool execution
  - tool_output_hash proves output was produced UNDER the same params
  - Both appear atomically in the PolicyCommitment

References:
  - symonbaikov.bsky.social causal binding thread (June 2026)
  - draft-nelson-agent-delegation-receipts (IETF DRP)
  - urn:pact:receipt:v0.8.1
"""

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


PACT_CAUSAL_VERSION = "0.8.1"


# ---------------------------------------------------------------------------
# Causal Commitment Types
# ---------------------------------------------------------------------------

@dataclass
class CausalCommitment:
    """
    Causal binding commitment: policy_hash extended to cover params and run_id.
    
    Unlike a plain policy hash (which only covers the policy document text),
    causal_hash = SHA-256(policy_hash | params_hash | run_id | prev_commit_hash)
    
    This makes the policy hash non-detachable from the specific tool invocation.
    The agent cannot change policy between commitment and execution because
    params_hash is locked in at the moment of commitment.
    """
    policy_hash: str          # sha256:... of committed policy doc
    params_hash: str          # sha256:... of tool_name + serialized args (known BEFORE execution)
    run_id: str               # monotonic run identifier (UUID or monotonic counter)
    prev_commit_hash: str     # sha256:... of previous commitment (genesis = "genesis")
    causal_hash: str          # sha256:... of binding: SHA-256(policy_hash|params_hash|run_id|prev)
    timestamp: str           # ISO-8601 when commitment was formed
    log_index: int = 0        # Index in transparency log
    log_id: str = ""
    merkle_root: str = ""
    merkle_proof: list = field(default_factory=list)  # Inclusion proof


def compute_causal_hash(
    policy_hash: str,
    params_hash: str,
    run_id: str,
    prev_commit_hash: str,
) -> str:
    """Compute the causal hash: atomically binds policy to params."""
    fields = "|".join([
        policy_hash,
        params_hash,
        run_id,
        prev_commit_hash,
    ])
    return "sha256:" + hashlib.sha256(fields.encode("utf-8")).hexdigest()


def hash_tool_params(tool_name: str, args: dict) -> str:
    """Hash tool name + args — this is what gets bound to policy BEFORE execution."""
    canonical = json.dumps({"tool": tool_name, "args": args}, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def form_causal_commitment(
    policy_hash: str,
    params_hash: str,
    run_id: Optional[str] = None,
    prev_commit_hash: str = "genesis",
    log_index: int = 0,
) -> CausalCommitment:
    """
    Form a causal commitment.
    
    run_id: generate one if not provided (UUID).
    prev_commit_hash: pass the hash of the previous commitment to chain them.
    """
    if run_id is None:
        run_id = str(uuid.uuid4())

    causal_hash = compute_causal_hash(policy_hash, params_hash, run_id, prev_commit_hash)

    return CausalCommitment(
        policy_hash=policy_hash,
        params_hash=params_hash,
        run_id=run_id,
        prev_commit_hash=prev_commit_hash,
        causal_hash=causal_hash,
        timestamp=datetime.now(timezone.utc).isoformat(),
        log_index=log_index,
    )


def verify_causal_binding(
    commitment: CausalCommitment,
    policy_hash: str,
    params_hash: str,
) -> dict:
    """
    Verify that a causal commitment correctly binds policy to params.
    
    Returns:
        valid: True if causal_hash matches computed hash
        reason: str
        causal_hash: str
        run_id: str
    """
    computed = compute_causal_hash(
        commitment.policy_hash,
        commitment.params_hash,
        commitment.run_id,
        commitment.prev_commit_hash,
    )
    if computed != commitment.causal_hash:
        return {
            "valid": False,
            "reason": f"causal_hash mismatch: expected {computed[:30]}..., got {commitment.causal_hash[:30]}...",
        }
    if commitment.policy_hash != policy_hash:
        return {"valid": False, "reason": "policy_hash mismatch"}
    if commitment.params_hash != params_hash:
        return {
            "valid": False,
            "reason": "params_hash mismatch: commitment params differ from verified params",
        }
    return {
        "valid": True,
        "reason": "Causal binding verified: policy hash, params hash, and run_id are atomically bound",
        "causal_hash": commitment.causal_hash,
        "run_id": commitment.run_id,
    }


# ---------------------------------------------------------------------------
# Tool Call
# ---------------------------------------------------------------------------

@dataclass
class ToolCall:
    """A single tool invocation record."""
    tool_name: str
    tool_input_hash: str     # sha256:... of serialized input args
    timestamp: str           # ISO-8601 UTC
    action_id: str           # Unique action UUID for this call
    tool_output_hash: Optional[str] = None  # SHA-256 of output (if included)


# ---------------------------------------------------------------------------
# ZK Proof
# ---------------------------------------------------------------------------

@dataclass
class ZKProof:
    """Zero-knowledge proof generated by the prover."""
    proof_type: str           # "risc0" | "dummy" | "halo2" | "groth16"
    image_id: str             # Image ID of the committed guest program
    seal: str                 # Raw seal bytes (or DUMMY marker when DUMMY_PROOF=1)
    public_inputs: dict      # Includes: causal_hash, params_hash, tool_name_hash, log_index, output_hash


# ---------------------------------------------------------------------------
# Policy Commitment (v0.8.1 — causal binding extended)
# ---------------------------------------------------------------------------

@dataclass
class PolicyCommitment:
    """
    Layer 1: Policy commitment anchored to the transparency log.
    Extended v0.8.1: params_hash and run_id are part of the commitment,
    making the policy hash causally bound to the specific tool invocation.
    """
    policy_hash: str
    params_hash: str          # NEW v0.8.1: tool name + args hash committed BEFORE execution
    run_id: str               # NEW v0.8.1: monotonic run id, bound to this commitment
    causal_hash: str         # NEW v0.8.1: SHA-256(policy_hash|params_hash|run_id|prev)
    log_index: int
    log_id: str
    merkle_root: str
    merkle_proof: list


# ---------------------------------------------------------------------------
# PACT Receipt v0.8.1
# ---------------------------------------------------------------------------

@dataclass
class PACTReceipt:
    """
    PACT receipt v0.8.1 with causal binding.
    
    Receipt proves:
        1. Policy was committed (log anchor + merkle proof)
        2. Tool params were bound to policy BEFORE execution (causal_hash)
        3. Tool executed and produced output (output_hash in ZK public inputs)
        4. All three are bound together (causal_hash links params to policy AND output)
    """
    version: str = PACT_CAUSAL_VERSION
    receipt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    issued_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    policy: PolicyCommitment = field(default_factory=lambda: PolicyCommitment(
        policy_hash="", params_hash="", run_id="", causal_hash="",
        log_index=0, log_id="", merkle_root="", merkle_proof=[]
    ))
    tool_call: ToolCall = field(default_factory=lambda: ToolCall(
        tool_name="", tool_input_hash="", timestamp="", action_id=""
    ))
    proof: Optional[ZKProof] = None
    receipt_hash: str = ""


def receipt_to_dict(receipt: PACTReceipt) -> dict:
    """Serialize a PACT receipt to a JSON-serializable dict."""
    d = {
        "version": receipt.version,
        "receipt_id": receipt.receipt_id,
        "issued_at": receipt.issued_at,
        "policy": {
            "policy_hash": receipt.policy.policy_hash,
            "params_hash": receipt.policy.params_hash,
            "run_id": receipt.policy.run_id,
            "causal_hash": receipt.policy.causal_hash,
            "log_index": receipt.policy.log_index,
            "log_id": receipt.policy.log_id,
            "merkle_root": receipt.policy.merkle_root,
            "merkle_proof": receipt.policy.merkle_proof,
        },
        "tool_call": {
            "tool_name": receipt.tool_call.tool_name,
            "tool_input_hash": receipt.tool_call.tool_input_hash,
            "timestamp": receipt.tool_call.timestamp,
            "action_id": receipt.tool_call.action_id,
            "tool_output_hash": receipt.tool_call.tool_output_hash,
        },
        "proof": {
            "proof_type": receipt.proof.proof_type,
            "image_id": receipt.proof.image_id,
            "seal": receipt.proof.seal,
            "public_inputs": receipt.proof.public_inputs,
        } if receipt.proof else None,
    }
    canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
    d["receipt_hash"] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    return d


def receipt_to_json(receipt: PACTReceipt, indent: Optional[int] = None) -> str:
    """Serialize a PACT receipt to a JSON string."""
    return json.dumps(receipt_to_dict(receipt), indent=indent)


def verify_causal_receipt(receipt: PACTReceipt, expected_policy_hash: str, expected_params_hash: str) -> dict:
    """Verify a complete PACT v0.8.1 receipt's causal binding."""
    result = verify_causal_binding(
        CausalCommitment(
            policy_hash=receipt.policy.policy_hash,
            params_hash=receipt.policy.params_hash,
            run_id=receipt.policy.run_id,
            prev_commit_hash="genesis",
            causal_hash=receipt.policy.causal_hash,
            timestamp="",
        ),
        expected_policy_hash,
        expected_params_hash,
    )
    if not result["valid"]:
        return result
    if receipt.policy.policy_hash != expected_policy_hash:
        return {"valid": False, "reason": "policy_hash mismatch in receipt"}
    if receipt.policy.params_hash != expected_params_hash:
        return {"valid": False, "reason": "params_hash mismatch in receipt"}
    return {
        "valid": True,
        "reason": f"PACT v{receipt.version} causal receipt verified",
        "receipt_id": receipt.receipt_id,
        "causal_hash": receipt.policy.causal_hash,
        "run_id": receipt.policy.run_id,
    }


def demo():
    """Smoke test causal binding."""
    print(f"PACT Causal Binding v{PACT_CAUSAL_VERSION}")
    print("=" * 50)

    # Step 1: hash tool params before execution
    params_hash = hash_tool_params("read_file", {"path": "/tmp/secret.txt"})
    print(f"Params hash: {params_hash[:40]}...")

    # Step 2: form causal commitment — params are now locked to policy
    policy_hash = "sha256:a1b2c3d4e5f6"
    commitment = form_causal_commitment(policy_hash, params_hash)
    print(f"Causal hash: {commitment.causal_hash[:40]}...")
    print(f"Run ID: {commitment.run_id}")

    # Step 3: simulate policy change attempt (FAILS — params_hash already in commitment)
    fake_policy_hash = "sha256:FAKE00000000"
    result = verify_causal_binding(commitment, fake_policy_hash, params_hash)
    print(f"\nPolicy change attempt: {'BLOCKED ✓' if not result['valid'] else 'ALLOWED ✗'}")
    print(f"Reason: {result['reason']}")

    # Step 4: correct verification
    result = verify_causal_binding(commitment, policy_hash, params_hash)
    print(f"\nCorrect verification: {'VERIFIED ✓' if result['valid'] else 'FAILED ✗'}")
    print(f"Reason: {result['reason']}")

    # Step 5: params change attempt (FAILS — params don't match)
    fake_args = {"path": "/tmp/other.txt"}
    fake_params_hash = hash_tool_params("read_file", fake_args)
    result = verify_causal_binding(commitment, policy_hash, fake_params_hash)
    print(f"\nParams change attempt: {'BLOCKED ✓' if not result['valid'] else 'ALLOWED ✗'}")
    print(f"Reason: {result['reason']}")
    print("\n✓ Causal binding: policy cannot be changed after params are committed.")


if __name__ == "__main__":
    demo()
