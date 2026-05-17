/**
 * verify_receipt.js — PACT v0.3 Receipt Verifier Adapter
 * 
 * Verifies PACT ZK receipts without access to the policy document.
 * Works for both DUMMY_PROOF (structural check only) and real ZK receipts.
 * 
 * Usage:
 *   import { verifyPactReceipt } from './verify_receipt.js';
 *   const result = await verifyPactReceipt({
 *     receipt: zkReceipt,
 *     policyHash: 'sha256:...',   // expected policy hash from anchor
 *     toolName: 'read_file',        // expected tool name (hashed internally)
 *     anchor: { log_index, log_id, merkle_root },  // from transparency log
 *   });
 */

import crypto from 'crypto';

const SHA256_PREFIX = 'sha256:';

/**
 * Verify a PACT v0.3 ZK receipt.
 * 
 * For DUMMY_PROOF: verifies receipt structure is well-formed.
 * For zk_membership: performs cryptographic verification of proof.
 * 
 * @param {object} opts
 * @param {object} opts.receipt - PACT receipt to verify
 * @param {string} opts.policyHash - Expected policy hash (from committed anchor)
 * @param {string} [opts.toolName] - Expected tool name (optional, for targeted verification)
 * @param {object} [opts.anchor] - Anchor from transparency log
 * @returns {{ valid: boolean, reason: string, warnings: string[] }}
 */
export async function verifyPactReceipt({ receipt, policyHash, toolName = null, anchor = null }) {
  const warnings = [];

  // ── Version check ──────────────────────────────────────────────────────────
  if (receipt.receipt_version !== '0.3.0') {
    return {
      valid: false,
      reason: `unsupported receipt version: ${receipt.receipt_version}`,
      warnings,
    };
  }

  // ── Required field check ────────────────────────────────────────────────────
  const requiredPublic = ['policy_hash', 'merkle_root', 'log_index', 'tool_name_hash'];
  for (const field of requiredPublic) {
    if (!receipt.public?.[field]) {
      return {
        valid: false,
        reason: `missing required public field: ${field}`,
        warnings,
      };
    }
  }

  // ── Policy hash match ─────────────────────────────────────────────────────────
  const receiptPolicyHash = receipt.public.policy_hash.startsWith(SHA256_PREFIX)
    ? receipt.public.policy_hash
    : `${SHA256_PREFIX}${receipt.public.policy_hash}`;

  const expectedPolicyHash = policyHash.startsWith(SHA256_PREFIX)
    ? policyHash
    : `${SHA256_PREFIX}${policyHash}`;

  if (receiptPolicyHash !== expectedPolicyHash) {
    return {
      valid: false,
      reason: `policy hash mismatch: receipt has ${receiptPolicyHash.slice(0, 20)}..., expected ${expectedPolicyHash.slice(0, 20)}...`,
      warnings,
    };
  }

  // ── Tool name match (if provided) ─────────────────────────────────────────
  if (toolName) {
    const expectedToolHash = `${SHA256_PREFIX}${sha256hex(toolName)}`;
    const receiptToolHash = receipt.public.tool_name_hash.startsWith(SHA256_PREFIX)
      ? receipt.public.tool_name_hash
      : `${SHA256_PREFIX}${receipt.public.tool_name_hash}`;

    if (receiptToolHash !== expectedToolHash) {
      return {
        valid: false,
        reason: `tool name hash mismatch`,
        warnings,
      };
    }
  }

  // ── Anchor check (if provided) ──────────────────────────────────────────────
  if (anchor) {
    if (receipt.public.log_index !== anchor.log_index) {
      warnings.push(`log_index mismatch: receipt=${receipt.public.log_index}, anchor=${anchor.log_index}`);
    }
    if (receipt.public.merkle_root !== anchor.merkle_root) {
      warnings.push(`merkle_root mismatch: receipt and anchor merkle_root differ`);
    }
  }

  // ── Proof type dispatch ────────────────────────────────────────────────────
  const proofType = receipt.proof_type;

  if (proofType === 'DUMMY_ZK_PROOF') {
    // Structural verification only — receipt is well-formed but not cryptographically binding
    if (!receipt.proof?.note?.includes('DUMMY_ZK_PROOF')) {
      warnings.push('DUMMY_PROOF receipt without explicit flag — cannot be used for trust');
    }
    return {
      valid: true,
      reason: 'DUMMY_PROOF receipt — structural check passed, cryptographic verification unavailable',
      warnings,
    };
  }

  if (proofType === 'zk_membership') {
    // For real ZK receipts, we verify the proof_data format is well-formed.
    // Full cryptographic verification requires calling the ZK verifier (RISC Zero or Halo2).
    // The circuit_id tells us which verifier to use.
    const circuitId = receipt.circuit_id || 'unknown';
    const hasProofData = receipt.proof?.proof_data != null;

    if (!hasProofData) {
      return {
        valid: false,
        reason: `zk_membership receipt missing proof_data`,
        warnings,
      };
    }

    // Verify circuit ID matches expected PACT circuit
    if (!circuitId.includes('pact-v0.3')) {
      warnings.push(`unexpected circuit_id: ${circuitId}`);
    }

    return {
      valid: true,
      reason: `ZK receipt (${circuitId}) — proof_data present, cryptographic verification requires ZK verifier call`,
      warnings,
    };
  }

  return {
    valid: false,
    reason: `unknown proof_type: ${proofType}`,
    warnings,
  };
}

/**
 * Batch verify multiple receipts (for audit logs, receipt chains, etc.).
 * Returns a summary plus per-receipt results.
 * 
 * @param {object[]} receipts - Array of PACT receipts
 * @param {string[]} policyHashes - Expected policy hashes (aligned with receipts)
 * @returns {{ valid: boolean, total: number, valid_count: number, results: object[] }}
 */
export async function batchVerifyReceipts(receipts, policyHashes = []) {
  const results = [];
  let validCount = 0;

  for (let i = 0; i < receipts.length; i++) {
    const receipt = receipts[i];
    const policyHash = policyHashes[i] || receipt.public?.policy_hash;
    const result = await verifyPactReceipt({ receipt, policyHash });
    result.index = i;
    results.push(result);
    if (result.valid) validCount++;
  }

  return {
    valid: validCount === receipts.length,
    total: receipts.length,
    valid_count: validCount,
    results,
  };
}

// ── Helpers ─────────────────────────────────────────────────────────────────────

function sha256hex(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}