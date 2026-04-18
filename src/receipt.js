/**
 * PACT v0.1 — Receipt Generation
 * 
 * Generates a PACT Receipt for a tool call.
 * v0.1: SHA-256 hash proof (no ZK). Establishes format.
 * v0.3 target: replace proof with actual ZK membership proof.
 */

import crypto from 'crypto';
import { checkToolCall, verifyPolicyHash } from './policy.js';

/**
 * Generate a PACT Receipt for a tool call.
 * @param {object} opts
 * @param {object} opts.policy - Full policy document (with policy_hash)
 * @param {string} opts.toolName - The tool being called
 * @param {object} [opts.params] - Tool parameters (hashed, not stored)
 * @returns {{ receipt: object, permitted: boolean, reason: string }}
 */
export function generateReceipt({ policy, toolName, params = {} }) {
  // Verify policy integrity first
  const hashCheck = verifyPolicyHash(policy);
  if (!hashCheck.valid) {
    throw new Error(`Policy hash mismatch: expected ${hashCheck.expected}, got ${hashCheck.got}`);
  }

  // Check if tool call is within policy
  const { permitted, reason } = checkToolCall(policy, toolName, params);

  // Hash the params (we prove params were hashed, not stored — privacy)
  const paramsHash = `sha256:${crypto.createHash('sha256').update(JSON.stringify(params), 'utf8').digest('hex')}`;

  const receipt = {
    receipt_version: '0.1.0',
    agent_id: policy.agent_id,
    policy_hash: policy.policy_hash,
    action_id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    tool_called: toolName,
    params_hash: paramsHash,
    outcome: permitted ? 'permitted' : 'denied',
    outcome_reason: reason,
    proof: {
      type: 'sha256_membership', // v0.1: hash proof. v0.3: zk_membership
      statement: permitted
        ? `tool_called ∈ policy.allowed_tools AND NOT IN policy.denied_tools`
        : `tool_called ∉ permitted set`,
      policy_hash: policy.policy_hash,
      // v0.1: proof is the deterministic hash of (policy_hash + tool_called)
      // This is verifiable but not zero-knowledge — ZK comes in v0.3
      proof_hash: `sha256:${crypto.createHash('sha256')
        .update(`${policy.policy_hash}:${toolName}:${permitted}`, 'utf8')
        .digest('hex')}`,
    },
  };

  return { receipt, permitted, reason };
}

/**
 * Verify a PACT Receipt.
 * @param {object} receipt - PACT Receipt object
 * @param {object} policy - The policy document the receipt claims to be against
 * @returns {{ valid: boolean, reason: string }}
 */
export function verifyReceipt(receipt, policy) {
  // Check receipt references the right policy
  if (receipt.policy_hash !== policy.policy_hash) {
    return { valid: false, reason: 'policy_hash mismatch' };
  }

  // Verify proof hash
  const expected = `sha256:${crypto.createHash('sha256')
    .update(`${policy.policy_hash}:${receipt.tool_called}:${receipt.outcome === 'permitted'}`, 'utf8')
    .digest('hex')}`;

  if (receipt.proof.proof_hash !== expected) {
    return { valid: false, reason: 'proof_hash invalid' };
  }

  // Re-check tool membership
  const { permitted } = checkToolCall(policy, receipt.tool_called);
  if (permitted !== (receipt.outcome === 'permitted')) {
    return { valid: false, reason: 'outcome does not match policy re-evaluation' };
  }

  return { valid: true, reason: 'receipt valid' };
}
