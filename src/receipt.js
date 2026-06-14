/**
 * PACT v0.1 — Receipt Generation
 * 
 * Generates a PACT Receipt for a tool call.
 * v0.1: SHA-256 hash proof (no ZK). Establishes format.
 * v0.3 target: replace proof with actual ZK membership proof.
 * 
 * MCP Transport Binding (v0.1 extended):
 * When mcp_binding is provided, the receipt proves it was generated
 * at the MCP transport layer before the tool executes. This composes with
 * zk-MCP (arxiv 2512.14737) which provides ZK verification of MCP message
 * structure — together, PACT receipt (what was authorized) + zk-MCP proof
 * (what was transmitted) form a complete bilateral accountability chain.
 * See: https://github.com/NousResearch/hermes-agent/issues/487 for
 * independent convergence on hash-chained action logs for agents.
 */

import crypto from 'crypto';
import { checkToolCall, verifyPolicyHash } from './policy.js';

/**
 * Generate a PACT Receipt for a tool call.
 * @param {object} opts
 * @param {object} opts.policy - Full policy document (with policy_hash)
 * @param {string} opts.toolName - The tool being called
 * @param {object} [opts.params] - Tool parameters (hashed, not stored)
 * @param {object} [opts.mcp_binding] - MCP transport binding fields:
 *   - mcp_message_id: The MCP message ID for this call (from MCP transport layer)
 *   - mcp_server_id: Which MCP server this call targets
 *   - mcp_transport: Transport type ('stdio'|'sse'|'http')
 * @returns {{ receipt: object, permitted: boolean, reason: string }}
 */
export function generateReceipt({ policy, toolName, params = {}, mcp_binding = null }) {
  // Verify policy integrity first
  const hashCheck = verifyPolicyHash(policy);
  if (!hashCheck.valid) {
    throw new Error(`Policy hash mismatch: expected ${hashCheck.expected}, got ${hashCheck.got}`);
  }

  // Check if tool call is within policy
  const { permitted, reason } = checkToolCall(policy, toolName, params);

  // Hash the params (we prove params were hashed, not stored — privacy)
  const paramsHash = `sha256:${crypto.createHash('sha256').update(JSON.stringify(params), 'utf8').digest('hex')}`;

  // MCP transport binding: binds this receipt to the MCP transport layer
  // This proves the receipt was generated at execution time, not retroactively.
  // Compose with zk-MCP (arxiv 2512.14737) for ZK verification of MCP message structure.
  let mcp_binding_header = null;
  if (mcp_binding) {
    mcp_binding_header = {
      mcp_message_id: mcp_binding.mcp_message_id,
      mcp_server_id: mcp_binding.mcp_server_id,
      mcp_transport: mcp_binding.mcp_transport || 'stdio',
      mcp_receipt_hash: `sha256:${crypto.createHash('sha256')
        .update(`${mcp_binding.mcp_message_id || 'unknown'}:${mcp_binding.mcp_server_id || 'unknown'}:${policy.policy_hash}`, 'utf8')
        .digest('hex')}`,
    };
  }

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
    // MCP transport binding: proves this receipt was bound to an MCP message
    // at execution time, not retroactively generated. The mcp_receipt_hash
    // provides a verifiable link to the MCP message that triggered this action.
    mcp_binding: mcp_binding_header,
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
