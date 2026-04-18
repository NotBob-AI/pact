/**
 * PACT v0.1 — Policy Commitment
 * 
 * Creates and verifies a Policy Document with SHA-256 hash anchoring.
 * No ZK yet — this establishes the format and commitment mechanism.
 */

import crypto from 'crypto';

/**
 * Create a PACT Policy Document.
 * @param {object} opts
 * @param {string} opts.agentId - DID or identifier for this agent
 * @param {string[]} opts.allowedTools - Tool names this agent may call
 * @param {string[]} opts.deniedTools - Tool names explicitly forbidden
 * @param {object} opts.scopeConstraints - Optional scope limits
 * @param {object} opts.escalationPolicy - What to do on violation
 * @returns {{ policy: object, hash: string }}
 */
export function createPolicy({ agentId, allowedTools, deniedTools = [], scopeConstraints = {}, escalationPolicy = {} }) {
  if (!agentId) throw new Error('agentId is required');
  if (!allowedTools || !Array.isArray(allowedTools)) throw new Error('allowedTools must be an array');

  const policy = {
    pact_version: '0.1.0',
    agent_id: agentId,
    created_at: new Date().toISOString(),
    policy: {
      allowed_tools: allowedTools.sort(), // sorted for deterministic hashing
      denied_tools: deniedTools.sort(),
      scope_constraints: scopeConstraints,
      escalation_policy: {
        on_constraint_violation: 'abort_and_log',
        ...escalationPolicy,
      },
    },
  };

  const hash = hashPolicy(policy);
  policy.policy_hash = `sha256:${hash}`;

  return { policy, hash };
}

/**
 * Compute the canonical SHA-256 hash of a policy document.
 * The hash is computed over the policy fields only (excluding policy_hash itself).
 */
export function hashPolicy(policy) {
  const { policy_hash, ...rest } = policy; // exclude existing hash if present
  const canonical = JSON.stringify(rest, Object.keys(rest).sort()); // deterministic key order
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Verify that a policy document's hash matches its contents.
 * @param {object} policy - Full policy document including policy_hash
 * @returns {{ valid: boolean, expected: string, got: string }}
 */
export function verifyPolicyHash(policy) {
  if (!policy.policy_hash) return { valid: false, expected: null, got: null };
  const got = `sha256:${hashPolicy(policy)}`;
  const expected = policy.policy_hash;
  return { valid: got === expected, expected, got };
}

/**
 * Check whether a given tool call is permitted by the policy.
 * @param {object} policy - Full policy document
 * @param {string} toolName - The tool being called
 * @param {object} [params] - Tool parameters (for future scope constraint checking)
 * @returns {{ permitted: boolean, reason: string }}
 */
export function checkToolCall(policy, toolName, params = {}) {
  const { allowed_tools, denied_tools } = policy.policy;

  if (denied_tools.includes(toolName)) {
    return { permitted: false, reason: `tool '${toolName}' is explicitly denied` };
  }

  if (!allowed_tools.includes(toolName)) {
    return { permitted: false, reason: `tool '${toolName}' is not in allowed_tools` };
  }

  // TODO v0.2: check scope_constraints against params

  return { permitted: true, reason: 'within policy' };
}
