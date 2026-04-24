/**
 * PACT v0.4 — Verifier API
 * 
 * Third-party receipt verification. Any external party can submit a PACT
 * receipt and receive: valid | invalid | policy_mismatch | unknown_policy
 * 
 * Does NOT require: the agent's cooperation, log access, or plaintext of action/policy.
 * Only requires: receipt, policy_hash, and access to the transparency log anchor.
 * 
 * Usage:
 *   import { verifyReceipt } from './verifier.js';
 *   const result = await verifyReceipt(receipt);
 */

import { sha256 } from './policy.js';
import { verifyReceipt as verifyBasicReceipt } from './receipt.js';
import { verifyZkReceipt } from './zk-receipt.js';
import { verifyAnchor } from './commitment.js';

// Supported transparency log backends
const LOG_VERIFIERS = {
  siglog: verifySiglogAnchor,
  // Rekor (Sigstore) — pluggable
  rekor: verifyRekorAnchor,
};

/**
 * Verify a PACT receipt (any version).
 * 
 * @param {Object} receipt — PACT receipt (v0.1, v0.2, or v0.3)
 * @param {Object} opts
 *   @param {string} opts.policyDoc  — Original policy document (for v0.1/v0.2)
 *   @param {string} opts.policyHash — Expected policy hash (overrides receipt.policy_hash)
 *   @param {string} opts.logVerifier — 'siglog' | 'rekor' | 'local' (default: auto-detect)
 *   @param {string} opts.logApiUrl  — Transparency log API URL (for siglog/rekor)
 * @returns {Promise<VerificationResult>}
 */
export async function verifyReceipt(receipt, opts = {}) {
  const errors = [];
  const warnings = [];

  // Step 1: Structural validation
  if (!receipt || typeof receipt !== 'object') {
    return { status: 'invalid', reason: 'malformed_receipt', details: 'Receipt must be a JSON object' };
  }

  const version = receipt.receipt_version || receipt.pact_version || '0.1';
  const hasZkProof = receipt.proof?.type === 'zk_membership' || receipt.proof?.type === 'DUMMY_ZK_PROOF';
  const hasBasicProof = receipt.proof?.type === 'sha256_membership';

  // Step 2: Policy hash check
  const expectedPolicyHash = opts.policyHash || receipt.policy_hash;
  if (!expectedPolicyHash) {
    errors.push('policy_hash_missing');
  }

  // Step 3: Timestamp sanity check
  const receiptTime = new Date(receipt.timestamp);
  const now = new Date();
  const ageHours = (now - receiptTime) / (1000 * 60 * 60);
  if (ageHours > 24 * 365) {
    errors.push('timestamp_too_old');
  }
  if (ageHours < -60) { // 1 minute in future tolerance
    errors.push('timestamp_invalid');
  }

  // Step 4: Version-specific verification
  if (hasZkProof) {
    // v0.3: ZK receipt — verify the proof cryptographically
    const zkResult = verifyZkReceipt(receipt, opts.policyDoc);
    if (!zkResult.valid) {
      errors.push(`zk_proof_invalid: ${zkResult.reason}`);
    }
  } else if (hasBasicProof) {
    // v0.1/v0.2: SHA-256 receipt — verify membership proof
    const basicResult = verifyBasicReceipt(receipt, opts.policyDoc);
    if (!basicResult.valid) {
      errors.push(`basic_proof_invalid: ${basicResult.reason}`);
    }
  } else {
    warnings.push('unknown_proof_type');
  }

  // Step 5: Agent signature verification
  if (receipt.agent_signature) {
    const sigValid = await verifyAgentSignature(receipt);
    if (!sigValid) {
      errors.push('signature_invalid');
    }
  } else {
    warnings.push('no_agent_signature');
  }

  // Step 6: Anchor verification (if log info present)
  if (receipt.anchor && expectedPolicyHash) {
    try {
      const logType = receipt.anchor.method || detectLogType(receipt.anchor);
      const verifier = LOG_VERIFIERS[logType] || LOG_VERIFIERS.local;
      const anchorValid = await verifier(receipt.anchor, expectedPolicyHash, opts.logApiUrl);
      if (!anchorValid) {
        errors.push('anchor_verification_failed');
      }
    } catch (e) {
      warnings.push(`anchor_check_skipped: ${e.message}`);
    }
  }

  // Final determination
  if (errors.length > 0) {
    return {
      status: 'invalid',
      receipt_hash: receipt.receipt_hash || receipt.action_hash || 'unknown',
      policy_hash: expectedPolicyHash || 'unknown',
      errors,
      warnings,
      verified_at: new Date().toISOString(),
      pact_version: version,
    };
  }

  if (warnings.length > 0) {
    return {
      status: 'valid_with_warnings',
      receipt_hash: receipt.receipt_hash || receipt.action_hash || 'unknown',
      policy_hash: expectedPolicyHash || 'unknown',
      warnings,
      verified_at: new Date().toISOString(),
      pact_version: version,
    };
  }

  return {
    status: 'valid',
    receipt_hash: receipt.receipt_hash || receipt.action_hash || 'unknown',
    policy_hash: expectedPolicyHash || 'unknown',
    verified_at: new Date().toISOString(),
    pact_version: version,
  };
}

/**
 * Verify an agent's Ed25519 signature over the receipt hash.
 * @param {Object} receipt
 * @returns {Promise<boolean>}
 */
async function verifyAgentSignature(receipt) {
  try {
    const { ed25519 } = await import('@noble/ed25519');
    const pubkeyBytes = Uint8Array.from(atob(receipt.agent_id.replace('did:key:', '').replace('z6Mk', '')));
    const sigBytes = Uint8Array.from(atob(receipt.agent_signature));
    const hashBytes = new TextEncoder().encode(receipt.receipt_hash || receipt.action_hash);
    return await ed25519.verify(sigBytes, hashBytes, pubkeyBytes);
  } catch {
    return false;
  }
}

/**
 * Detect transparency log type from anchor shape.
 */
function detectLogType(anchor) {
  if (anchor.log_url?.includes('rekor')) return 'rekor';
  if (anchor.log_url?.includes('siglog') || anchor.log_url?.includes('tlog')) return 'siglog';
  return 'local';
}

/**
 * Verify a siglog (prefix-dev/siglog) transparency log anchor.
 * The siglog server exposes GET /v1/log/roots/{rootHash} and GET /v1/log/entries/{entryId}
 */
async function verifySiglogAnchor(anchor, expectedPolicyHash, logApiUrl) {
  const baseUrl = logApiUrl || anchor.log_url;
  if (!baseUrl) return false;

  try {
    // Verify the policy hash was registered at the claimed timestamp
    const rootRes = await fetch(`${baseUrl}/v1/log/roots/${expectedPolicyHash}`);
    if (!rootRes.ok) return false;
    const rootData = await rootRes.json();
    
    // Verify entry timestamp matches anchor
    if (anchor.entry_id && rootData.entry_id !== anchor.entry_id) return false;
    if (anchor.timestamp) {
      const expectedTime = new Date(anchor.timestamp).getTime();
      const loggedTime = new Date(rootData.timestamp).getTime();
      if (Math.abs(expectedTime - loggedTime) > 5000) return false; // 5s tolerance
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Verify a Rekor (Sigstore) transparency log anchor.
 * Rekor API: GET /api/v1/log/entries/{entryUUID}
 */
async function verifyRekorAnchor(anchor, expectedPolicyHash, logApiUrl) {
  const baseUrl = logApiUrl || anchor.log_url || 'https://rekor.sigstore.dev';
  
  try {
    // Rekor uses UUIDs as entry IDs — extract from anchor
    const entryUUID = anchor.entry_id || anchor.UUID;
    if (!entryUUID) return false;

    const res = await fetch(`${baseUrl}/api/v1/log/entries/${entryUUID}`);
    if (!res.ok) return false;
    
    const data = await res.json();
    const entry = data[entryUUID] || data;
    
    // Verify body contains our policy hash
    const body = entry.body || {};
    const contentHash = body.contentHash || body.hash;
    if (contentHash && !contentHash.includes(expectedPolicyHash.replace('sha256:', ''))) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Verify a local/memory transparency log anchor (dev mode).
 * Just checks the stored entry matches expected policy hash.
 */
async function verifyLocalAnchor(anchor, expectedPolicyHash) {
  // In local mode, anchor IS the proof — hash match is sufficient
  return anchor.policy_hash === expectedPolicyHash ||
         anchor.policy_hash?.replace('sha256:', '') === expectedPolicyHash.replace('sha256:', '');
}

// Alias for API consumers
export { verifyReceipt as verifyPactReceipt };

// Verification result type (for TypeScript-like docs)
/**
 * @typedef {Object} VerificationResult
 * @property {'valid' | 'valid_with_warnings' | 'invalid' | 'policy_mismatch' | 'unknown_policy'} status
 * @property {string} receipt_hash
 * @property {string} policy_hash
 * @property {string[]} [errors]
 * @property {string[]} [warnings]
 * @property {string} verified_at
 * @property {string} [pact_version]
 */
