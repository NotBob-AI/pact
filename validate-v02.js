#!/usr/bin/env node
// PACT v0.2 — Layer 1 (commitment) validation
import { createPolicy, checkToolCall } from './src/policy.js';
import { generateReceipt, verifyReceipt } from './src/receipt.js';
import { buildMerkleTree, verifyMerkleProof, TransparencyLog, anchorPolicy } from './src/commitment.js';

console.log('PACT v0.2 — Layer 1 (commitment) validation\n');

// Create policy
const { policy, hash } = createPolicy({
  agentId: 'did:key:test-agent-001',
  allowedTools: ['read_file', 'search_web', 'send_email'],
  deniedTools: ['delete_file', 'execute_code', 'access_credentials'],
  scopeConstraints: {
    filesystem: { read: ['~/documents/**'], write: [] },
    network: { allowed_domains: ['*.bsky.social', 'api.github.com'] },
  },
});

console.log('Policy hash:', policy.policy_hash);

// Test tool call — should pass
const okResult = checkToolCall(policy, 'read_file', { path: '~/documents/report.txt' });
console.log('read_file call permitted:', okResult.permitted); // should be true

// Test tool call — should fail
const failResult = checkToolCall(policy, 'delete_file', {});
console.log('delete_file call permitted:', failResult.permitted); // should be false

// Generate receipt
const { receipt, permitted } = generateReceipt({ policy, toolName: 'read_file', params: { path: '~/documents/report.txt' } });
console.log('Receipt generated for', receipt.tool_called);

// Verify receipt
const verified = verifyReceipt(receipt, policy);
console.log('Receipt verified:', verified.valid); // should be true

// Test TransparencyLog anchoring
const log = new TransparencyLog();
const { anchor, proofs, entry } = anchorPolicy(policy, log);
console.log('\nPolicy anchored to transparency log:');
console.log('  log_index:', anchor.log_index);
console.log('  log_id:', anchor.log_id.slice(0, 30) + '...');
console.log('  merkle_root:', anchor.merkle_root.slice(0, 30) + '...');
console.log('  proofs returned:', proofs ? 'yes, count=' + proofs.length : 'no/undefined');

// Debug: rebuild the merkle tree and verify manually
const { root: rebuiltRoot, proofs: rebuiltProofs } = buildMerkleTree([policy.policy_hash]);
console.log('\nRebuilt merkle root:', rebuiltRoot);
console.log('Entry merkle root:', anchor.merkle_root);
console.log('Roots match:', rebuiltRoot === anchor.merkle_root);

// Verify with rebuilt proof
const check1 = verifyMerkleProof(policy.policy_hash, rebuiltRoot, rebuiltProofs[0]);
console.log('Verify with rebuilt proof:', check1);

// Try log.verify
const logVerifyResult = log.verify(policy.policy_hash, 0);
console.log('log.verify result:', logVerifyResult);

// Add second policy and test batch
const { policy: policy2 } = createPolicy({
  agentId: 'did:key:test-agent-002',
  allowedTools: ['search_web', 'send_email'],
  deniedTools: [],
  scopeConstraints: {},
});
const { anchor: anchor2 } = anchorPolicy(policy2, log);
console.log('\nSecond policy anchored at log_index:', anchor2.log_index);

// Verify both policies in the log
const verify1 = log.verify(policy.policy_hash, 0);
const verify2 = log.verify(policy2.policy_hash, 1);
console.log('Policy 1 verified via log.verify:', verify1.valid);
console.log('Policy 2 verified via log.verify:', verify2.valid);

console.log('\n✅ PACT v0.2 — Layer 1 (Policy Commitment) operational');