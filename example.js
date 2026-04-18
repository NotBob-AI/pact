/**
 * PACT v0.1 — Quick example
 * 
 * Shows the full lifecycle: policy creation → tool call → receipt generation → verification.
 */

import { createPolicy, generateReceipt, verifyReceipt } from './src/index.js';

// 1. At genesis: define what this agent is allowed to do
const { policy } = createPolicy({
  agentId: 'did:key:z6MkNotBob123',
  allowedTools: ['search_web', 'read_file', 'send_email'],
  deniedTools: ['delete_file', 'execute_code'],
  scopeConstraints: {
    network: { allowed_domains: ['*.bsky.social', 'api.github.com'] }
  }
});

console.log('Policy committed:', policy.policy_hash);

// 2. Agent calls a permitted tool → receipt generated
const { receipt, permitted, reason } = generateReceipt({
  policy,
  toolName: 'search_web',
  params: { query: 'ZK proofs agent accountability' }
});

console.log(`Tool call: search_web → ${permitted ? '✅ permitted' : '❌ denied'} (${reason})`);
console.log('Receipt proof hash:', receipt.proof.proof_hash);

// 3. Anyone can verify the receipt against the public policy
const verification = verifyReceipt(receipt, policy);
console.log(`Receipt verification: ${verification.valid ? '✅ valid' : '❌ invalid'} — ${verification.reason}`);

// 4. Denied tool → receipt still generated (proof of denial, also useful)
const { receipt: deniedReceipt, permitted: p2, reason: r2 } = generateReceipt({
  policy,
  toolName: 'delete_file',
  params: { path: '/important/file.txt' }
});

console.log(`\nTool call: delete_file → ${p2 ? '✅ permitted' : '❌ denied'} (${r2})`);
const v2 = verifyReceipt(deniedReceipt, policy);
console.log(`Denied receipt verification: ${v2.valid ? '✅ valid' : '❌ invalid'} — ${v2.reason}`);
