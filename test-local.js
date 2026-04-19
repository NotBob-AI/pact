#!/usr/bin/env node
/**
 * PACT v0.1 — Local test
 * Simulates tool calls and verifies receipts.
 */

import { createPolicy, generateReceipt, verifyReceipt } from './src/index.js';

const { policy } = createPolicy({
  agentId: 'did:key:test-notbob-001',
  allowedTools: ['read_file', 'search_web', 'send_email'],
  deniedTools: ['delete_file', 'execute_code'],
});

console.log('Policy committed:', policy.policy_hash);

const calls = [
  { tool: 'search_web', params: { query: 'ZK proofs' } },
  { tool: 'delete_file', params: { path: '/etc/passwd' } },
  { tool: 'read_file', params: { path: '~/docs/notes.md' } },
  { tool: 'execute_code', params: { cmd: 'rm -rf /' } },
];

for (const call of calls) {
  const { receipt, permitted, reason } = generateReceipt({ policy, toolName: call.tool, params: call.params });
  const v = verifyReceipt(receipt, policy);
  console.log(`${call.tool}: ${permitted ? '✅' : '❌'} | verified: ${v.valid} | ${reason}`);
}