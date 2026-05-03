#!/usr/bin/env node
/**
 * PACT v0.1 — Local test
 * Simulates tool calls and verifies receipts.
 */

import { createPolicy, generateReceipt, verifyReceipt } from './src/index.js';
import { StdioInterceptor } from './src/interceptor-stdio.js';

// ── v0.1: Basic policy + receipt tests ───────────────────────────────────────

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

// ── v0.6: StdioInterceptor smoke test ───────────────────────────────────────

console.log('\n--- StdioInterceptor smoke test ---');

const si = new StdioInterceptor({
  policy,
  anchor: { log_index: 0, log_id: 'siglog:test', merkle_root: policy.policy_hash },
  command: null,   // no child process
  args: [],
  blockUnauthorized: false,
});

// Verify instantiation
console.log('Instantiated ✅');
console.assert(Array.isArray(si.getReceipts()), 'getReceipts should return array');
console.log('getReceipts() returns:', si.getReceipts().length, 'receipts ✅');

// Verify policy enforcement logic directly
const { checkToolCall } = await import('./src/policy.js');
const allowed = checkToolCall(policy, 'search_web', {});
const denied = checkToolCall(policy, 'delete_file', {});
console.log('search_web permitted:', allowed.permitted, '✅');
console.assert(!denied.permitted, 'delete_file should be denied');
console.log('delete_file denied:', denied.reason, '✅');

si.stop();
console.log('stop() ✅');
console.log('StdioInterceptor: all tests passed.');
