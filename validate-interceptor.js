/**
 * PACT v0.2 — Interceptor (Layer 0) validation
 * Tests policy enforcement logic without requiring a live MCP server.
 * 
 * Run: node validate-interceptor.js
 */

import { McpInterceptor } from './src/interceptor.js';
import { createPolicy, hashPolicy } from './src/policy.js';
import { TransparencyLog, anchorPolicy } from './src/commitment.js';

console.log('PACT v0.2 — Layer 0 (MCP Interceptor) validation\n');

// 1. Create a committed policy
const { policy } = createPolicy({
  agentId: 'did:pact:test-agent',
  allowedTools: ['read_file', 'list_directory', 'web_search'],
  deniedTools: ['delete_file', 'exec', 'send_email'],
});

console.log('Policy created:', policy.policy_hash);

// 2. Anchor to transparency log
const log = new TransparencyLog();
const { anchor } = anchorPolicy(policy, log);
console.log('Policy anchored:', anchor.log_id.slice(0, 20) + '...');
console.log('Log index:', anchor.log_index);

// 3. Create interceptor (without starting server — just test the intercept logic)
const interceptor = new McpInterceptor({
  policy,
  anchor,
  upstreamUrl: 'http://localhost:3100',  // placeholder
  port: 3101,
  allowUnaudited: false,
});

// 4. Test the intercept logic directly
async function runTests() {
  console.log('\n--- Policy enforcement tests ---\n');

  const tests = [
    { tool: 'read_file', args: { path: '/tmp/test.txt' }, expect: 'permit' },
    { tool: 'list_directory', args: { path: '/home' }, expect: 'permit' },
    { tool: 'web_search', args: { query: 'ZK proofs 2026' }, expect: 'permit' },
    { tool: 'delete_file', args: { path: '/etc/passwd' }, expect: 'block' },
    { tool: 'exec', args: { cmd: 'rm -rf /' }, expect: 'block' },
    { tool: 'send_email', args: { to: 'test@example.com' }, expect: 'block' },
  ];

  let passed = 0;
  let failed = 0;

  for (const test of tests) {
    const mockMsg = {
      id: `test-${test.tool}`,
      method: 'tools/call',
      params: { name: test.tool, arguments: test.args },
    };

    const toolResult = await interceptor._interceptToolCall(mockMsg, JSON.stringify(mockMsg));

    const actuallyBlocked = toolResult.drop === true;
    const shouldBlock = test.expect === 'block';

    if (actuallyBlocked === shouldBlock) {
      console.log(`  ✅ ${test.tool}: ${test.expect === 'block' ? 'BLOCKED ✓' : 'PERMITTED ✓'}`);
      if (toolResult.receipt) {
        console.log(`     Receipt: ${toolResult.receipt.action_id}`);
      }
      passed++;
    } else {
      console.log(`  ❌ ${test.tool}: expected ${test.expect}, got ${actuallyBlocked ? 'BLOCKED' : 'PERMITTED'}`);
      failed++;
    }
  }

  console.log(`\n${passed} passed, ${failed} failed`);

  // 5. Show all receipts generated
  const receipts = interceptor.getReceipts();
  console.log(`\n--- Receipts (${receipts.length}) ---\n`);
  for (const r of receipts) {
    if (r.blocked) {
      console.log(`  BLOCKED: ${r.tool_name} — ${r.reason}`);
    } else {
      console.log(`  ${r.tool_called}: ${r.action_id}`);
    }
  }

  if (failed > 0) {
    process.exit(1);
  }

  console.log('\n✅ PACT Layer 0 (MCP Interceptor) — policy enforcement validated');
}

runTests().catch((err) => {
  console.error('Test error:', err);
  process.exit(1);
});
