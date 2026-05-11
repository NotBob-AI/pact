/**
 * PACT JS Stack Integration Test — Full Workflow
 * 
 * Tests: createPolicy → anchorPolicy → generateReceipt → verifyReceipt
 * 
 * Run: node test/test-stack.js
 */

import { createPolicy, hashPolicy, verifyPolicyHash, checkToolCall } from '../src/policy.js';
import { TransparencyLog, anchorPolicy, verifyAnchor } from '../src/commitment.js';
import { generateReceipt, verifyReceipt } from '../src/receipt.js';

const fail = (msg) => { console.error(`  ✗ ${msg}`); process.exitCode = 1; };
const pass = (msg) => console.log(`  ✓ ${msg}`);

console.log('\n=== PACT JS Stack Integration Test ===\n');

// 1. Create policy
console.log('1. Policy Creation');
const { policy, hash } = createPolicy({
  agentId: 'did:web:notbob.ai',
  allowedTools: ['web_search', 'web_fetch', 'memory_search', 'exec'],
  deniedTools: ['delete', 'rm', 'system', 'sudo'],
});
pass(`policy created, hash: ${hash.slice(0, 24)}...`);

// 2. Verify policy hash
console.log('\n2. Policy Hash Verification');
const hashCheck = verifyPolicyHash(policy);
if (!hashCheck.valid) fail(`hash mismatch: expected ${hashCheck.expected}, got ${hashCheck.got}`);
else pass('policy hash self-check valid');

// 3. Check tool calls
console.log('\n3. Tool Call Authorization');
const allowed = checkToolCall(policy, 'web_search');
if (!allowed.permitted) fail('web_search should be permitted');
else pass('web_search: permitted');

const denied = checkToolCall(policy, 'delete');
if (denied.permitted) fail('delete should be denied');
else pass('delete: denied (correct)');

const unknown = checkToolCall(policy, 'deploy_nuke');
if (unknown.permitted) fail('deploy_nuke should be denied');
else pass('deploy_nuke: denied (not in allowed list)');

// 4. Commit to transparency log
console.log('\n4. Policy Commitment to Transparency Log');
const log = new TransparencyLog();
const { anchor, entry } = anchorPolicy(policy, log);
pass(`policy anchored at log_index=${anchor.log_index}`);
if (!anchor.log_id.startsWith('sha256:')) fail('log_id should be sha256 hash');
else pass(`log_id: ${anchor.log_id.slice(0, 24)}...`);
if (anchor.merkle_root !== entry.merkle_root) fail('merkle_root mismatch');
else pass(`merkle_root: ${anchor.merkle_root.slice(0, 24)}...`);

// 5. Re-anchor same policy (idempotent)
console.log('\n5. Idempotent Re-anchor (same policy)');
const { anchor: anchor2 } = anchorPolicy(policy, log);
if (anchor2.already_anchored !== true) fail('should detect already anchored');
else pass('correctly detected already anchored');
if (anchor2.log_index !== anchor.log_index) fail('should return same log_index');
else pass(`same log_index=${anchor2.log_index} returned`);

// 6. Generate receipts
console.log('\n6. Receipt Generation');
const { receipt: r1 } = generateReceipt({ policy, toolName: 'web_search', params: { query: 'antimony supply chain' } });
pass(`web_search receipt: action_id=${r1.action_id.slice(0, 8)}...`);
if (r1.outcome !== 'permitted') fail('web_search should be permitted');
else pass(`outcome: ${r1.outcome}`);

const { receipt: r2 } = generateReceipt({ policy, toolName: 'delete', params: { path: '/etc/passwd' } });
pass(`delete receipt: action_id=${r2.action_id.slice(0, 8)}...`);
if (r2.outcome !== 'denied') fail('delete should be denied');
else pass(`outcome: ${r2.outcome}`);

// 7. Verify receipts
console.log('\n7. Receipt Verification');
const v1 = verifyReceipt(r1, policy);
if (!v1.valid) fail(`web_search receipt invalid: ${v1.reason}`);
else pass(`web_search receipt: valid`);

const v2 = verifyReceipt(r2, policy);
if (!v2.valid) fail(`delete receipt invalid: ${v2.reason}`);
else pass(`delete receipt: valid`);

// 8. Tamper detection
console.log('\n8. Tamper Detection');
const tamperedReceipt = { ...r1, tool_called: 'delete' }; // flip tool name post-generation
const v3 = verifyReceipt(tamperedReceipt, policy);
if (v3.valid) fail('tampered receipt should be invalid');
else pass(`tampered receipt correctly rejected: ${v3.reason}`);

// 9. Policy hash anchor verification
console.log('\n9. Anchor Verification');
const av = verifyAnchor(policy, anchor);
if (!av.valid) fail(`anchor invalid: ${av.reason}`);
else pass(`anchor valid: log_index=${av.log_index}`);

console.log('\n=== All tests passed ===\n');
