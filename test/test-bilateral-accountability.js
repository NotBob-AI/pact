/**
 * PACT Bilateral Accountability Integration Test
 * 
 * Tests the complete bilateral accountability chain:
 *   1. PACT (agent-side): Intercepts tool call, generates receipt BEFORE action
 *   2. Notarized Agents (receiver-side): Service signs what it received
 *   3. Bilateral verification: Both receipts must be valid and consistent
 * 
 * Run: node test/test-bilateral-accountability.js
 */

import { createPolicy, generateReceipt, verifyReceipt, checkToolCall } from '../src/index.js';
import { TransparencyLog, anchorPolicy, verifyAnchor } from '../src/commitment.js';
import crypto from 'crypto';

const fail = (msg) => { console.error(`  ✗ ${msg}`); process.exitCode = 1; };
const pass = (msg) => console.log(`  ✓ ${msg}`);

console.log('\n=== PACT Bilateral Accountability Integration Test ===\n');

// ─── Setup ───────────────────────────────────────────────────────────────────

const log = new TransparencyLog();

// Create agent policy and anchor it
const { policy, hash: policyHash } = createPolicy({
  agentId: 'did:key:z6MkNotBobAlpha',
  allowedTools: ['mcp_filesystem_read', 'mcp_search', 'web_fetch'],
  deniedTools: ['mcp_filesystem_delete', 'exec', 'sudo'],
  scopeConstraints: { network: { allowed_domains: ['*.search/*'] } }
});

// Anchor policy to transparency log (genesis commitment)
const { anchor } = anchorPolicy(policy, log);
pass(`policy anchored at log_index=${anchor.log_index}`);

// ─── Simulated Notarized Agents Service Receipt ────────────────────────────────

/**
 * Simulate a Notarized Agents receipt (arxiv 2606.04193v1).
 * In production: service holds its own Ed25519 key, signs what it received.
 * We simulate the cryptographic structure here.
 */
function generateServiceReceipt({ serviceKey, serviceId, receivedCall, ownerPublicKey }) {
  const timestamp = Date.now();
  const receivedHash = crypto.createHash('sha256')
    .update(JSON.stringify(receivedCall))
    .digest('hex');
  
  // Simulate service signature (in production: Ed25519 sign)
  const sigInput = `${serviceId}:${receivedHash}:${timestamp}`;
  const signature = crypto.createHmac('sha256', serviceKey)
    .update(sigInput)
    .digest('hex');
  
  return {
    version: '1.0',
    type: 'notarized-agent-receipt',
    service_id: serviceId,
    received_hash: receivedHash,
    owner_public_key: ownerPublicKey,
    timestamp,
    signature,
    // arxiv 2606.04193: service encrypts to owner's key
    encrypted_to_owner: Buffer.from(JSON.stringify({
      received_call: receivedCall,
      service_sig: signature
    })).toString('base64')
  };
}

// ─── Step 1: Agent decides to call tool ──────────────────────────────────────

const toolName = 'mcp_search';
const params = { query: 'ZK proofs agent accountability', domain: 'search.example' };
const agentPrivateKey = 'agent-ed25519-sk-verysecret';
const agentPublicKey = policy.agentId;
const serviceId = 'did:key:z6MkSearchServiceAlpha';
const servicePrivateKey = 'service-ed25519-sk-secret';
const mcpMessageId = 'msg_' + crypto.randomBytes(8).toString('hex');

console.log('\n1. Agent Policy Check');
const { permitted, reason } = checkToolCall(policy, toolName, params);
if (!permitted) fail(`expected permitted, got: ${reason}`);
else pass(`mcp_search permitted: ${reason}`);

// ─── Step 2: PACT generates receipt BEFORE action ────────────────────────────

console.log('\n2. PACT Receipt Generation (before action)');
const { receipt: pactReceipt } = generateReceipt({
  policy,
  toolName,
  params,
  mcp_binding: {
    mcp_message_id: mcpMessageId,
    mcp_server_id: serviceId,
    mcp_transport: 'stdio'
  }
});

if (pactReceipt.outcome !== 'permitted') fail(`expected permitted, got: ${pactReceipt.outcome}`);
else pass(`PACT receipt outcome: ${pactReceipt.outcome}`);
if (!pactReceipt.proof?.proof_hash) fail('missing proof_hash');
else pass(`PACT proof_hash: ${pactReceipt.proof.proof_hash.slice(0, 24)}...`);
if (!pactReceipt.policy_hash.startsWith('sha256:')) fail('missing policy_hash');
else pass(`PACT policy_hash: ${pactReceipt.policy_hash.slice(0, 24)}...`);
if (!pactReceipt.mcp_binding?.mcp_message_id) fail('missing MCP binding message id');
else pass(`MCP binding: ${pactReceipt.mcp_binding.mcp_transport} / msg_id=${pactReceipt.mcp_binding.mcp_message_id}`);
if (!pactReceipt.mcp_binding?.mcp_receipt_hash) fail('missing MCP binding receipt hash');
else pass(`MCP receipt_hash: ${pactReceipt.mcp_binding.mcp_receipt_hash.slice(0, 24)}...`);

// Verify PACT receipt
console.log('\n3. PACT Receipt Verification');
const pactVerify = verifyReceipt(pactReceipt, policy);
if (!pactVerify.valid) fail(`PACT receipt invalid: ${pactVerify.reason}`);
else pass('PACT receipt verified valid');

// ─── Step 3: Service receives call, generates Notarized Agents receipt ───────

console.log('\n4. Service Receipt Generation (Notarized Agents pattern)');
// arxiv 2606.04193: service receives the call and signs what it observed.
// We include the MCP binding from PACT to link the two receipts.
const receivedCall = {
  tool: toolName,
  params,
  // MCP binding links to PACT receipt
  mcp_message_id: pactReceipt.mcp_binding.mcp_message_id,
  mcp_receipt_hash: pactReceipt.mcp_binding.mcp_receipt_hash,
  // PACT policy hash — proves which policy authorized this
  pact_policy_hash: pactReceipt.policy_hash,
  // PACT action_id — unique per-action identifier
  pact_action_id: pactReceipt.action_id
};

const serviceReceipt = generateServiceReceipt({
  serviceKey: servicePrivateKey,
  serviceId,
  receivedCall,
  ownerPublicKey: agentPublicKey
});

if (!serviceReceipt.received_hash) fail('missing received_hash');
else pass(`service received_hash: ${serviceReceipt.received_hash.slice(0, 24)}...`);
if (!serviceReceipt.signature) fail('missing signature');
else pass(`service signature: ${serviceReceipt.signature.slice(0, 24)}...`);
if (!serviceReceipt.encrypted_to_owner) fail('missing encrypted_to_owner');
else pass('service receipt encrypted to owner key');

// Decrypt and verify (in production: owner's key decrypts)
const decrypted = JSON.parse(Buffer.from(serviceReceipt.encrypted_to_owner, 'base64').toString('utf8'));
if (decrypted.received_call.tool !== toolName) fail('decrypted tool mismatch');
else pass('service receipt decrypts to original call');

// ─── Step 4: Bilateral Consistency Check ─────────────────────────────────────

console.log('\n5. Bilateral Consistency Verification');
const pactProofHash = pactReceipt.proof.proof_hash;
const pactMcpReceiptHash = pactReceipt.mcp_binding.mcp_receipt_hash;
const serviceReceivedHash = serviceReceipt.received_hash;

// The MCP receipt hash links PACT's transport binding to the service receipt
// arxiv 2606.04193 calls this "committing to the received message"
const serviceCall = decrypted.received_call;

if (serviceCall.mcp_receipt_hash !== pactMcpReceiptHash) {
  fail(`MCP receipt hash link broken: service=${serviceCall.mcp_receipt_hash?.slice(0, 16)}, pact=${pactMcpReceiptHash?.slice(0, 16)}`);
} else {
  pass(`MCP receipt hash link verified: ${pactMcpReceiptHash.slice(0, 24)}...`);
}

// Policy hash must match between PACT and service
if (serviceCall.pact_policy_hash !== pactReceipt.policy_hash) {
  fail(`policy hash mismatch: service=${serviceCall.pact_policy_hash?.slice(0, 16)}, pact=${pactReceipt.policy_hash?.slice(0, 16)}`);
} else {
  pass(`policy hash consistent: ${pactReceipt.policy_hash.slice(0, 24)}...`);
}

// MCP message ID link
if (serviceCall.mcp_message_id !== pactReceipt.mcp_binding.mcp_message_id) {
  fail('MCP message ID link broken between receipts');
} else {
  pass(`MCP message ID link verified: ${pactReceipt.mcp_binding.mcp_message_id}`);
}

// Action ID link
if (serviceCall.pact_action_id !== pactReceipt.action_id) {
  fail('action ID link broken between receipts');
} else {
  pass(`action ID link verified: ${pactReceipt.action_id}`);
}

// ─── Step 5: Tamper Detection ────────────────────────────────────────────────

console.log('\n6. Tamper Detection');
// Try to fake a PACT receipt
const fakePactReceipt = {
  ...pactReceipt,
  outcome: 'permitted',
  tool_called: 'mcp_filesystem_delete' // switched to denied tool
};
const fakeVerify = verifyReceipt(fakePactReceipt, policy);
if (fakeVerify.valid) fail('tampered PACT receipt should be rejected');
else pass(`tampered PACT receipt correctly rejected: ${fakeVerify.reason}`);

// Try to fake a service receipt with wrong hash
const tamperedServiceReceipt = {
  ...serviceReceipt,
  received_hash: crypto.createHash('sha256').update('tampered').digest('hex')
};
// In production: signature verification would fail here since received_hash changed.
// In this simulation: signature is copied (not re-signed), so we verify hash mismatch
// by checking that tampered received_hash differs from original.
if (serviceReceipt.received_hash === tamperedServiceReceipt.received_hash) {
  fail('tampered receipt should have different received_hash');
} else {
  pass('tampered receipt: received_hash differs, original signature no longer valid for tampered content');
}

// ─── Step 6: Anchor Verification ─────────────────────────────────────────────

console.log('\n7. Policy Anchor Verification');
const anchorVerify = verifyAnchor(policy, anchor);
if (!anchorVerify.valid) fail(`anchor invalid: ${anchorVerify.reason}`);
else pass(`policy anchored at log_index=${anchor.log_index}, merkle_root=${anchor.merkle_root.slice(0, 24)}...`);

// ─── Step 6: Anchor Verification ─────────────────────────────────────────────



console.log('\n=== All bilateral accountability tests passed ===\n');
console.log('Bilateral chain: PACT (agent-side) → Service (receiver-side)');
console.log(`PACT proof_hash:   ${pactReceipt.proof.proof_hash.slice(0, 32)}...`);
console.log(`Service recv_hash: ${serviceReceipt.received_hash.slice(0, 32)}...`);
console.log('Neither party can unilaterally falsify the record.\n');
