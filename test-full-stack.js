#!/usr/bin/env node
/**
 * PACT v0.3 — Full Stack Integration Test
 * 
 * Tests the complete v0.3 receipt lifecycle:
 *   1. Create policy + compute hash
 *   2. Anchor to mock transparency log (builds Merkle tree)
 *   3. Generate ZK receipt for permitted + denied tool calls
 *   4. Verify receipts using verify_receipt.js
 *   5. Tamper detection (modified receipt, policy hash mismatch, wrong tool name)
 *   6. Idempotent anchor (same policy re-anchored doesn't duplicate)
 * 
 * Run: node test-full-stack.js
 */

import { createPolicy } from './src/policy.js';
import { generateReceipt } from './src/receipt.js';
import { TransparencyLog, buildMerkleTree } from './src/commitment.js';
import { verifyPactReceipt, batchVerifyReceipts } from './src/verify_receipt.js';
import crypto from 'crypto';

// ── Helpers ────────────────────────────────────────────────────────────────────

let TESTS_PASSED = 0;
let TESTS_FAILED = 0;

function test(name, fn) {
  process.stdout.write(`  ${name}... `);
  try {
    fn();
    console.log('✅');
    TESTS_PASSED++;
  } catch (err) {
    console.log(`❌ ${err.message}`);
    TESTS_FAILED++;
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'assertion failed');
}

// ── Test Suite ─────────────────────────────────────────────────────────────────

async function runTests() {
  console.log('\n=== PACT v0.3 Full Stack Integration Test ===\n');

  // ── 1. Policy Creation ───────────────────────────────────────────────────────
  console.log('[1] Policy Creation');
  const { policy } = createPolicy({
    agentId: 'did:key:test-notbob-001',
    allowedTools: ['read_file', 'search_web', 'browser', 'web_fetch'],
    deniedTools: ['exec', 'delete_file'],
    maxActionsPerSession: 100,
    requireReceipts: true,
  });

  test('policy has valid hash', () => {
    assert(policy.policy_hash?.startsWith('sha256:'), 'policy_hash must start with sha256:');
  });

  test('policy has allowed_tools list', () => {
    assert(Array.isArray(policy.allowed_tools) && policy.allowed_tools.length > 0, 'allowed_tools must be non-empty array');
  });

  // ── 2. Transparency Log + Merkle Anchor ─────────────────────────────────────
  console.log('\n[2] Transparency Log Anchoring');
  const log = new TransparencyLog();

  test('append policy to empty log', () => {
    const { entry, root, proofs } = log.append([policy.policy_hash], 'test v0.3 policy');
    assert(entry.log_index === 0, 'first entry must have index 0');
    assert(entry.merkle_root?.startsWith('sha256:'), 'merkle_root must be a sha256 hash');
    assert(entry.log_id?.startsWith('sha256:'), 'log_id must be a sha256 hash');
    assert(entry.prev_hash === 'GENESIS', 'first entry prev_hash must be GENESIS');
  });

  test('idempotent re-anchor of same policy', () => {
    const countBefore = log.entries.length;
    const { entry: entry2 } = log.append([policy.policy_hash], 're-anchor same policy');
    assert(log.entries.length === countBefore, 're-anchoring same policy should not add new entry (idempotent)');
  });

  test('anchor can be used as PACT anchor', () => {
    const entry = log.entries[0];
    const anchor = {
      log_index: entry.log_index,
      log_id: entry.log_id,
      merkle_root: entry.merkle_root,
      log_url: 'mock://transparency-log',
    };
    assert(anchor.log_index === 0, 'anchor.log_index must match entry');
    assert(anchor.merkle_root === entry.merkle_root, 'anchor.merkle_root must match entry');
  });

  // ── 3. Receipt Generation ────────────────────────────────────────────────────
  console.log('\n[3] Receipt Generation (v0.1)');

  const permittedReceipt = generateReceipt({
    policy,
    toolName: 'search_web',
    params: { query: 'ZK proofs for agent accountability' },
  });

  test('permitted call generates valid receipt', () => {
    assert(permittedReceipt.permitted === true, 'search_web must be permitted');
    assert(permittedReceipt.receipt?.receipt_version === '0.1.0', 'receipt_version must be 0.1.0');
  });

  const deniedReceipt = generateReceipt({
    policy,
    toolName: 'exec',
    params: { cmd: 'rm -rf /' },
  });

  test('denied call generates receipt with denied outcome', () => {
    assert(deniedReceipt.permitted === false, 'exec must be denied');
    assert(deniedReceipt.receipt?.outcome === 'denied', 'outcome must be denied');
  });

  // ── 4. Receipt Verification ──────────────────────────────────────────────────
  console.log('\n[4] Receipt Verification (verify_receipt.js)');

  const anchor = {
    log_index: 0,
    log_id: log.entries[0].log_id,
    merkle_root: log.entries[0].merkle_root,
  };

  // Build a DUMMY_ZK_PROOF receipt to test verification
  const { zk_receipt } = buildDummyZkReceipt(policy, 'search_web', anchor, { query: 'ZK proofs' });

  test('verify DUMMY_ZK_PROOF receipt — valid structure passes', async () => {
    const result = await verifyPactReceipt({
      receipt: zk_receipt,
      policyHash: policy.policy_hash,
      toolName: 'search_web',
      anchor,
    });
    assert(result.valid === true, `verify must pass: ${result.reason}`);
  });

  test('verify — policy hash mismatch detected', async () => {
    const badReceipt = { ...zk_receipt };
    badReceipt.public = { ...zk_receipt.public, policy_hash: 'sha256:0000000000000000000000000000000000000000000000000000000000000000' };
    const result = await verifyPactReceipt({
      receipt: badReceipt,
      policyHash: policy.policy_hash,
    });
    assert(result.valid === false, 'policy hash mismatch must fail verification');
    assert(result.reason.includes('mismatch'), 'reason must mention mismatch');
  });

  test('verify — tool name mismatch detected', async () => {
    const result = await verifyPactReceipt({
      receipt: zk_receipt,
      policyHash: policy.policy_hash,
      toolName: 'this_tool_is_not_allowed',
    });
    assert(result.valid === false, 'wrong tool name must fail');
  });

  // ── 5. Merkle Proof Verification ────────────────────────────────────────────
  console.log('\n[5] Merkle Proof Verification');

  const { proofs } = log.verify(policy.policy_hash, 0);
  test('verify Merkle proof for policy in log', () => {
    assert(proofs !== null, 'proof must be returned for valid policy hash');
  });

  test('verify fails for unknown policy hash', () => {
    const result = log.verify('sha256:0000000000000000000000000000000000000000000000000000000000000000', 0);
    assert(result.valid === false, 'unknown policy hash must fail verification');
  });

  // ── 6. Batch Verification ────────────────────────────────────────────────────
  console.log('\n[6] Batch Verification');

  const zkReceipt1 = buildDummyZkReceipt(policy, 'search_web', anchor, { query: 'test' }).zk_receipt;
  const zkReceipt2 = buildDummyZkReceipt(policy, 'read_file', anchor, { path: '/tmp/test' }).zk_receipt;
  const zkReceipt3 = buildDummyZkReceipt(policy, 'browser', anchor, { url: 'https://example.com' }).zk_receipt;

  test('batch verify — all valid receipts pass', async () => {
    const results = await batchVerifyReceipts(
      [zkReceipt1, zkReceipt2, zkReceipt3],
      [policy.policy_hash, policy.policy_hash, policy.policy_hash]
    );
    assert(results.valid === true, 'all receipts must be valid');
    assert(results.valid_count === 3, `expected 3 valid, got ${results.valid_count}`);
    assert(results.total === 3, 'total must be 3');
  });

  test('batch verify — one tampered receipt fails entire batch', async () => {
    const tampered = { ...zkReceipt2 };
    tampered.public = { ...zkReceipt2.public, policy_hash: 'sha256:0000000000000000000000000000000000000000000000000000000000000000' };
    const results = await batchVerifyReceipts(
      [zkReceipt1, tampered, zkReceipt3],
      [policy.policy_hash, policy.policy_hash, policy.policy_hash]
    );
    assert(results.valid === false, 'batch must fail with tampered receipt');
    assert(results.valid_count === 2, `expected 2 valid, got ${results.valid_count}`);
  });

  // ── Summary ──────────────────────────────────────────────────────────────────
  console.log(`\n=== Results: ${TESTS_PASSED} passed, ${TESTS_FAILED} failed ===\n`);
  if (TESTS_FAILED > 0) {
    console.error(`FAIL: ${TESTS_FAILED} test(s) failed`);
    process.exit(1);
  } else {
    console.log('ALL TESTS PASSED ✅');
  }
}

// ── Build a dummy ZK receipt for testing verify_receipt.js ─────────────────────

function buildDummyZkReceipt(policy, toolName, anchor, params = {}) {
  const timestamp = new Date().toISOString();
  const toolNameHash = `sha256:${crypto.createHash('sha256').update(toolName).digest('hex')}`;
  const paramsHash = `sha256:${crypto.createHash('sha256').update(JSON.stringify(params)).digest('hex')}`;

  return {
    zk_receipt: {
      receipt_version: '0.3.0',
      proof_type: 'DUMMY_ZK_PROOF',
      circuit_id: 'pact-v0.3-dummy',
      public: {
        policy_hash: policy.policy_hash,
        merkle_root: anchor.merkle_root,
        log_index: anchor.log_index,
        log_id: anchor.log_id,
        tool_name_hash: toolNameHash,
        params_hash: paramsHash,
        timestamp,
      },
      proof: {
        proof_encoding: 'dummy_v1',
        proof_data: null,
        prover_id: policy.agent_id,
        note: 'DUMMY_ZK_PROOF — RISC Zero not available. Replace with actual proof before production.',
      },
      outcome: 'permitted',
      outcome_reason: `tool_name ∈ policy.allowed_tools[dummy]`,
      generated_at: timestamp,
    },
    permitted: true,
    reason: 'DUMMY_ZK_PROOF (RISC Zero not available)',
  };
}

runTests().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});