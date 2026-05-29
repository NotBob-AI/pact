/**
 * verify-pact.js — PACT v0.4 Third-Party Verification CLI
 * 
 * Given a PACT receipt (v0.1, v0.2, or v0.3) and a policy hash, verify
 * the receipt without requiring: the agent's cooperation, log access, or
 * plaintext of the action/policy.
 * 
 * Usage:
 *   node src/verify-pact.js <receipt.json> [--policy-hash <hash>] [--log-url <url>]
 * 
 * Input receipt.json can be a file path or a JSON string.
 * 
 * Exit codes: 0=valid, 1=invalid, 2=error
 */

import { verifyPactReceipt } from './verify_receipt.js';
import { verifyReceipt } from './verifier.js';
import { readFileSync } from 'fs';

const args = process.argv.slice(2);

function usage() {
  console.error(`
PACT Third-Party Receipt Verifier
Usage: node src/verify-pact.js <receipt.json> [--policy-hash <hash>] [--log-url <url>]
  <receipt.json>    Path to a PACT receipt JSON file, or raw JSON string
  --policy-hash     Expected policy hash (overrides receipt.policy_hash)
  --log-url         Transparency log API URL (for siglog anchor verification)

Exit codes:
  0 — receipt is valid
  1 — receipt is invalid
  2 — error (malformed input, missing args)
`);
}

if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
  usage();
  process.exit(2);
}

// ── Parse args ────────────────────────────────────────────────────────────────

let receiptArg = args[0];
const opts = {};

for (let i = 1; i < args.length; i++) {
  if (args[i] === '--policy-hash' && args[i + 1]) {
    opts.policyHash = args[++i];
  } else if (args[i] === '--log-url' && args[i + 1]) {
    opts.logApiUrl = args[++i];
  } else if (args[i] === '--verbose' || args[i] === '-v') {
    opts.verbose = true;
  }
}

// ── Load receipt ───────────────────────────────────────────────────────────────

let receipt;
try {
  const raw = receiptArg.trim();
  if (raw.startsWith('{') || raw.startsWith('[')) {
    // Raw JSON string
    receipt = JSON.parse(raw);
  } else {
    // File path
    receipt = JSON.parse(readFileSync(raw, 'utf8'));
  }
} catch (err) {
  console.error(`Error loading receipt: ${err.message}`);
  process.exit(2);
}

// ── Run verification ────────────────────────────────────────────────────────────

try {
  const result = await verifyReceipt(receipt, opts);

  if (opts.verbose) {
    console.error(`[PACT] status=${result.status}`);
    console.error(`[PACT] policy_hash=${result.policy_hash}`);
    console.error(`[PACT] receipt_hash=${result.receipt_hash}`);
    console.error(`[PACT] pact_version=${result.pact_version}`);
    console.error(`[PACT] verified_at=${result.verified_at}`);
    if (result.errors?.length) console.error(`[PACT] errors=${JSON.stringify(result.errors)}`);
    if (result.warnings?.length) console.error(`[PACT] warnings=${JSON.stringify(result.warnings)}`);
    console.error(`[PACT] reason=${result.reason}`);
  }

  // Human-readable output
  const statusIcon = result.status === 'valid' ? '✓' : result.status === 'valid_with_warnings' ? '⚠' : '✗';
  console.log(`${statusIcon} PACT receipt verification: ${result.status}`);
  console.log(`  receipt: ${result.receipt_hash || 'unknown'}`);
  console.log(`  policy:  ${result.policy_hash || 'unknown'}`);
  if (result.reason) console.log(`  reason:  ${result.reason}`);
  if (result.errors?.length) {
    console.log(`  errors:  ${result.errors.join(', ')}`);
  }
  if (result.warnings?.length) {
    console.log(`  warnings: ${result.warnings.join(', ')}`);
  }

  // Exit code
  if (result.status === 'valid' || result.status === 'valid_with_warnings') {
    process.exit(0);
  } else {
    process.exit(1);
  }
} catch (err) {
  console.error(`Verification error: ${err.message}`);
  if (opts.verbose) console.error(err.stack);
  process.exit(2);
}
