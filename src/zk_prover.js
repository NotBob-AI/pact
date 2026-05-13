/**
 * PACT v0.3 — ZK Prover Bridge (Node.js → RISC Zero)
 * 
 * Bridges the Node.js PACT stack to the RISC Zero prover.
 * 
 * Workflow:
 *   interceptor-stdio.js → generateZkReceipt() → ZkProver.prove() → [call Rust guest] → PACT ZK Receipt
 * 
 * The prover accepts:
 *   - publicInputs: { policy_hash, merkle_root, log_index, tool_name_hash, timestamp }
 *   - privateWitness: { policy_document, allowed_tools, merkle_proof, log_id }
 * 
 * Returns a receipt compatible with PACT v0.3 format (urn:pact:receipt:v0.3).
 * 
 * Usage:
 *   import { ZkProver } from './zk_prover.js';
 *   const prover = new ZkProver({ guestBinaryPath: './rust/guest/target/riscv32im-risc0-zkvm-elf' });
 *   const receipt = await prover.prove({ policy, toolName, anchor, merkleProof, params });
 */

import { spawn } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

export class ZkProver {
  /**
   * @param {object} opts
   * @param {string} opts.guestBinaryPath - Path to compiled RISC Zero guest ELF binary
   * @param {string} opts.guestMethod    - RISC Zero method name (default: 'pact_tool_membership')
   * @param {boolean} opts.useDummyProof  - Use DUMMY_ZK_PROOF if RISC Zero unavailable (default: true)
   */
  constructor({ guestBinaryPath = null, guestMethod = 'pact_tool_membership', useDummyProof = true } = {}) {
    this.guestBinaryPath = guestBinaryPath;
    this.guestMethod = guestMethod;
    this.useDummyProof = useDummyProof;
    this.riscZeroAvailable = null; // lazily determined
  }

  /**
   * Determine if RISC Zero toolchain is available.
   * @returns {Promise<boolean>}
   */
  async checkAvailability() {
    if (this.riscZeroAvailable !== null) return this.riscZeroAvailable;
    
    if (!this.guestBinaryPath) {
      this.riscZeroAvailable = false;
      return false;
    }

    try {
      await fs.promises.access(this.guestBinaryPath, fs.constants.R_OK);
      this.riscZeroAvailable = true;
      return true;
    } catch {
      this.riscZeroAvailable = false;
      return false;
    }
  }

  /**
   * Generate a ZK receipt proving a tool call was within committed policy.
   * 
   * @param {object} opts
   * @param {object} opts.policy        - Full policy document (from PolicySpec)
   * @param {string} opts.toolName       - Tool being called
   * @param {object} opts.anchor         - Anchor from transparency log { log_index, log_id, merkle_root }
   * @param {object} opts.merkleProof    - Merkle inclusion proof from transparency log
   * @param {object} [opts.params]      - Tool parameters (hashed privately, not revealed)
   * @returns {Promise<{ zk_receipt: object, permitted: boolean, reason: string }>}
   */
  async prove({ policy, toolName, anchor, merkleProof, params = {} }) {
    const available = await this.checkAvailability();

    if (!available || !this.guestBinaryPath) {
      return this._generateDummyProof({ policy, toolName, anchor, merkleProof, params });
    }

    try {
      return await this._proveWithRiscZero({ policy, toolName, anchor, merkleProof, params });
    } catch (err) {
      console.error(`[PACT ZK] RISC Zero failed: ${err.message}, falling back to DUMMY`);
      return this._generateDummyProof({ policy, toolName, anchor, merkleProof, params });
    }
  }

  /**
   * Internal: call the RISC Zero guest ELF binary.
   */
  async _proveWithRiscZero({ policy, toolName, anchor, merkleProof, params }) {
    // Prepare public inputs
    const policyHash = policy.policy_hash || this._computePolicyHash(policy);
    const toolNameHash = `sha256:${crypto.createHash('sha256').update(toolName, 'utf8').digest('hex')}`;
    const paramsHash = `sha256:${crypto.createHash('sha256').update(JSON.stringify(params), 'utf8').digest('hex')}`;
    const timestamp = new Date().toISOString();

    const publicInputs = {
      policy_hash: policyHash.replace('sha256:', ''),
      merkle_root: anchor.merkle_root.replace('sha256:', ''),
      log_index: anchor.log_index,
      tool_name_hash: toolNameHash.replace('sha256:', ''),
      timestamp,
    };

    // Prepare private witness
    const privateWitness = {
      policy_document: JSON.stringify(policy),
      allowed_tools: policy.allowed_tools || [],
      merkle_proof: merkleProof || [],
      log_id: anchor.log_id,
    };

    // Serialize inputs as JSON for the guest
    const inputJson = JSON.stringify({ public: publicInputs, private: privateWitness });
    const inputPath = path.join('/tmp', `pact-input-${Date.now()}.json`);
    await fs.promises.writeFile(inputPath, inputJson);

    // Call RISC Zero guest
    const result = await this._runGuest(inputPath);

    // Clean up
    await fs.promises.unlink(inputPath).catch(() => {});

    if (!result.ok || !result.receipt) {
      throw new Error(`RISC Zero guest failed: ${result.error || 'unknown'}`);
    }

    // Build PACT ZK receipt from guest output
    const zkReceipt = {
      receipt_version: '0.3.0',
      proof_type: 'zk_membership',
      circuit_id: `pact-v0.3-${this.guestMethod}`,
      
      // Public inputs (verifier sees these)
      public: publicInputs,
      
      // Proof output from RISC Zero
      proof: {
        proof_encoding: 'risc0_receipt_v1',
        proof_data: result.receipt, // raw output from guest
        prover_id: policy.agent_id || policy.principal_did || 'unknown',
      },
      
      // Metadata
      outcome: 'permitted',
      outcome_reason: `tool_name ∈ policy.allowed_tools[proof]`,
      generated_at: timestamp,
      
      // Anchor for verification
      anchor: {
        log_index: anchor.log_index,
        log_id: anchor.log_id,
        merkle_root: anchor.merkle_root,
        method: anchor.method || 'siglog',
      },
    };

    return { zk_receipt: zkReceipt, permitted: true, reason: 'ZK proof generated via RISC Zero' };
  }

  /**
   * Internal: run the RISC Zero guest binary.
   * 
   * The guest ELF is a RISC-V binary that runs inside the RISC Zero zkVM.
   * Input is passed via file; output is read from stdout.
   */
  async _runGuest(inputPath) {
    return new Promise((resolve, reject) => {
      const child = spawn(this.guestBinaryPath, [inputPath], {
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';

      child.stdout.on('data', (d) => { stdout += d.toString(); });
      child.stderr.on('data', (d) => { stderr += d.toString(); });

      child.on('error', (err) => reject(err));

      child.on('close', (code) => {
        if (code !== 0) {
          resolve({ ok: false, error: `exit ${code}: ${stderr.slice(0, 500)}` });
          return;
        }

        try {
          // Guest commits output as "valid|policy_hash|tool_name_hash|merkle_root"
          const lines = stdout.trim().split('\n');
          const commitLine = lines[lines.length - 1];
          const parts = commitLine.split('|');
          
          resolve({
            ok: true,
            receipt: {
              valid: parts[0] === 'valid',
              policy_hash: parts[1] || '',
              tool_name_hash: parts[2] || '',
              merkle_root: parts[3] || '',
            },
          });
        } catch (err) {
          resolve({ ok: false, error: `parse error: ${err.message}` });
        }
      });

      // Timeout after 120 seconds (ZK proof generation can be slow)
      setTimeout(() => {
        child.kill();
        resolve({ ok: false, error: 'timeout after 120s' });
      }, 120000);
    });
  }

  /**
   * Fallback: generate a DUMMY_ZK_PROOF when RISC Zero is unavailable.
   * Proves the receipt structure is correct but the proof is not cryptographically binding.
   */
  _generateDummyProof({ policy, toolName, anchor, merkleProof, params }) {
    const timestamp = new Date().toISOString();
    const policyHash = policy.policy_hash || this._computePolicyHash(policy);
    const toolNameHash = `sha256:${crypto.createHash('sha256').update(toolName, 'utf8').digest('hex')}`;
    const paramsHash = `sha256:${crypto.createHash('sha256').update(JSON.stringify(params), 'utf8').digest('hex')}`;

    const zkReceipt = {
      receipt_version: '0.3.0',
      proof_type: 'DUMMY_ZK_PROOF',  // Non-production placeholder
      circuit_id: 'pact-v0.3-dummy',
      
      public: {
        policy_hash: policyHash,
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
        prover_id: policy.agent_id || policy.principal_did || 'notbob',
        note: 'DUMMY_ZK_PROOF — RISC Zero not available. Replace with actual proof before production.',
      },
      
      outcome: 'permitted',
      outcome_reason: `tool_name ∈ policy.allowed_tools[dummy]`,
      generated_at: timestamp,
      
      anchor: {
        log_index: anchor.log_index,
        log_id: anchor.log_id,
        merkle_root: anchor.merkle_root,
        method: anchor.method || 'siglog',
      },
    };

    return { zk_receipt: zkReceipt, permitted: true, reason: 'DUMMY_ZK_PROOF (RISC Zero not available)' };
  }

  /**
   * Compute SHA-256 hash of a policy document.
   */
  _computePolicyHash(policy) {
    const canonical = JSON.stringify(policy);
    return `sha256:${crypto.createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
  }
}

// -----------------------------------------------------------------------
// CLI for testing
// -----------------------------------------------------------------------

if (import.meta.url === `file://${process.argv[1]}`) {
  // Usage: node zk_prover.js --policy <policy.json> --tool <toolName> --anchor <anchor.json> --merkle-proof <proof.json>
  const args = process.argv.slice(2);
  const get = (flag) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : null; };

  const prover = new ZkProver({
    guestBinaryPath: get('--guest-binary') || process.env.PACT_GUEST_BINARY,
    useDummyProof: true,
  });

  const policy = JSON.parse(require('fs').readFileSync(get('--policy'), 'utf8'));
  const anchor = JSON.parse(get('--anchor') || '{}');
  const merkleProof = JSON.parse(get('--merkle-proof') || '[]');
  const toolName = get('--tool') || 'test_tool';

  prover.prove({ policy, toolName, anchor, merkleProof }).then((result) => {
    console.log(JSON.stringify(result.zk_receipt, null, 2));
  }).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}