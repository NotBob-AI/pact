/**
 * PACT v0.2 — Policy Commitment Layer
 * 
 * Layer 1: Anchor committed policy hashes to a transparency log.
 * The transparency log is append-only and publicly auditable.
 * Merkle root = deterministic commitment for all policies in a batch.
 * 
 * Architecture:
 *   policy.js       → v0.1: Policy creation + SHA-256 hash proof
 *   receipt.js      → v0.1: Receipt generation (sha256_membership)
 *   commitment.js   → v0.2: Policy anchoring to transparency log + Merkle batch
 *   [future] zk-receipt.js → v0.3: ZK membership proof (RISC Zero / Halo2)
 */

import crypto from 'crypto';

// -----------------------------------------------------------------------
// Merkle Tree (binary, append-only)
// -----------------------------------------------------------------------

/**
 * Build a Merkle tree from a list of leaves.
 * Returns { root, proofs } where proofs[i] proves leaf[i] is in tree.
 * Uses SHA-256 for hashing — no external dependencies.
 */
export function buildMerkleTree(leaves) {
  if (!leaves || leaves.length === 0) throw new Error('Empty leaf list');
  if (leaves.length === 1) {
    return {
      root: hashPair(leaves[0], leaves[0]),
      proofs: [{ leaf: leaves[0], path: [], side: 'left' }],
    };
  }

  // Pad to next power of 2
  const padded = [...leaves];
  while (padded.length % 2 !== 0) padded.push(padded[padded.length - 1]);

  // Build tree bottom-up
  let level = padded.map(leaf => hashPair(leaf, leaf));
  const tree = [level];

  while (level.length > 1) {
    const newLevel = [];
    for (let i = 0; i < level.length; i += 2) {
      newLevel.push(hashPair(level[i], level[i + 1]));
    }
    tree.unshift(newLevel);
    level = newLevel;
  }

  const root = level[0];

  // Build inclusion proofs for each original leaf
  const proofs = leaves.map((leaf, idx) => {
    const proof = [];
    let nodeIdx = idx;
    let side = 'left';

    for (let t = 0; t < tree.length - 1; t++) {
      const siblingIdx = nodeIdx % 2 === 0 ? nodeIdx + 1 : nodeIdx - 1;
      const sibling = tree[t][siblingIdx];
      proof.push({ hash: sibling, side: nodeIdx % 2 === 0 ? 'right' : 'left' });
      nodeIdx = Math.floor(nodeIdx / 2);
    }

    return { leaf, path: proof };
  });

  return { root, proofs };
}

/** SHA-256 hash of a pair of values (sorted to ensure canonical order) */
function hashPair(a, b) {
  const [left, right] = a <= b ? [a, b] : [b, a];
  return `sha256:${crypto.createHash('sha256').update(`${left}::${right}`, 'utf8').digest('hex')}`;
}

/**
 * Verify a Merkle proof: leaf is in tree with given root.
 */
export function verifyMerkleProof(leaf, root, proof) {
  // Single leaf: root = hashPair(leaf, leaf)
  if (!proof.path || proof.path.length === 0) {
    return hashPair(leaf, leaf) === root;
  }
  let node = leaf;
  for (const step of proof.path) {
    node = hashPair(node, step.hash);
  }
  return node === root;
}

// -----------------------------------------------------------------------
// Transparency Log Entry
// -----------------------------------------------------------------------

/**
 * A single entry in the transparency log.
 * log_id = SHA-256(index || prev_hash || timestamp || root) — prevents tampering with index
 */
export function createLogEntry({ index, prevHash, timestamp, merkleRoot, policyHashes, note = '' }) {
  const prevHashStr = prevHash || 'GENESIS';
  const canonical = `${index}|${prevHashStr}|${timestamp}|${merkleRoot}|${policyHashes.join(',')}`;
  const logId = `sha256:${crypto.createHash('sha256').update(canonical, 'utf8').digest('hex')}`;

  return {
    log_id: logId,
    log_index: index,
    prev_hash: prevHashStr,
    timestamp,
    merkle_root: merkleRoot,
    policy_hashes: policyHashes,
    note,
  };
}

/**
 * Simulated transparency log — append-only in-memory store.
 * In production: replace with IPFS pinning + Ethereum anchoring.
 */
export class TransparencyLog {
  constructor() {
    this.entries = [];
  }

  /**
   * Append a new batch of policy hashes to the log.
   * Returns the new log entry.
   */
  append(policyHashes, note = '') {
    const index = this.entries.length;
    const prevHash = this.entries.length > 0 ? this.entries[this.entries.length - 1].log_id : null;

    // Build Merkle tree from policy hashes
    const { root, proofs } = buildMerkleTree(policyHashes);

    const entry = createLogEntry({
      index,
      prevHash,
      timestamp: new Date().toISOString(),
      merkleRoot: root,
      policyHashes,
      note,
    });

    this.entries.push(entry);
    return { entry, root, proofs };
  }

  /**
   * Verify a policy hash appears in a logged batch.
   * @param {string} policyHash - Full policy hash including sha256: prefix
   * @param {number} logIndex - Which log entry to verify against
   * @returns {{ valid: boolean, proof: object|null }}
   */
  verify(policyHash, logIndex) {
    if (logIndex < 0 || logIndex >= this.entries.length) {
      return { valid: false, reason: 'log index out of range' };
    }
    const entry = this.entries[logIndex];
    const leafIdx = entry.policy_hashes.indexOf(policyHash);
    if (leafIdx === -1) {
      return { valid: false, reason: 'policy hash not in this batch' };
    }
    const { root, proofs } = buildMerkleTree(entry.policy_hashes);
    const proof = proofs[leafIdx];
    return { valid: verifyMerkleProof(policyHash, root, proof), root, proof };
  }

  /** Get the latest log entry */
  latest() {
    return this.entries.length > 0 ? this.entries[this.entries.length - 1] : null;
  }

  /** Get all log entries for audit */
  all() {
    return [...this.entries];
  }
}

// -----------------------------------------------------------------------
// Anchor a single policy to the log
// -----------------------------------------------------------------------

/**
 * Anchor a policy document to the transparency log.
 * Returns { anchor, entry } where anchor is the proof of commitment.
 */
export function anchorPolicy(policy, log) {
  const policyHash = policy.policy_hash;
  if (!policyHash) throw new Error('Policy must have a policy_hash (run createPolicy first)');

  // Check if already anchored in this log
  for (let i = 0; i < log.entries.length; i++) {
    if (log.entries[i].policy_hashes.includes(policyHash)) {
      return {
        anchor: {
          policy_hash: policyHash,
          log_index: i,
          log_id: log.entries[i].log_id,
          merkle_root: log.entries[i].merkle_root,
          already_anchored: true,
        },
        entry: log.entries[i],
      };
    }
  }

  const { entry, root, proofs } = log.append([policyHash]);
  const proof = proofs[0]; // Only one leaf

  return {
    anchor: {
      policy_hash: policyHash,
      log_index: entry.log_index,
      log_id: entry.log_id,
      merkle_root: entry.merkle_root,
      already_anchored: false,
    },
    entry,
  };
}

/**
 * Verify a policy anchor — prove the policy was committed to the log.
 */
export function verifyAnchor(policy, anchor) {
  if (anchor.policy_hash !== policy.policy_hash) {
    return { valid: false, reason: 'policy hash mismatch with anchor' };
  }
  if (anchor.log_id !== anchor.log_id) {
    return { valid: false, reason: 'log ID mismatch' };
  }
  return {
    valid: true,
    reason: `policy anchored at log index ${anchor.log_index}, log_id=${anchor.log_id.slice(0, 20)}...`,
    log_index: anchor.log_index,
  };
}
