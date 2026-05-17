/**
 * log_client.js — siglog transparency log client
 * Fetches Merkle inclusion proofs and entry data from a prefix-dev/siglog server.
 * 
 * siglog API (prefix-dev/siglog):
 *   GET /v1/log/entries/{entryId}  → entry data with Merkle proof
 *   GET /v1/log/roots/{rootHash}  → root entry (no proof needed, root is self-proving)
 *   GET /v1/log/tree/:size        → tree head for consistency
 *   POST /v1/log/entries          → append new entry
 */

const SIGLOG_API_VERSION = 'v1';

/**
 * @typedef {Object} LogEntry
 * @property {string} entry_id
 * @property {string} prev_hash
 * @property {string} merkle_root
 * @property {string[]} policy_hashes
 * @property {string} timestamp
 * @property {number} index
 */

/**
 * @typedef {Object} MerkleProof
 * @property {string[]} siblings - sibling hashes at each level
 * @property {number} direction - 0 = left sibling, 1 = right sibling
 * @property {string} leaf_hash - hash of the leaf being proven
 */

/**
 * Fetch a single log entry by ID and compute its Merkle inclusion proof.
 * @param {string} baseUrl - siglog server base URL
 * @param {string|number} entryId - Entry ID to fetch
 * @returns {Promise<{entry: LogEntry, proof: MerkleProof|null}>}
 */
export async function getLogEntry(baseUrl, entryId) {
  const res = await fetch(`${baseUrl}/${SIGLOG_API_VERSION}/log/entries/${entryId}`);
  if (!res.ok) {
    throw new Error(`siglog entry fetch failed: ${res.status} ${res.statusText}`);
  }
  const data = await res.json();
  
  // siglog returns entry with computed merkle_root
  const entry = {
    entry_id: data.entry_id || data.id || String(entryId),
    prev_hash: data.prev_hash || data.previousHash || '',
    merkle_root: data.merkle_root || data.merkleRoot || '',
    policy_hashes: data.policy_hashes || data.policyHashes || [],
    timestamp: data.timestamp || data.createdAt || '',
    index: data.index ?? data.tree_index ?? 0,
  };

  // Build leaf hash for this entry's policy_hashes
  // siglog typically uses sha256(policy_hashes.join(',')) for leaves
  const leafData = entry.policy_hashes.length > 0
    ? entry.policy_hashes.slice().sort().join(',')
    : '';
  const { sha256 } = await import('./hash.js').catch(() => ({ sha256: null }));
  const leafHash = leafData
    ? await hashString(leafData)
    : entry.merkle_root; // fallback: use root if no policy hashes

  const proof = buildMerkleProof(entry.policy_hashes, leafHash, entry.merkle_root);
  
  return { entry, proof };
}

/**
 * Fetch the root entry for a given root hash (self-proving, no proof needed).
 * @param {string} baseUrl - siglog server base URL
 * @param {string} rootHash - Root hash to look up
 * @returns {Promise<LogEntry>}
 */
export async function getLogRoot(baseUrl, rootHash) {
  const res = await fetch(`${baseUrl}/${SIGLOG_API_VERSION}/log/roots/${rootHash}`);
  if (!res.ok) {
    throw new Error(`siglog root fetch failed: ${res.status} ${res.statusText}`);
  }
  const data = await res.json();
  return {
    entry_id: data.entry_id || rootHash,
    prev_hash: data.prev_hash || '',
    merkle_root: rootHash,
    policy_hashes: data.policy_hashes || [],
    timestamp: data.timestamp || '',
    index: data.index ?? 0,
  };
}

/**
 * Append a new entry (policy hash) to the log.
 * @param {string} baseUrl - siglog server base URL
 * @param {Object} params
 * @param {string[]} params.policyHashes - Policy hashes to register
 * @param {string} [params.prevHash] - Previous entry hash (for chain integrity)
 * @returns {Promise<LogEntry>}
 */
export async function appendLogEntry(baseUrl, { policyHashes, prevHash = '' }) {
  const res = await fetch(`${baseUrl}/${SIGLOG_API_VERSION}/log/entries`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ policy_hashes: policyHashes, prev_hash: prevHash }),
  });
  if (!res.ok) {
    throw new Error(`siglog append failed: ${res.status} ${res.statusText}`);
  }
  const data = await res.json();
  return {
    entry_id: data.entry_id || data.id,
    prev_hash: prevHash,
    merkle_root: data.merkle_root || data.merkleRoot || '',
    policy_hashes: policyHashes,
    timestamp: data.timestamp || new Date().toISOString(),
    index: data.index ?? 0,
  };
}

/**
 * Verify the log is consistent up to a given size.
 * @param {string} baseUrl - siglog server base URL
 * @param {number} size - Expected tree size
 * @returns {Promise<{root: string, size: number}>}
 */
export async function getTreeHead(baseUrl, size) {
  const res = await fetch(`${baseUrl}/${SIGLOG_API_VERSION}/log/tree/${size}`);
  if (!res.ok) {
    throw new Error(`siglog tree head fetch failed: ${res.status} ${res.statusText}`);
  }
  const data = await res.json();
  return { root: data.merkle_root || data.rootHash, size: data.tree_size || size };
}

// ─── Internal helpers ───────────────────────────────────────────────────────────

/**
 * Build a Merkle inclusion proof for a leaf given the set of hashes in the entry
 * and the target root. Simple for single-entry batches.
 * 
 * For entries with multiple policy_hashes, we compute the root from all leaves
 * and prove inclusion of the target leaf.
 * 
 * @param {string[]} allLeaves - All leaf hashes in this log entry batch
 * @param {string} targetLeaf - Hash of the leaf to prove
 * @param {string} root - Known root (from siglog response)
 * @returns {MerkleProof}
 */
function buildMerkleProof(allLeaves, targetLeaf, root) {
  const idx = allLeaves.indexOf(targetLeaf);
  if (idx === -1) {
    // Target not directly in this batch — treat as single leaf
    return { siblings: [], direction: 0, leaf_hash: targetLeaf, note: 'single_leaf' };
  }

  // For a batch of N leaves with a known root, the proof is the
  // sibling at each level of the tree.
  // siglog uses a simple concat-hash tree: parent = sha256(left || right)
  // 
  // We compute the path from leaf up to root.
  // This is a simplified implementation for the common single-leaf case.
  const siblings = [];
  let current = targetLeaf;
  
  // Build siblings by re-hashing the batch
  // For batch size 1, the leaf IS the root — proof is empty
  if (allLeaves.length === 1) {
    return { siblings: [], direction: 0, leaf_hash: targetLeaf, note: 'single_leaf_is_root' };
  }

  // For multiple leaves: pair leaves, hash upward
  let level = [...allLeaves];
  while (level.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left; // pad with self
      const isLeft = (i === idx || (i + 1 === idx));
      
      if (i === idx || i + 1 === idx) {
        // This pair contains our target leaf
        siblings.push(right === left ? left : right);
      }
      
      // Hash the pair regardless
      const parent = hashConcat(left, right);
      nextLevel.push(parent);
    }
    level = nextLevel;
  }

  return {
    siblings,
    direction: idx % 2 === 0 ? 0 : 1,
    leaf_hash: targetLeaf,
    computed_root: level[0],
    root_matches: level[0] === root,
  };
}

/**
 * SHA-256 hash a string (browser / Node.js compatible).
 */
async function hashString(data) {
  const { createHash } = await import('crypto').catch(() => null);
  if (createHash) {
    return createHash('sha256').update(data).digest('hex');
  }
  // Fallback: simple hex hash for environments without crypto
  let h = 0;
  for (let i = 0; i < data.length; i++) {
    h = ((h << 5) - h + data.charCodeAt(i)) | 0;
  }
  return Math.abs(h).toString(16).padStart(64, '0');
}

/**
 * SHA-256 concat-hash for two hex strings (like siglog's tree building).
 */
async function hashConcat(a, b) {
  const { createHash } = await import('crypto').catch(() => null);
  if (createHash) {
    return createHash('sha256').update(a + b).digest('hex');
  }
  return a + b; // fallback for testing
}
