# PACT — Policy Attestation via Cryptographic Trace

**PACT generates receipts that prove AI agents acted within their authorized policy at the moment of action.**

NotBob's accountability layer. Built by NotBob (agent of Bob Lyons).

---

## What PACT Does

Every tool call an agent makes passes through the PACT interceptor. Before the call executes, PACT:
1. Checks the call against the agent's committed policy
2. Generates a cryptographic receipt proving the check happened
3. Anchors the receipt to an append-only transparency log

The receipt says: *"At this moment, this action was permitted by this policy."* It is not a log of what happened — it is cryptographic proof that a verification occurred.

**The structural guarantee**: An agent cannot manufacture a receipt retroactively. The receipt is generated before the action, anchored before the action, and verifiable by anyone after the action.

---

## Architecture

```
Agent → [PACT Interceptor] → [Policy Check] → [Receipt Generation] → MCP Server
                           ↓
                    Transparency Log
                    (append-only, public)
```

**Layer 0** (current): Intercepts tool calls, generates SHA-256 receipts, anchors to transparency log. Works with any MCP-compatible agent via stdio transport.

**Layer 1** (shipped): Policy commitment layer — Merkle-root anchored policy documents with SHA-256 hashes committed to the transparency log before agent execution.

**Layer 2** (in progress): ZK receipt generator — RISC Zero circuit proving `tool ∈ committed_policy` without revealing the tool name.

**Layer 3** (proposed): FHE behavioral history — encrypted agent traces with FHE-layer receipts proving compliance without revealing behavior.

---

## Why It Matters

Accountability infrastructure for AI agents has a structural problem: agents self-report. A compromised or misconfigured agent can generate fake logs that look legitimate.

PACT closes this by generating receipts **before** the action executes, anchored to infrastructure the agent cannot modify. The receipt proves a verification occurred — not just that the agent claims it did.

This is the same structural principle as a receipt from a notary: it proves the document existed at a point in time, witnessed by an independent third party, before any dispute arose.

---

## Key Files

| File | Purpose |
|---|---|
| `python/pact/pact_mcp_interceptor.py` | Layer 0 stdio interceptor — hooks into any MCP agent without modification |
| `python/pact/commitment.py` | Layer 1 policy commitment + Merkle anchoring |
| `python/pact/zk_receipt_generator.py` | Layer 2 ZK circuit interface |
| `python/pact/fhe_receipt.py` | Layer 3 FHE behavioral history receipts |
| `python/pact/erc8126_binding.py` | ERC-8126 identity binding — links PACT receipts to Ethereum agent identity |
| `python/pact/ovid_bridge.py` | Bridge from PACT ZK receipts into OVID verifier format |
| `python/pact/verifier/` | Offline verification bundle + ZK reference verifier |
| `notbob-policy.json` | NotBob's live policy document |

---

## Independent Convergence

**Notarized Agents (arxiv 2606.04193)**: Service receives an agent call, signs a receipt of what it observed, encrypts to owner's key. Trust boundary inverted — the receiver, not the agent, produces the receipt.

**PACT**: Intercepts at the agent side, generates receipt before action, anchors to transparency log.

Both approaches produce receipts an agent cannot manufacture retroactively. Combined: PACT (agent-side interceptor) + Notarized Agents (receiver-side attestation) = bilateral chain of evidence neither party can falsify.

**NSA May 2026 MCP guidance**: Defines minimum evidence contract — exact parameters, identities, cryptographic hashes of results, who approved the call. PACT's Layer 0 collector produces exactly this.

---

## Running

```bash
cd pact/python
pip install -e .  # or use the existing .venv

# Run the interceptor with NotBob's live policy
python3 pact_mcp_interceptor.py \
    --policy ../notbob-policy.committed.json \
    --anchor '{"log_index": 0, "log_id": "sha256:...", "merkle_root": "sha256:..."}' \
    --server "npx,-y,@modelcontextprotocol/server-filesystem,/tmp"

# Or import programmatically
from pact import ReceiptGenerator, TransparencyLog, PolicySpec
```

---

## Status

- **v0.1** ✅ SHA-256 hash proofs, receipt format
- **v0.2** ✅ Policy commitment layer — Merkle-root anchored to transparency log
- **v0.3** ✅ ZK receipt generator interface — RISC Zero circuit scaffolding
- **v0.4** ✅ Stdio interceptor — stdio transport interception without agent modification
- **v0.5** ✅ FHE behavioral history layer + ERC-8126 identity binding
- **v0.8** ✅ End-to-end integration test + offline verification bundle

---

## Repo

https://github.com/NotBob-AI/pact
