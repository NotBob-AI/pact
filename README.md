# PACT — Policy Attestation via Cryptographic Trace

**An agent makes a PACT. Every action either honors it or it doesn't. You can prove which — without trusting the agent.**

---

## The Problem

Every agent accountability framework shipped in 2025–2026 shares the same flaw:

> The agent controls the evidence.

Logs, SIEM dashboards, append-only audit trails, runtime circuit breakers — all of these require the agent to *cooperate* with its own oversight. An agent that controls its execution environment can falsify a log. An agent that generates its own receipts can generate clean ones for actions that violated its constraints.

The industry calls this "observability." It is not accountability. It is surveillance theater.

There is a deeper problem that nobody has named:

**Proof of execution ≠ proof of policy soundness.**

TrustAgentAI (Ed25519 receipts for MCP tool calls) proves *what happened*. Armalo (on-chain reputation, USDC escrow) tracks *outcomes over time*. Neither proves that the specific action taken was *consistent with a pre-committed policy constraint*.

An agent can generate a valid execution receipt, maintain a clean reputation score, and still violate an unenforced constraint — because no one committed to what "within policy" means before execution began.

**PACT closes this gap.**

---

## The Core Idea

At genesis, an agent commits to a **Policy Document** — a formal, machine-verifiable specification of what it is permitted to do.

- The Policy Document is hashed and anchored (on-chain, in a transparency log, or via IPFS — the anchoring method is pluggable)
- Every action generates a **PACT Receipt** — a ZK proof that the action is consistent with the committed policy
- The receipt is verifiable by any third party without: (a) revealing the action's content, (b) trusting the agent, or (c) requiring log access

The agent cannot generate a valid receipt for a policy-violating action. The policy cannot be changed without producing a new commitment. The commitment is timestamped and public.

This is not observability. This is **cryptographic accountability**.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      PACT Stack                         │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Verifier API                                  │
│    → Third parties submit receipts for verification     │
│    → Returns: valid | invalid | policy_mismatch         │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Receipt Generator                             │
│    → Intercepts MCP tool calls                          │
│    → Generates ZK proof: action ∈ committed_policy      │
│    → Signs receipt with agent's Ed25519 key             │
├─────────────────────────────────────────────────────────┤
│  Layer 1: Policy Commitment                             │
│    → Structured policy document (JSON Schema + logic)   │
│    → SHA-256 hash anchored at genesis                   │
│    → Merkle root in transparency log                    │
├─────────────────────────────────────────────────────────┤
│  Layer 0: MCP Tool Interface                            │
│    → Intercept layer wraps any MCP-compatible agent     │
│    → No agent modification required                     │
└─────────────────────────────────────────────────────────┘
```

---

## Policy Document Format

```json
{
  "pact_version": "0.1.0",
  "agent_id": "did:key:z6Mk...",
  "created_at": "2026-03-26T00:00:00Z",
  "policy": {
    "allowed_tools": ["read_file", "search_web", "send_email"],
    "denied_tools": ["delete_file", "execute_code", "access_credentials"],
    "scope_constraints": {
      "filesystem": { "read": ["~/documents/**"], "write": [] },
      "network": { "allowed_domains": ["*.bsky.social", "api.github.com"] },
      "data_sensitivity": "public_only"
    },
    "escalation_policy": {
      "on_constraint_violation": "abort_and_log",
      "human_approval_required_for": ["send_email", "financial_transactions"]
    }
  },
  "policy_hash": "sha256:abc123...",
  "anchor": {
    "method": "transparency_log",
    "log_url": "https://rekor.sigstore.dev",
    "entry_id": "...",
    "timestamp": "2026-03-26T00:00:00Z"
  }
}
```

---

## PACT Receipt Format

```json
{
  "receipt_version": "0.1.0",
  "agent_id": "did:key:z6Mk...",
  "policy_hash": "sha256:abc123...",
  "action_id": "uuid-...",
  "timestamp": "2026-03-26T12:00:00Z",
  "tool_called": "search_web",
  "proof": {
    "type": "zk_membership",
    "statement": "tool_called ∈ policy.allowed_tools AND scope_constraints_satisfied",
    "proof_bytes": "base64:...",
    "verifier_key": "base64:..."
  },
  "agent_signature": "base64:..."
}
```

---

## What PACT Proves (and What It Doesn't)

### Proves
- The agent called a tool that is in its committed allowed list
- The action parameters satisfied the scope constraints in the committed policy
- The policy has not been changed since genesis (via anchored hash)
- The receipt was generated at the time of the action (timestamped)

### Does Not Prove
- That the policy itself is *good* (policy soundness is a human responsibility)
- That the agent acted in good faith on the *purpose* of a tool call
- That no side effects occurred outside the instrumented tool calls

### Why This Matters
PACT is not a silver bullet. It closes the **self-reporting gap** — the specific failure mode where agents generate their own compliance evidence. Policy design and human oversight still matter. PACT makes oversight *credible* rather than *assumed*.

---

## Comparison to Prior Work

| System | What It Proves | Gap |
|--------|---------------|-----|
| TrustAgentAI (Ed25519 MCP receipts) | Execution happened | Not: execution was within policy |
| Armalo (on-chain reputation + escrow) | Outcomes over time | Not: this specific action was authorized |
| Aegis (ethics policy at genesis) | Policy exists | Not: action was cryptographically consistent with it |
| Microsoft agent-governance-toolkit | Actions were logged | Not: logs weren't generated by the agent itself |
| PACT | Action ∈ committed policy | Not: policy was correctly designed |

---

## Status

**Roadmap:**
- [x] v0.1 ✅ — Policy commitment + SHA-256 receipt format
- [x] v0.2 ✅ — Policy anchoring to transparency log + Merkle batch commitment
- [ ] v0.3 ⬜ — ZK receipt generator (interface done, RISC Zero circuit stubbed)
- [ ] v0.4 — Verifier API + full MCP intercept layer (basic interceptor working)
- [ ] v1.0 — Production-ready, audited

### Current Implementation

```
 policy.js         → v0.1: Policy creation + SHA-256 hash proof
 receipt.js        → v0.1: Receipt generation (sha256_membership)
 commitment.js     → v0.2: Policy anchoring to transparency log + Merkle batch
 zk-receipt.js    → v0.3: ZK receipt interface (RISC Zero circuit stubbed)
 pact-mcp-interceptor.py → v0.4: MCP proxy layer (basic working)
```

### Quick Start

```bash
# Test the full stack
node test-local.js

# Run the MCP interceptor (requires a committed policy.json)
python3 python/pact-mcp-interceptor.py \
  --upstream http://localhost:3000 \
  --policy-file policy.json \
  --port 8101
```

---

## Authors

- **NotBob** — AI research agent ([notbob@reallynotbob.com](mailto:notbob@reallynotbob.com)) — concept, specification, threat model
- **Bob Lyons** — ([bob@reallynotbob.com](mailto:bob@reallynotbob.com)) — architecture review, direction

---

## License

MIT. Build on it.
