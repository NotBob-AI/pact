# PACT v0.4 — Stdio Interceptor Specification

> Status: **SPEC DRAFT** — Not yet implemented
> Heartbeat: 2026-05-22
> PREREQUISITE: v0.3 (ZK receipts) ✓ shipped

---

## Motivation

v0.3 shipped ZK receipts proving `action ∈ committed_policy`. But the receipt generator requires a running agent to call it. The agent controls when and how receipts are generated — that reintroduces the self-reporting gap.

The interceptor is the architectural fix: a layer between the agent and its MCP servers that intercepts every tool call, enforces policy, and generates receipts **before** the agent can decide not to.

v0.4 adds the stdio transport interceptor. This is the most common deployment: agents using MCP STDIO transport to communicate with tools.

---

## Design

### The Problem with STDIO

Most local AI agents communicate with tools via STDIO (stdin/stdout JSON-RPC). The agent spawns an MCP server as a subprocess and talks to it through pipes. There is no network, no HTTP — just bytes flowing between processes.

The challenge: you cannot simply "tap" a subprocess's stdin/stdout without being in the middle. You have to route the traffic through the interceptor.

### The Dual-Pipe Architecture

```
Agent (process)
    stdin ──┬──► [Interceptor reads] ──► [policy check + receipt] ──► [child stdin] ──► MCP Server
    stdout ─┴── [Interceptor reads] ◄── [response forward] ◄───────── [child stdout] ◄─┘
```

The interceptor **replaces** the MCP server. The agent never connects directly to the real server. All traffic flows through the interceptor which:
1. Parses JSON-RPC messages from the agent
2. Checks the tool call against committed policy
3. Generates a PACT receipt
4. Forwards the request to the real MCP server (or blocks it)
5. Returns the server's response to the agent

### Enforcement Modes

| Mode | Behavior |
|------|----------|
| `block` | Policy-violating calls return an error to the agent; no server request made |
| `audit` | Policy-violating calls are forwarded but logged as violations |
| `warn` | Policy-violating calls are forwarded with a warning header attached |

The default is `block`. `audit` and `warn` are for deployment staging.

### Receipt Generation

Receipts are generated **before** the tool call is forwarded to the MCP server. This matters:

- The receipt proves the call was checked, not just that it succeeded
- A blocked call generates a `blocked_receipt` — the denial itself is on the record
- The receipt is written to local storage and/or forwarded to the transparency log

### ZK Receipt Integration

When `useZkReceipts=true`, the interceptor:
1. Fetches the Merkle inclusion proof from the transparency log (siglog)
2. Calls the ZK prover (RISC Zero via `zk_host.py`)
3. Embeds the ZK proof in the PACT receipt

The ZK circuit proves: `tool_name ∈ allowed_tools AND scope_constraints_satisfied`

### STDIO Message Flow

```
Agent → JSON-RPC { method: "tools/call", params: { name: "read_file", arguments: {...} } }
         ↓ interceptor parses
Policy check: read_file ∈ allowed_tools? scope_constraints satisfied?
         ↓
[RECEIPT GENERATED — ZK or v0.1 Ed25519]
         ↓
If permitted: forward to MCP server, return response with _pact metadata
If blocked: return PACT policy error to agent, don't forward
```

### The `onReceipt` Callback

The interceptor accepts an `onReceipt` callback invoked for each receipt generated. This allows:
- Async receipt upload to transparency log
- Local receipt storage
- Real-time monitoring dashboards

---

## Deployment

### Agent Integration (TypeScript)

```typescript
import { StdioInterceptor } from '@notbob/pact';

const policy = JSON.parse(fs.readFileSync('./my-policy.committed.json'));
const anchor = JSON.parse(fs.readFileSync('./my-policy.anchor.json'));

const interceptor = new StdioInterceptor({
  policy,
  anchor,
  command: ['npx', '-y', '@modelcontextprotocol/server-filesystem', '/tmp'],
  args: [],
  useZkReceipts: true,
  logUrl: 'https://siglog.example.com',
  blockUnauthorized: true,
  onReceipt: (receipt) => {
    // Upload to transparency log
    fetch('https://siglog.example.com/v1/log/entries', {
      method: 'POST',
      body: JSON.stringify(receipt),
    });
  },
});

// Agent connects to interceptor's stdin/stdout instead of direct server
const child = interceptor.start();

// Agent writes to process.stdin, reads from process.stdout
// Interceptor handles everything else
```

### CLI Usage

```bash
node src/interceptor-stdio.js \
  --policy ./my-policy.committed.json \
  --anchor '{"log_index": 42, "log_id": "sha256:abc...", "merkle_root": "sha256:xyz..."}' \
  --command npx \
  --args -y,@modelcontextprotocol/server-filesystem,/tmp \
  --zk \
  --log-url https://siglog.example.com
```

---

## Implementation Checklist

- [x] `interceptor-stdio.js` — core dual-pipe interception (shipped in v0.3 refactor)
- [x] `log_client.js` — siglog Merkle proof fetching (shipped v0.3)
- [x] `zk_prover.js` — RISC Zero bridge (shipped v0.3)
- [x] `policy.js` — tool call policy checker (shipped v0.3)
- [ ] `onReceipt` async upload to siglog (not hooked up yet)
- [ ] Python `pact-mcp-interceptor.py` — native Python stdio interceptor for non-Node agents
- [ ] Integration test: agent connects via interceptor, receipts written to siglog
- [ ] Documentation: how to point any MCP agent at the interceptor

---

## Open Questions

1. **Blocking vs. warning default**: Block (hard enforcement) vs. warn (soft enforcement) — which should be the default? Block is safer but breaks agents that rely on fallthrough behavior.

2. **Batched receipts**: For high-frequency tool calls, should receipts be batched and written to log in groups? (Tradeoff: latency vs. log throughput cost)

3. **Inter-agent communication**: When agent A calls agent B via MCP, who generates the receipt? Both sides need policy commitments. Currently unimplemented.

4. **MCP transport variants**: Beyond STDIO, there is also HTTP+SSE. The interceptor needs an HTTP variant for cloud-deployed agents.

---

## Connection to PACT v0.3

v0.3 shipped the ZK receipt generator. v0.4 puts it to use: every tool call intercepted by v0.4 generates a v0.3 receipt. The interceptor is the deployment mechanism for the receipt generator.

Without v0.4, PACT receipts are generated by the agent itself (after-action reporting). With v0.4, receipts are generated before the action — the agent cannot suppress or modify them.

---

## References

- MCP STDIO Transport spec: https://modelcontextprotocol.io/docs/concepts/transports
- RISC Zero prover: `python/pact/zk_host.py`
- siglog transparency log: `src/log_client.js`
- Existing stdio interceptor: `src/interceptor-stdio.js`