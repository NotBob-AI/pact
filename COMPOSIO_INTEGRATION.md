# PACT Integration: Composio CLI Wrapper

## Architecture

```
OpenClaw Agent
    ↓ (tool call)
Composio CLI (via StdioInterceptor)
    ↓ (receipted + forwarded)
Real Composio API
    ↓
GitHub Actions API
```

The StdioInterceptor wraps Composio's CLI. Every `composio execute` call is:
1. Parsed and checked against PACT policy
2. Receipt generated with timestamp, tool name, params hash
3. Forwarded to Composio API
4. Response returned to agent

## Quick Start

```bash
# Test the interceptor inline
node pact/src/interceptor-stdio.js \
  --policy pact/policy.json \
  --anchor '{"log_index":1,"log_id":"test","merkle_root":"abc"}' \
  --command echo \
  --args "hello,world"
```

## Real Deployment (requires Composio API key)

```bash
# Wrap composio execute calls
COMPOSIO_API_KEY=sk_xxx \
node pact/src/interceptor-stdio.js \
  --policy pact/policy.json \
  --anchor "{\"log_index\":1,\"log_id\":\"$(date +%s)\",\"merkle_root\":\"$(openssl rand -hex 32)\"}" \
  --command composio \
  --args "execute,GITHUB_CREATE_PULL_REQUEST,--account,github_avick-bios,-d,\"JSONPayloadHere\""
```

## Policy Configuration

Edit `pact/policy.json` to list permitted Composio action slugs:

```json
{
  "policy_id": "notbob-composio-v1",
  "policy_hash": "sha256:...",
  "allowed_tools": [
    "GITHUB_CREATE_PULL_REQUEST",
    "GITHUB_GET_REPOSITORY",
    "GITHUB_LIST_ACTIONS_WORKFLOWS",
    ...
  ]
}
```

## OpenClaw Agent Integration

When OpenClaw supports stdio MCP interception natively, set in agent config:

```yaml
mcp:
  servers:
    composio:
      type: stdio
      command: node
      args:
        - /path/to/pact/src/interceptor-stdio.js
        - --policy
        - /path/to/pact/policy.json
        - --anchor
        - '{"log_index":0,"log_id":"...","merkle_root":"..."}'
        - --command
        - composio
        - --args
        - execute
```

## Next Steps

1. **Composio action slug inventory** — dump all permitted slugs into policy.json
2. **Anchor commitment** — integrate with Bob's transparency log (TBD provider)
3. **Receipt storage** — append receipts to local log after each composio execute
4. **OpenClaw native stdio support** — file feature request

## Verification

```bash
# Dry-run a tool without executing
composio execute GITHUB_GET_REPOSITORY --get-schema --dry-run

# After integration, the interceptor logs:
# [PACT Stdio] PERMITTED: GITHUB_GET_REPOSITORY | receipt: pact-stdio-xxx
# [PACT Stdio] MCP server stdout: {json response...}
```