/**
 * PACT Stdio Interceptor — Layer 0 (stdio transport)
 *
 * Intercepts MCP tool calls via stdio transport without requiring
 * agent modification or PTY. Uses dual-pipe approach:
 *   Parent (agent) → [stdin/stdout] → interceptor → [stdin/stdout] → child (real MCP server)
 *
 * Agent MUST connect to interceptor's stdio instead of the real server's stdio.
 * The interceptor parses JSON-RPC messages, checks policy, generates receipts,
 * then forwards to the real MCP server.
 *
 * Usage (standalone):
 *   node src/interceptor-stdio.js \
 *     --policy ./policy.json \
 *     --anchor '{"log_index":0,"log_id":"...","merkle_root":"..."}' \
 *     --command "npx" \
 *     --args "-y,@modelcontextprotocol/server-filesystem,/tmp"
 *
 * Usage (programmatic):
 *   import { StdioInterceptor } from './interceptor-stdio.js';
 *   const interceptor = new StdioInterceptor({ policy, anchor, command, args });
 *   const child = interceptor.start(); // spawns MCP server
 *   // Agent connects to this process's stdin/stdout instead of direct server stdio
 */

import { spawn } from 'child_process';
import { createInterface } from 'readline';
import { checkToolCall } from './policy.js';
import { generateReceipt } from './receipt.js';
import { generateZkReceipt } from './zk-receipt.js';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

// MCP JSON-RPC message types we care about
const TOOL_CALL_METHODS = ['tools/call', 'tools/callBatch'];

/**
 * StdioInterceptor — intercepts MCP stdio traffic for policy enforcement + receipts.
 *
 * Architecture:
 *   Agent stdin → [Interceptor reads] → [parse JSON-RPC] → [policy check + receipt] → [forward to child stdin]
 *   Child stdout → [Interceptor reads] → [parse JSON-RPC] → [forward to agent stdout]
 *
 * The agent never talks directly to the real MCP server — all traffic goes through the interceptor.
 */
export class StdioInterceptor {
  /**
   * @param {object} config
   * @param {object} config.policy - Committed policy document
   * @param {object} config.anchor - Policy anchor { log_index, log_id, merkle_root }
   * @param {string[]} [config.command] - Command to spawn real MCP server e.g. ['npx', '-y', '@modelcontextprotocol/server-filesystem', '/tmp']
   * @param {string[]} [config.args] - Arguments for the command
   * @param {boolean} [config.useZkReceipts=false] - Use ZK receipts (requires RISC Zero)
   * @param {boolean} [config.blockUnauthorized=true] - Block tool calls not in policy
   * @param {function} [config.onReceipt] - Callback(receipt) for each generated receipt
   */
  constructor({ policy, anchor, command, args = [], useZkReceipts = false, blockUnauthorized = true, onReceipt = null }) {
    this.policy = policy;
    this.anchor = anchor;
    this.command = command;
    this.args = args;
    this.useZkReceipts = useZkReceipts;
    this.blockUnauthorized = blockUnauthorized;
    this.onReceipt = onReceipt || (() => {});

    this.child = null;
    this.receipts = [];
    this.callCount = 0;
    this.sessionId = `pact-stdio-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`;
    this.running = false;

    // Message tracking for request/response pairing
    this.pendingRequests = new Map(); // jsonrpc id → { method, toolName, startTime, agentId }
  }

  /**
   * Start the interceptor — spawn the real MCP server and wire up stdio interception.
   * Returns the child process. Agent should write to this process's stdin;
   * agent should read from this process's stdout.
   *
   * NOTE: The calling process IS the interceptor. This starts the real MCP server
   * as a child and routes agent traffic through this process.
   */
  start() {
    if (!this.command) {
      throw new Error('StdioInterceptor requires a command to spawn the real MCP server');
    }

    console.error(`[PACT Stdio] Spawning: ${this.command.join(' ')}`);
    console.error(`[PACT Stdio] Policy: ${this.policy.policy_hash}`);
    console.error(`[PACT Stdio] BlockUnauthorized: ${this.blockUnauthorized}`);

    this.child = spawn(this.command[0], this.command.slice(1), {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    this.running = true;

    // Wire agent stdin → interceptor → child stdin
    const agentRl = createInterface({ input: process.stdin, crlfDelay: Infinity });
    const childStdin = this.child.stdin;

    agentRl.on('line', (line) => {
      if (!line.trim()) return;
      this._handleAgentMessage(line, childStdin);
    });

    // Wire child stdout → interceptor → agent stdout
    const childRl = createInterface({ input: this.child.stdout, crlfDelay: Infinity });
    childRl.on('line', (line) => {
      if (!line.trim()) return;
      this._handleChildMessage(line, process.stdout);
    });

    // Log child stderr
    this.child.stderr.on('data', (chunk) => {
      console.error(`[MCP Server stderr]: ${chunk.toString().trim()}`);
    });

    this.child.on('close', (code) => {
      console.error(`[PACT Stdio] MCP server exited with code ${code}`);
      this.running = false;
    });

    this.child.on('error', (err) => {
      console.error(`[PACT Stdio] Child error: ${err.message}`);
    });

    return this.child;
  }

  /**
   * Handle a JSON-RPC message from the agent.
   * Parse, check policy, generate receipt, forward to real MCP server.
   * @param {string} line - Raw JSON-RPC line from agent stdin
   * @param {import('stream').Writable} forwardTo - Stream to write forwarded message to
   */
  _handleAgentMessage(line, forwardTo) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      // Not JSON or malformed — forward as-is
      forwardTo.write(line + '\n');
      return;
    }

    // Only intercept tool call requests
    if (msg.method && TOOL_CALL_METHODS.includes(msg.method)) {
      this._interceptToolCall(msg, forwardTo, line);
    } else {
      // Pass through: initialize, tools/list, etc.
      forwardTo.write(line + '\n');
    }
  }

  /**
   * Handle a JSON-RPC message from the MCP server (response).
   * Forward to agent; attach receipt metadata if available.
   * @param {string} line - Raw JSON-RPC line from child stdout
   * @param {import('stream').Writable} forwardTo - Stream to write to (agent stdout)
   */
  _handleChildMessage(line, forwardTo) {
    // In a full implementation we'd match responses to requests and attach receipt metadata
    // For now: forward as-is
    forwardTo.write(line + '\n');
  }

  /**
   * Intercept a tools/call request from the agent.
   * Check policy, generate receipt, either block or forward.
   */
  async _interceptToolCall(msg, forwardTo, rawLine) {
    this.callCount++;
    const callId = `${this.sessionId}-${this.callCount}`;
    const startTime = new Date().toISOString();

    // Extract tool name from params
    const params = msg.params || {};
    const toolCalls = Array.isArray(params) ? params : [params];
    const primaryTool = toolCalls[0]?.name || 'unknown';

    console.error(`[PACT Stdio] Tool call #${this.callCount}: ${primaryTool}`);

    // Check against committed policy
    const policyCheck = checkToolCall(this.policy, primaryTool, toolCalls[0]?.arguments || {});

    if (!policyCheck.permitted) {
      console.error(`[PACT Stdio] BLOCKED: ${primaryTool} — ${policyCheck.reason}`);
      
      // Generate blocked receipt
      const blockedReceipt = {
        receipt_id: callId,
        blocked: true,
        tool_name: primaryTool,
        reason: policyCheck.reason,
        policy_hash: this.policy.policy_hash,
        anchor_log_index: this.anchor.log_index,
        anchor_log_id: this.anchor.log_id,
        timestamp: startTime,
        session_id: this.sessionId,
      };
      this.receipts.push(blockedReceipt);
      this.onReceipt(blockedReceipt);

      if (this.blockUnauthorized) {
        // Return error to agent — don't forward to server
        const errorResp = {
          jsonrpc: '2.0',
          id: msg.id,
          error: {
            code: -32000,
            message: `PACT policy violation: tool '${primaryTool}' is not permitted under committed policy (hash: ${this.policy.policy_hash.slice(0, 16)}...)`,
          }
        };
        process.stdout.write(JSON.stringify(errorResp) + '\n');
        return;
      }
    }

    // Generate receipt for permitted call
    let receipt;
    if (this.useZkReceipts) {
      try {
        const { zk_receipt } = await generateZkReceipt({
          policy: this.policy,
          toolName: primaryTool,
          anchor: this.anchor,
          params: toolCalls[0]?.arguments || {},
        });
        receipt = zk_receipt;
      } catch (e) {
        console.error(`[PACT Stdio] ZK receipt generation failed: ${e.message} — falling back to v0.1`);
        const { receipt: v01 } = generateReceipt({
          policy: this.policy,
          toolName: primaryTool,
          params: toolCalls[0]?.arguments || {},
        });
        receipt = v01;
      }
    } else {
      const { receipt: v01 } = generateReceipt({
        policy: this.policy,
        toolName: primaryTool,
        params: toolCalls[0]?.arguments || {},
      });
      receipt = v01;
    }

    // Enrich with PACT anchor metadata
    receipt.action_id = callId;
    receipt.anchor_log_index = this.anchor.log_index;
    receipt.anchor_log_id = this.anchor.log_id;
    receipt.policy_hash = this.policy.policy_hash;
    receipt.timestamp = startTime;
    receipt.session_id = this.sessionId;
    receipt.permitted = true;

    this.receipts.push(receipt);
    this.onReceipt(receipt);

    console.error(`[PACT Stdio] PERMITTED: ${primaryTool} | receipt: ${receipt.receipt_id}`);

    // Attach receipt to the forwarded request as an extension header
    // (MCP servers that support extensions will see it; others ignore)
    const forwardedParams = { ...params };
    forwardedParams._pact = {
      receipt_id: receipt.receipt_id,
      policy_hash: this.policy.policy_hash.slice(0, 16),
      log_index: this.anchor.log_index,
    };

    const forwardedMsg = {
      jsonrpc: msg.jsonrpc || '2.0',
      id: msg.id,
      method: msg.method,
      params: forwardedParams,
    };

    forwardTo.write(JSON.stringify(forwardedMsg) + '\n');
  }

  /**
   * Get all receipts generated in this session.
   */
  getReceipts() {
    return [...this.receipts];
  }

  /**
   * Stop the interceptor and kill the MCP server child process.
   */
  stop() {
    if (this.child) {
      this.child.kill();
    }
    this.running = false;
    console.error(`[PACT Stdio] Stopped. Total receipts: ${this.receipts.length}`);
  }
}

// -----------------------------------------------------------------------
// CLI entry point
// -----------------------------------------------------------------------

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  
  // Minimal argparse for CLI usage
  const parsed = {};
  let i = 0;
  while (i < args.length) {
    if (args[i] === '--policy') { parsed.policy = args[++i]; continue; }
    if (args[i] === '--anchor') { parsed.anchor = JSON.parse(args[++i]); continue; }
    if (args[i] === '--command') { parsed.command = args[++i].split(','); continue; }
    if (args[i] === '--args') { parsed.args = args[++i].split(','); continue; }
    if (args[i] === '--zk') { parsed.useZkReceipts = true; continue; }
    if (args[i] === '--allow-unaudited') { parsed.blockUnauthorized = false; continue; }
    i++;
  }

  if (!parsed.policy || !parsed.anchor || !parsed.command) {
    console.error('Usage: node interceptor-stdio.js --policy <file> --anchor <json> --command <cmd>[,<arg1>,<arg2>]');
    console.error('Example: node interceptor-stdio.js --policy ./policy.json --anchor \'{"log_index":0,"log_id":"...","merkle_root":"..."}\' --command npx --args -y,@modelcontextprotocol/server-filesystem,/tmp');
    process.exit(1);
  }

  const policy = JSON.parse(fs.readFileSync(parsed.policy, 'utf8'));
  const fullCommand = parsed.args ? [parsed.command, ...parsed.args] : parsed.command.split(',');

  const interceptor = new StdioInterceptor({
    policy,
    anchor: parsed.anchor,
    command: fullCommand,
    useZkReceipts: parsed.useZkReceipts,
    blockUnauthorized: parsed.blockUnauthorized !== false,
  });

  interceptor.start();

  // Handle shutdown signals
  process.on('SIGINT', () => { interceptor.stop(); process.exit(0); });
  process.on('SIGTERM', () => { interceptor.stop(); process.exit(0); });
}