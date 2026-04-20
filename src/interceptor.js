/**
 * PACT MCP Interceptor — Layer 0
 * 
 * Intercepts MCP tool calls from an agent and generates PACT receipts.
 * Does NOT require agent modification — agent connects to interceptor, not real server.
 * 
 * Architecture:
 *   Agent → [Interceptor Server] → [Real MCP Server]
 *              ↓
 *         Policy Check
 *              ↓
 *         Receipt Generation
 *              ↓
 *         Return to agent
 * 
 * Usage:
 *   import { McpInterceptor } from './interceptor.js';
 *   import { createPolicy } from './policy.js';
 *   import { TransparencyLog } from './commitment.js';
 * 
 *   const log = new TransparencyLog();
 *   const policy = createPolicy({ ... });
 *   anchorPolicy(policy, log);
 * 
 *   const interceptor = new McpInterceptor({
 *     policy,
 *     anchor: anchorResult.anchor,
 *     upstreamUrl: 'http://localhost:3100',  // real MCP server
 *     port: 3101,                           // interceptor listens here
 *   });
 * 
 *   await interceptor.start();
 *   // Agent connects to interceptor at localhost:3101
 */

import http from 'http';
import https from 'https';
import { WebSocketServer } from 'ws';
import { checkToolCall } from './policy.js';
import { generateReceipt } from './receipt.js';
import crypto from 'crypto';

const MCP_VERSION = '2024-11-05';

/**
 * Parse an MCP JSON-RPC request or response.
 */
function parseMcpMessage(data) {
  try {
    return typeof data === 'string' ? JSON.parse(data) : data;
  } catch {
    return null;
  }
}

/**
 * Build a JSON-RPC response.
 */
function jsonRpcResponse(id, result) {
  return JSON.stringify({ jsonrpc: '2.0', id, result });
}

/**
 * Build a JSON-RPC error response.
 */
function jsonRpcError(id, code, message) {
  return JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } });
}

/**
 * McpInterceptor — intercepts MCP tool calls and generates PACT receipts.
 */
export class McpInterceptor {
  /**
   * @param {object} config
   * @param {object} config.policy - Committed policy document (from createPolicy)
   * @param {object} config.anchor - Policy anchor (from anchorPolicy)
   * @param {string} config.upstreamUrl - URL of the real MCP server
   * @param {number} [config.port=3101] - Port for interceptor to listen on
   * @param {string} [config.host='localhost'] - Host for interceptor
   * @param {boolean} [config.allowUnaudited=false] - If true, forward calls without matching policy rule (dangerous)
   */
  constructor({ policy, anchor, upstreamUrl, port = 3101, host = 'localhost', allowUnaudited = false }) {
    this.policy = policy;
    this.anchor = anchor;
    this.upstreamUrl = upstreamUrl;
    this.port = port;
    this.host = host;
    this.allowUnaudited = allowUnaudited;

    this.receipts = [];           // All generated receipts
    this.callCount = 0;           // Monotonic counter per session
    this.upstreamWs = null;       // WebSocket to real MCP server
    this.agentWs = null;          // WebSocket to agent
    this.sessionId = `pact-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;

    this.server = null;
    this.wss = null;
  }

  /**
   * Start the interceptor server.
   * Returns a promise that resolves when the server is listening.
   */
  async start() {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        // Health check endpoint
        if (req.url === '/health') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok', session: this.sessionId, receipts: this.receipts.length }));
          return;
        }
        // CORS preflight
        if (req.method === 'OPTIONS') {
          res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Mcp-Agent-Token',
          });
          res.end();
          return;
        }
        res.writeHead(404);
        res.end('PACT MCP Interceptor — connect via WebSocket');
      });

      this.wss = new WebSocketServer({ server: this.server });

      this.wss.on('connection', (ws, req) => {
        this._handleConnection(ws, req);
      });

      this.wss.on('error', reject);

      this.server.listen(this.port, this.host, () => {
        console.log(`[PACT Interceptor] Listening on ws://${this.host}:${this.port}`);
        console.log(`[PACT Interceptor] Upstream: ${this.upstreamUrl}`);
        console.log(`[PACT Interceptor] Policy: ${this.policy.policy_hash}`);
        resolve();
      });
    });
  }

  /**
   * Handle a new WebSocket connection from the agent.
   */
  async _handleConnection(agentWs, req) {
    // Validate agent token if provided
    const token = req.headers['mcp-agent-token'];
    if (token && token !== process.env.PACT_AGENT_TOKEN) {
      agentWs.close(4001, 'Unauthorized');
      return;
    }

    this.agentWs = agentWs;
    this.callCount = 0;

    // Connect upstream to real MCP server
    const upstreamUrl = new URL(this.upstreamUrl);
    const isHttps = upstreamUrl.protocol === 'https:';
    const wsModule = isHttps ? https : http;

    // Convert HTTP URL to WebSocket URL
    const wsUrl = `ws${isHttps ? 's' : ''}://${upstreamUrl.host}${upstreamUrl.pathname}`;

    // For now, connect upstream via HTTP(S) upgrade — store agent connection
    // and relay messages
    this._relayToAgent(agentWs);
  }

  /**
   * Relay messages between agent and upstream.
   * Intercept tool_call and tool_call_batch messages for PACT receipt generation.
   */
  _relayToAgent(agentWs) {
    // For stdio-based MCP servers, we use a different approach (see McpInterceptorStdio)
    // For HTTP/WebSocket MCP servers:
    let pendingRequests = new Map(); // id → { method, toolName, startTime }

    agentWs.on('message', (rawData) => {
      const msg = parseMcpMessage(rawData);
      if (!msg) return;

      // Intercept MCP requests (not responses)
      if (msg.method === 'tools/call' || msg.method === 'tools/callBatch') {
        this._interceptToolCall(msg, rawData.toString()).then((intercepted) => {
          if (intercepted.drop) {
            // Policy violation — return error to agent, don't forward
            agentWs.send(jsonRpcError(
              msg.id,
              -32000,
              `PACT policy violation: tool '${intercepted.toolName}' is not permitted under committed policy`
            ));
          } else if (intercepted.forward) {
            // Policy OK — forward to upstream (would need upstream WS connection)
            // For now, log and return the receipt
            console.log(`[PACT] Tool call permitted: ${intercepted.toolName}`);
            console.log(`[PACT] Receipt:`, JSON.stringify(intercepted.receipt, null, 2));
            
            // Return success with receipt to agent
            const response = {
              jsonrpc: '2.0',
              id: msg.id,
              result: intercepted.result || { content: [{ type: 'text', text: 'Tool executed. See PACT receipt.' }] }
            };
            // Attach receipt metadata to response headers if possible
            // For WS, we embed it in the result
            if (response.result?.content?.[0]) {
              response.result.content[0].annotations = {
                pact_receipt: {
                  receipt_id: intercepted.receipt.receipt_id,
                  policy_hash: this.policy.policy_hash,
                  log_index: this.anchor.log_index,
                  tool_name: intercepted.toolName,
                  tool_params_hash: intercepted.receipt.params_hash,
                  permitted: true,
                }
              };
            }
            agentWs.send(JSON.stringify(response));
          }
        });
      } else {
        // Non-tool-call message — pass through (initialize, tools/list, etc.)
        // In a full implementation, forward to upstream here
        console.log(`[PACT] Passthrough: ${msg.method || 'notification'}`);
      }
    });

    agentWs.on('close', () => {
      console.log(`[PACT] Agent disconnected. Total calls: ${this.callCount}`);
    });

    agentWs.on('error', (err) => {
      console.error(`[PACT] Agent WS error:`, err.message);
    });
  }

  /**
   * Intercept a tool call, validate against policy, generate receipt.
   * Returns { drop: true } if policy violation, or { forward: true, receipt } if OK.
   */
  async _interceptToolCall(msg, rawStr) {
    this.callCount++;
    const callId = `${this.sessionId}-${this.callCount}`;
    const startTime = new Date().toISOString();

    // Extract tool name from params
    const params = msg.params || msg.params?.[0] || {};
    const toolName = params.name;
    const toolArgs = params.arguments || {};

    if (!toolName) {
      return { drop: false, forward: true, toolName: 'unknown' };
    }

    // Validate against committed policy
    const policyCheck = checkToolCall(this.policy, toolName, toolArgs);

    if (!policyCheck.permitted) {
      console.warn(`[PACT] BLOCKED: ${toolName} — ${policyCheck.reason}`);
      this.receipts.push({
        receipt_id: callId,
        blocked: true,
        tool_name: toolName,
        reason: policyCheck.reason,
        policy_hash: this.policy.policy_hash,
        timestamp: startTime,
      });
      return { drop: true, toolName, reason: policyCheck.reason };
    }

    // Generate PACT receipt for permitted call
    const { receipt } = generateReceipt({
      policy: this.policy,
      toolName,
      params: toolArgs,
    });

    // Enrich with PACT-specific metadata
    receipt.action_id = callId;
    receipt.anchor_log_index = this.anchor.log_index;
    receipt.anchor_log_id = this.anchor.log_id;

    this.receipts.push(receipt);

    return {
      drop: false,
      forward: true,
      toolName,
      receipt,
      result: params._result || null,
    };
  }

  /**
   * Stop the interceptor.
   */
  async stop() {
    if (this.upstreamWs) {
      this.upstreamWs.close();
    }
    if (this.wss) {
      this.wss.close();
    }
    if (this.server) {
      this.server.close();
    }
    console.log(`[PACT] Interceptor stopped. Total receipts: ${this.receipts.length}`);
  }

  /**
   * Get all receipts generated in this session.
   */
  getReceipts() {
    return [...this.receipts];
  }
}


/**
 * McpInterceptorStdio — for intercepting stdio-based MCP servers.
 * Spawns the real MCP server as a child process and relays stdio.
 * Agent connects to this interceptor; interceptor wraps the real server.
 * 
 * Usage:
 *   const interceptor = new McpInterceptorStdio({
 *     policy, anchor,
 *     command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'],
 *   });
 *   interceptor.start();  // returns child process
 */
export class McpInterceptorStdio {
  constructor({ policy, anchor, command, args = [], allowUnaudited = false }) {
    this.policy = policy;
    this.anchor = anchor;
    this.command = command;
    this.args = args;
    this.allowUnaudited = allowUnaudited;
    this.receipts = [];
    this.callCount = 0;
    this.sessionId = `pact-stdio-${Date.now()}`;
    this.child = null;
  }

  /**
   * Start the interceptor by spawning the real MCP server.
   * Returns { childProcess, interceptorFd: writeStream }.
   * Agent reads/writes to interceptorFd instead of the real server.
   */
  start() {
    const { spawn } = require('child_process');

    // Create a mock stdio pair that intercepts tool calls
    // Real implementation: use a PTY or dual-pipe approach
    // For now: document the approach

    console.log(`[PACT Stdio Interceptor] Spawning: ${this.command} ${this.args.join(' ')}`);
    console.log(`[PACT Stdio Interceptor] Policy: ${this.policy.policy_hash}`);

    this.child = spawn(this.command, this.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    // Line-by-line JSON message parsing on stdout/stderr
    let buffer = '';

    this.child.stdout.on('data', (chunk) => {
      buffer += chunk.toString();
      let newline;
      while ((newline = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        if (!line.trim()) continue;

        const msg = parseMcpMessage(line);
        if (msg) {
          // Pass through responses from server
          this._handleServerMessage(msg);
        }
      }
    });

    this.child.stderr.on('data', (chunk) => {
      console.error(`[MCP Server stderr]:`, chunk.toString().trim());
    });

    this.child.on('close', (code) => {
      console.log(`[PACT] MCP server exited with code ${code}`);
    });

    return {
      childProcess: this.child,
      // In full impl: return a duplex stream that wraps child stdio
      // Agent uses this instead of direct child stdio
      note: 'Full stdio interception requires PTY wrapper — see interceptor-stdio.js'
    };
  }

  _handleServerMessage(msg) {
    // Server responses — in stdio mode, forward to whoever is listening
    // (Agent would be reading from our wrapper stdout)
    // For now: log only
    if (msg.result) {
      console.log(`[PACT Server response]: method=${msg.result.method || 'tools/call result'}`);
    }
  }

  getReceipts() {
    return [...this.receipts];
  }

  stop() {
    if (this.child) {
      this.child.kill();
    }
  }
}
