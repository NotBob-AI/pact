#!/usr/bin/env python3
"""
PACT MCP Interceptor — Layer 0 (v0.2)

A proxy that wraps any MCP HTTP endpoint and intercepts tool calls.
Generates PACT receipts for every call against a committed policy.
Hash-chained receipts create a tamper-evident, append-only audit trail.

Key improvement over v0.1: hash chaining (inspired by Agent Receipts proxy,
Otto Jongerius — https://jongerius.solutions/post/auditing-github-mcp-agent-receipts/)

No agent modification required — the agent calls us, we forward and prove.

Usage:
    python3 pact-mcp-interceptor.py \
        --upstream http://localhost:3000 \
        --policy-file policy.json \
        --port 8101

The agent calls http://127.0.0.1:8101 (us) instead of the upstream.
"""

import argparse
import json
import threading
import hashlib
import uuid
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import os

CHAIN_STATE_FILE = ".pact-chain-state.json"
RECEIPT_LOG_FILE = ".pact-receipts.jsonl"


class PactChainState:
    """
    Manages the PACT receipt hash chain.
    Each receipt hash includes the previous receipt hash, creating a tamper-evident chain.
    State is persisted to disk and loaded at startup.
    """
    
    def __init__(self, state_file: str, log_file: str):
        self.state_file = state_file
        self.log_file = log_file
        self.lock = threading.Lock()
        self.head_hash = None
        self.seq = 0
        self._load()
    
    def _load(self):
        """Load chain state from disk. Creates new chain if none exists."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file) as f:
                    state = json.load(f)
                self.head_hash = state.get("head_hash")
                self.seq = state.get("seq", 0)
            except (json.JSONDecodeError, IOError):
                # Corrupt state — start fresh chain
                self.head_hash = None
                self.seq = 0
        # Also check receipt log to find the actual chain head
        if os.path.exists(self.log_file):
            last_line = None
            try:
                with open(self.log_file) as f:
                    for line in f:
                        if line.strip():
                            last_line = line
                if last_line:
                    last_receipt = json.loads(last_line)
                    self.head_hash = last_receipt.get("receipt_hash")
                    self.seq = last_receipt.get("seq", self.seq)
            except (json.JSONDecodeError, IOError):
                pass
    
    def _save(self):
        """Persist chain head to disk."""
        with open(self.state_file, "w") as f:
            json.dump({"head_hash": self.head_hash, "seq": self.seq}, f)
    
    def append(self, receipt: dict) -> str:
        """
        Add a receipt to the chain.
        Computes receipt_hash as SHA-256 of canonical receipt (without receipt_hash itself).
        Returns the new head hash.
        """
        with self.lock:
            self.seq += 1
            receipt["seq"] = self.seq
            receipt["prev_receipt_hash"] = self.head_hash
            
            # Canonicalize for hashing: sort keys, no receipt_hash field
            canon = {k: v for k, v in receipt.items() if k != "receipt_hash"}
            canon_str = json.dumps(canon, sort_keys=True, default=str)
            receipt_hash = f"sha256:{hashlib.sha256(canon_str.encode()).hexdigest()}"
            receipt["receipt_hash"] = receipt_hash
            
            # Persist to append-only log
            with open(self.log_file, "a") as f:
                f.write(json.dumps(receipt, default=str) + "\n")
            
            self.head_hash = receipt_hash
            self._save()
            return receipt_hash


class PactInterceptor:
    """Handles PACT policy loading, receipt generation, and verification."""
    
    def __init__(self, policy_path: str, chain: PactChainState, verbose: bool = False):
        with open(policy_path) as f:
            self.policy = json.load(f)
        self.agent_id = self.policy.get("agent_id", "unknown")
        self.policy_hash = self.policy.get("policy_hash")
        if not self.policy_hash:
            raise ValueError("Policy must have policy_hash — run createPolicy first")
        self.chain = chain
        self.verbose = verbose
    
    def check_tool(self, tool_name: str) -> tuple[bool, str]:
        """Check if tool is permitted under committed policy."""
        allowed = self.policy.get("policy", {}).get("allowed_tools", [])
        denied = self.policy.get("policy", {}).get("denied_tools", [])
        
        if tool_name in denied:
            return False, f"tool '{tool_name}' is explicitly denied by committed policy"
        if tool_name in allowed:
            return True, f"tool '{tool_name}' is permitted by committed policy"
        return False, f"tool '{tool_name}' not in committed allowed_tools"
    
    def generate_receipt(
        self, tool_name: str, params: dict, outcome: bool, reason: str,
        request_id: str = None
    ) -> dict:
        """
        Generate a PACT receipt for a tool call.
        Receipt is added to the hash chain by PactChainState.append().
        """
        params_str = json.dumps(params, sort_keys=True, default=str)
        params_hash = f"sha256:{hashlib.sha256(params_str.encode()).hexdigest()}"
        
        receipt = {
            "receipt_version": "0.2.0",
            "agent_id": self.agent_id,
            "policy_hash": self.policy_hash,
            "action_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_called": tool_name,
            "params_hash": params_hash,
            "outcome": "permitted" if outcome else "denied",
            "outcome_reason": reason,
            "proof": {
                "type": "sha256_membership_with_chain",
                "statement": (
                    f"tool_called {'∈' if outcome else '∉'} policy.allowed_tools "
                    f"AND NOT IN policy.denied_tools @ committed policy_hash"
                ),
                "policy_hash": self.policy_hash,
                # v0.2: proof is verifiable against committed policy hash
                # v0.3: replace with ZK membership proof
                "proof_hash": f"sha256:{hashlib.sha256(f'{self.policy_hash}:{tool_name}:{outcome}'.encode()).hexdigest()}",
            },
            "interceptor": "pact-mcp-interceptor v0.2 (hash-chained)",
            "request_id": request_id,
        }
        
        # Add to hash chain — this sets seq, prev_receipt_hash, and receipt_hash
        receipt_hash = self.chain.append(receipt)
        
        if self.verbose:
            status = "✓" if outcome else "✗"
            print(f"[PACT] {status} {tool_name} (seq={receipt['seq']}, hash={receipt_hash[:20]}...)")
        
        return receipt


class ProxyHandler(BaseHTTPRequestHandler):
    """HTTP handler that intercepts MCP tool calls and generates chained receipts."""
    
    interceptor: PactInterceptor = None
    upstream_url: str = None
    
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
            return
        
        method = request.get("method", "")
        request_id = request.get("id")
        
        # Intercept tool call methods
        if method in ("tools/call", "execute_tool", "tool_call"):
            tool_name = self._extract_tool_name(request)
            params = self._extract_params(request)
            
            permitted, reason = self.interceptor.check_tool(tool_name)
            receipt = self.interceptor.generate_receipt(tool_name, params, permitted, reason, request_id)
            
            if not permitted:
                # Denied: return policy violation error with receipt embedded
                self._send_json(403, {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": f"PACT_POLICY_VIOLATION: {reason}",
                        "data": {"pact_receipt": receipt}
                    },
                    "id": request_id
                })
                return
            
            # Permitted: forward to upstream, attach receipt to response
            upstream_resp = self._forward(body)
            if upstream_resp:
                try:
                    upstream_json = json.loads(upstream_resp)
                    # Inject receipt into response for transparency
                    if "result" in upstream_json:
                        upstream_json["result"]["_pact_receipt"] = {
                            "receipt_hash": receipt["receipt_hash"],
                            "seq": receipt["seq"],
                            "policy_hash": receipt["policy_hash"],
                            "tool_called": receipt["tool_called"],
                            "timestamp": receipt["timestamp"],
                        }
                    self._send_json(200, upstream_json, rid=request_id)
                except json.JSONDecodeError:
                    self._send_raw(200, upstream_resp)
            else:
                self._send_json(500, {
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": "Upstream timeout"},
                    "id": request_id
                })
        
        elif method in ("tools/list", "tools/list_next", "initialize", "ping"):
            # Pass through — no tool call intercepted
            upstream = self._forward(body)
            if upstream:
                self._send_raw(200, upstream)
            else:
                self._send_json(500, {
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": "Upstream unreachable"},
                    "id": request_id
                })
        
        else:
            # Unknown method — forward as-is
            upstream = self._forward(body)
            if upstream:
                self._send_raw(200, upstream)
            else:
                self._send_json(500, {"jsonrpc": "2.0", "error": {"code": -32603}, "id": request_id})
    
    def _extract_tool_name(self, request: dict) -> str:
        """Extract tool name from various MCP JSON-RPC shapes."""
        params = request.get("params", {})
        return params.get("name") or params.get("tool") or params.get("toolName") or "unknown"
    
    def _extract_params(self, request: dict) -> dict:
        """Extract tool params from various MCP JSON-RPC shapes."""
        params = request.get("params", {})
        return params.get("arguments") or params.get("params") or params.get("input") or {}
    
    def _forward(self, body: bytes) -> str:
        """Forward request to upstream MCP server."""
        try:
            req = urllib.request.Request(
                self.upstream_url,
                data=body,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode()
        except urllib.error.URLError as e:
            if self.interceptor.verbose:
                print(f"[PACT] Upstream error: {e}")
            return None
        except Exception as e:
            if self.interceptor.verbose:
                print(f"[PACT] Forward error: {e}")
            return None
    
    def _send_json(self, code: int, payload: dict, rid=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload, default=str).encode())
    
    def _send_raw(self, code: int, body: str):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode() if isinstance(body, str) else body)
    
    def log_message(self, format, *args):
        """Suppress default HTTP logging unless verbose."""
        if self.interceptor.verbose:
            print(f"[PACT HTTP] {format % args}")


def main():
    parser = argparse.ArgumentParser(description="PACT MCP Interceptor — Layer 0 (v0.2, hash-chained)")
    parser.add_argument("--upstream", required=True, help="Upstream MCP server URL")
    parser.add_argument("--policy-file", required=True, help="Path to committed policy JSON")
    parser.add_argument("--port", type=int, default=8101, help="Listen port (default 8101)")
    parser.add_argument("--host", default="127.0.0.1", help="Listen host (default 127.0.0.1)")
    parser.add_argument("--chain-state", default=CHAIN_STATE_FILE, help="Chain state file")
    parser.add_argument("--receipt-log", default=RECEIPT_LOG_FILE, help="Receipt log file (.jsonl)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    chain = PactChainState(args.chain_state, args.receipt_log)
    interceptor = PactInterceptor(args.policy_file, chain, verbose=args.verbose)
    ProxyHandler.interceptor = interceptor
    ProxyHandler.upstream_url = args.upstream
    
    print(f"[PACT v0.2] Hash-chained MCP interceptor")
    print(f"[PACT] Listening on {args.host}:{args.port} → {args.upstream}")
    print(f"[PACT] Policy: {interceptor.agent_id}")
    print(f"[PACT] Policy hash: {interceptor.policy_hash[:24]}...")
    print(f"[PACT] Chain state: {args.chain_state}  Receipt log: {args.receipt_log}")
    print(f"[PACT] Chain head: seq={chain.seq}, hash={chain.head_hash[:20] if chain.head_hash else 'GENESIS'}...")
    print()
    print("Agent should call http://{host}:{port} instead of {upstream}".format(
        host=args.host, port=args.port, upstream=args.upstream))
    
    try:
        server = HTTPServer((args.host, args.port), ProxyHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[PACT] Shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
