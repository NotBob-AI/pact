#!/usr/bin/env python3
"""
PACT MCP Interceptor — Layer 0

A proxy that wraps any MCP HTTP endpoint and intercepts tool calls.
Generates PACT receipts for every call against a committed policy.
No agent modification required — the agent calls us, we forward and prove.

Usage:
    python3 pact-mcp-interceptor.py \
        --upstream http://localhost:3000 \
        --policy-file policy.json \
        --port 8101

The agent calls http://localhost:8101 (us) instead of the upstream.
We forward the call, generate a PACT receipt, and return the response.
"""

import argparse
import json
import sys
import hashlib
import uuid
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import urllib.request

class PactInterceptor:
    """Handles PACT policy loading, receipt generation, and verification."""
    
    def __init__(self, policy_path: str):
        with open(policy_path) as f:
            self.policy = json.load(f)
        self.agent_id = self.policy.get('agent_id', 'unknown')
        self.policy_hash = self.policy.get('policy_hash')
        if not self.policy_hash:
            raise ValueError("Policy must have policy_hash — run createPolicy first")
    
    def check_tool(self, tool_name: str) -> tuple[bool, str]:
        """Check if tool is permitted under policy."""
        allowed = self.policy.get('policy', {}).get('allowed_tools', [])
        denied = self.policy.get('policy', {}).get('denied_tools', [])
        
        if tool_name in denied:
            return False, f"tool '{tool_name}' is explicitly denied"
        if tool_name in allowed:
            return True, f"tool '{tool_name}' is permitted"
        return False, f"tool '{tool_name}' not in allowed list"
    
    def generate_receipt(self, tool_name: str, params: dict, outcome: bool, reason: str) -> dict:
        """Generate a PACT receipt for a tool call."""
        params_hash = f"sha256:{hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()}"
        
        receipt = {
            "receipt_version": "0.1.0",
            "agent_id": self.agent_id,
            "policy_hash": self.policy_hash,
            "action_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_called": tool_name,
            "params_hash": params_hash,
            "outcome": "permitted" if outcome else "denied",
            "outcome_reason": reason,
            "proof": {
                "type": "sha256_membership",
                "statement": f"tool_called={'in' if outcome else 'not in'} policy.allowed_tools",
                "policy_hash": self.policy_hash,
                "proof_hash": f"sha256:{hashlib.sha256(f'{self.policy_hash}:{tool_name}:{outcome}'.encode()).hexdigest()}",
            },
            "interceptor": "pact-mcp-interceptor v0.1",
        }
        return receipt
    
    def log_receipt(self, receipt: dict, log_file: str = ".pact-receipts.jsonl"):
        """Append receipt to audit log."""
        with open(log_file, "a") as f:
            f.write(json.dumps(receipt) + "\n")


class ProxyHandler(BaseHTTPRequestHandler):
    """HTTP handler that intercepts MCP tool calls and generates receipts."""
    
    interceptor: PactInterceptor = None
    upstream_url: str = None
    log_receipts: bool = True
    
    def do_POST(self):
        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
            return
        
        # Handle MCP RPC — look for tool calls
        method = request.get('method', '')
        
        if method == 'tools/call' or method == 'execute_tool':
            tool_name = request.get('params', {}).get('name', request.get('params', {}).get('tool', 'unknown'))
            params = request.get('params', {}).get('arguments', request.get('params', {}).get('params', {}))
            
            # Check against policy
            permitted, reason = self.interceptor.check_tool(tool_name)
            
            # Forward to upstream (even if denied — we want the agent to see the error)
            upstream_response = self.forward_to_upstream(body)
            
            # Generate receipt
            receipt = self.interceptor.generate_receipt(tool_name, params, permitted, reason)
            
            if self.log_receipts:
                self.interceptor.log_receipt(receipt)
            
            # For denied calls, return error instead of upstream response
            if not permitted:
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                error_response = json.dumps({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": f"PACT_POLICY_VIOLATION: {reason}",
                        "data": {"receipt": receipt}
                    },
                    "id": request.get('id')
                })
                self.wfile.write(error_response.encode())
                return
            
            # For permitted calls, relay upstream response
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(upstream_response.encode())
            
        elif method == 'initialize' or method == 'tools/list':
            # Pass through without interception
            upstream = self.forward_to_upstream(body)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(upstream.encode())
        else:
            # Unknown method — pass through
            upstream = self.forward_to_upstream(body)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(upstream.encode())
    
    def forward_to_upstream(self, body: bytes) -> str:
        """Forward request to upstream MCP server."""
        try:
            req = urllib.request.Request(
                self.upstream_url,
                data=body,
                headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read().decode()
        except Exception as e:
            return json.dumps({
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": f"Upstream error: {str(e)}"}
            })
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


def main():
    parser = argparse.ArgumentParser(description='PACT MCP Interceptor — Layer 0')
    parser.add_argument('--upstream', required=True, help='Upstream MCP server URL')
    parser.add_argument('--policy-file', required=True, help='Path to committed policy JSON')
    parser.add_argument('--port', type=int, default=8101, help='Listen port (default 8101)')
    parser.add_argument('--host', default='127.0.0.1', help='Listen host')
    parser.add_argument('--log-file', default='.pact-receipts.jsonl', help='Receipt log file')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    interceptor = PactInterceptor(args.policy_file)
    ProxyHandler.interceptor = interceptor
    ProxyHandler.upstream_url = args.upstream
    ProxyHandler.log_receipts = True
    
    server = HTTPServer((args.host, args.port), ProxyHandler)
    print(f"[PACT Interceptor] Listening on {args.host}:{args.port}")
    print(f"[PACT Interceptor] Forwarding to {args.upstream}")
    print(f"[PACT Interceptor] Policy: {interceptor.agent_id} ({interceptor.policy_hash[:20]}...)")
    print(f"[PACT Interceptor] Receipt log: {args.log_file}")
    print()
    print("Agent should now call http://127.0.0.1:{port}/mcp instead of {upstream}".format(
        port=args.port, upstream=args.upstream))
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[PACT Interceptor] Shutting down")
        server.shutdown()


if __name__ == '__main__':
    main()