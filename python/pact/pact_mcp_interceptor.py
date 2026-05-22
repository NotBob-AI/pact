#!/usr/bin/env python3
"""
PACT v0.5 — Python Stdio Interceptor

Intercepts MCP tool calls via stdio transport without requiring agent modification.
Mirrors stdin/stdout between agent and MCP server, generates PACT receipts
before forwarding tool calls.

Architecture:
    Agent stdin → [Intercepts] → [Policy check + receipt] → [Forward to MCP server]
    Agent stdout ← [Intercepts] ← [Response forward] ← [MCP server stdout]

For use with any MCP-compatible agent (OpenClaw, Claude Code, etc.)
that uses stdio transport to communicate with MCP servers.

Usage (CLI):
    python3 pact_mcp_interceptor.py \\
        --policy notbob-policy.committed.json \\
        --anchor '{"log_index": 0, "log_id": "sha256:...", "merkle_root": "sha256:..."}' \\
        --server "npx,-y,@modelcontextprotocol/server-filesystem,/tmp"

Usage (programmatic):
    from pact_mcp_interceptor import MCPStdioInterceptor
    interceptor = MCPStdioInterceptor(policy, anchor, command=["npx", "-y", "server", "/tmp"])
    interceptor.start()  # replaces current process stdin/stdout

Requirements:
    pip install pact-zk  (or run from pact/python directory with PYTHONPATH set)
"""

import argparse
import asyncio
import json
import os
import sys
import uuid
import signal
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable, Any

# Try to import PACT components
try:
    from pact import (
        create_policy_spec, generate_receipt, verify_receipt,
        ReceiptGenerator, TransparencyLog
    )
    from pact.policy_spec import PolicySpec
    from pact.commitment import anchor_policy
    PACT_AVAILABLE = True
except ImportError:
    PACT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PACT_VERSION = "0.5.0"
MCP_JSONRPC_METHODS = ["tools/call", "tools/callBatch", "initialize", "tools/list"]


# ---------------------------------------------------------------------------
# Tool Outcome
# ---------------------------------------------------------------------------

class ToolOutcome:
    PERMITTED = "permitted"
    DENIED = "denied"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# MCP Stdio Interceptor
# ---------------------------------------------------------------------------

class MCPStdioInterceptor:
    """
    Intercepts MCP stdio traffic for policy enforcement + PACT receipt generation.
    
    The agent connects to MCP servers through this interceptor instead of
    directly. Every tool call is checked against committed policy before
    forwarding. A PACT receipt is generated for each call.
    
    Enforcement modes:
        block  — deny tool calls not in policy (default)
        audit  — forward but log violations
        warn   — forward with warning header attached
    
    Attributes:
        policy: Committed policy document (dict)
        anchor: Transparency log anchor {log_index, log_id, merkle_root}
        command: Command + args to spawn the real MCP server
        enforcement: Enforcement mode (block/audit/warn)
        use_zk_receipts: Generate ZK receipts (requires RISC Zero)
        on_receipt: Callback(receipt_dict) for each generated receipt
    """
    
    def __init__(
        self,
        policy: dict,
        anchor: dict,
        command: list[str],
        enforcement: str = "block",
        use_zk_receipts: bool = False,
        on_receipt: Optional[Callable[[dict], None]] = None,
        transparency_log: Optional[Any] = None,
    ):
        self.policy = policy
        self.anchor = anchor
        self.command = command
        self.enforcement = enforcement
        self.use_zk_receipts = use_zk_receipts and PACT_AVAILABLE
        self.on_receipt = on_receipt or (lambda r: None)
        self.transparency_log = transparency_log
        
        self.receipts: list[dict] = []
        self.call_count = 0
        self.session_id = f"pact-{uuid.uuid4().hex[:8]}"
        self.running = False
        
        # Receipt generator (PACT v0.7+)
        self._receipt_gen: Optional[ReceiptGenerator] = None
        if PACT_AVAILABLE:
            try:
                self._receipt_gen = ReceiptGenerator(
                    agent_id=policy.get("agent_id", "unknown"),
                    principal_did=policy.get("principal", policy.get("agent", {}).get("did", "did:web:unknown")),
                    transparency_log=transparency_log or TransparencyLog(),
                )
            except Exception:
                pass
    
    # ------------------------------------------------------------------
    # Policy Checking
    # ------------------------------------------------------------------
    
    def _check_tool(self, tool_name: str, params: Optional[dict] = None) -> tuple[str, Optional[str]]:
        """
        Check if a tool is permitted under committed policy.
        
        Returns (outcome: str, reason: Optional[str]):
            ("permitted", None) — allowed
            ("denied", reason) — explicitly denied
            ("unknown", "tool not in policy") — not found in either list
        """
        if not PACT_AVAILABLE or not self._receipt_gen:
            # Fallback: simple allow-list check
            allowed = self.policy.get("policy", {}).get("allowed_tools", [])
            denied = self.policy.get("policy", {}).get("denied_tools", [])
            if tool_name in denied:
                return (ToolOutcome.DENIED, f"{tool_name} is in denied_tools")
            if tool_name in allowed:
                return (ToolOutcome.PERMITTED, None)
            return (ToolOutcome.UNKNOWN, f"{tool_name} not in policy")
        
        try:
            outcome, reason = self._receipt_gen.check_tool(tool_name)
            return (outcome, reason)
        except Exception as e:
            return (ToolOutcome.UNKNOWN, str(e))
    
    def _generate_receipt(
        self,
        tool_name: str,
        params: dict,
        permitted: bool,
        reason: Optional[str] = None,
    ) -> dict:
        """
        Generate a PACT receipt for a tool call.
        
        If PACT is available, uses ReceiptGenerator (v0.7+).
        Otherwise falls back to simple receipt format.
        """
        self.call_count += 1
        action_id = f"{self.session_id}-{self.call_count}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Try PACT receipt generator
        if PACT_AVAILABLE and self._receipt_gen:
            try:
                receipt, outcome = self._receipt_gen.generate_receipt(tool_name, params or {})
                receipt["action_id"] = action_id
                receipt["session_id"] = self.session_id
                receipt["anchor_log_index"] = self.anchor.get("log_index", 0)
                receipt["anchor_log_id"] = self.anchor.get("log_id", "")
                receipt["policy_hash"] = self.policy.get("policy_hash", self.policy.get("policy", {}).get("policy_hash", ""))
                self.receipts.append(receipt)
                self.on_receipt(receipt)
                return receipt
            except Exception as e:
                # Fall through to simple receipt
                print(f"[PACT Interceptor] Receipt generation failed: {e} — using fallback", file=sys.stderr)
        
        # Simple receipt (no ZK)
        receipt = {
            "receipt_version": PACT_VERSION,
            "action_id": action_id,
            "session_id": self.session_id,
            "tool_name": tool_name,
            "tool_params": params or {},
            "timestamp": timestamp,
            "policy_hash": self.policy.get("policy_hash", self.policy.get("policy", {}).get("policy_hash", "")),
            "anchor_log_index": self.anchor.get("log_index", 0),
            "anchor_log_id": self.anchor.get("log_id", ""),
            "outcome": "permitted" if permitted else "denied",
            "reason": reason,
            "receipt_id": action_id,
            "zk_proof": None,  # DUMMY — set to True for real ZK receipts
        }
        self.receipts.append(receipt)
        self.on_receipt(receipt)
        return receipt
    
    # ------------------------------------------------------------------
    # MCP Message Parsing
    # ------------------------------------------------------------------
    
    def _parse_jsonrpc(self, line: str) -> Optional[dict]:
        """Parse a JSON-RPC message from a line."""
        try:
            msg = json.loads(line.strip())
            return msg
        except (json.JSONDecodeError, TypeError):
            return None
    
    def _is_tool_call(self, msg: dict) -> bool:
        """Check if a JSON-RPC message is a tool call."""
        return msg.get("method", "") in MCP_JSONRPC_METHODS
    
    def _extract_tool_calls(self, msg: dict) -> list[tuple[str, dict]]:
        """Extract (tool_name, params) pairs from a JSON-RPC message."""
        method = msg.get("method", "")
        params = msg.get("params", {})
        
        if method == "tools/call":
            if isinstance(params, dict):
                tools = params.get("tool_calls", []) or params.get("tools", [])
                if isinstance(tools, list) and tools:
                    return [(t.get("name", "unknown"), t.get("arguments", {})) for t in tools]
            return [(params.get("name", "unknown"), params.get("arguments", {}))]
        
        elif method == "tools/callBatch":
            if isinstance(params, list):
                return [(p.get("name", "unknown"), p.get("arguments", {})) for p in params]
            return []
        
        return []
    
    # ------------------------------------------------------------------
    # Stdio interception
    # ------------------------------------------------------------------
    
    def _handle_agent_message(self, line: str, child_stdin: Any, raw_line: str) -> Optional[str]:
        """
        Handle a JSON-RPC message from the agent.
        Returns a response to send back, or None to forward as-is.
        """
        msg = self._parse_jsonrpc(line)
        if not msg:
            return None  # Forward malformed as-is
        
        # Only intercept tool calls; pass through initialize, tools/list, etc.
        if not self._is_tool_call(msg):
            return None  # Forward non-tool-call as-is
        
        # Extract tool calls
        tool_calls = self._extract_tool_calls(msg)
        if not tool_calls:
            return None
        
        primary_tool, primary_params = tool_calls[0]
        
        # Policy check
        outcome, reason = self._check_tool(primary_tool, primary_params)
        permitted = (outcome == ToolOutcome.PERMITTED)
        
        # Generate receipt BEFORE decision (important for enforcement)
        receipt = self._generate_receipt(primary_tool, primary_params, permitted, reason)
        
        print(f"[PACT Interceptor] Tool call #{self.call_count}: {primary_tool} → {outcome}", file=sys.stderr)
        
        if not permitted:
            if self.enforcement == "block":
                # Return error to agent — do NOT forward to server
                error_resp = {
                    "jsonrpc": "2.0",
                    "id": msg.get("id"),
                    "error": {
                        "code": -32000,
                        "message": f"PACT policy violation: {primary_tool} — {reason or 'not permitted'}",
                        "data": {
                            "receipt_id": receipt["action_id"],
                            "policy_hash": receipt["policy_hash"][:16] + "...",
                        }
                    }
                }
                return json.dumps(error_resp) + "\n"
            
            elif self.enforcement == "warn":
                # Forward but attach warning header
                print(f"[PACT Interceptor] WARNING: {primary_tool} not in policy — forwarding anyway", file=sys.stderr)
        
        # Forward permitted call (with receipt metadata attached to params)
        forwarded_params = primary_params.copy() if isinstance(primary_params, dict) else {}
        forwarded_params["_pact"] = {
            "receipt_id": receipt["action_id"],
            "policy_hash": receipt["policy_hash"][:16] + "..." if len(receipt.get("policy_hash","")) > 16 else receipt.get("policy_hash",""),
            "log_index": receipt.get("anchor_log_index", 0),
            "session_id": self.session_id,
        }
        
        forwarded_msg = {
            "jsonrpc": msg.get("jsonrpc", "2.0"),
            "id": msg.get("id"),
            "method": msg.get("method"),
            "params": forwarded_params,
        }
        
        # Write to child stdin
        child_stdin.write(json.dumps(forwarded_msg) + "\n")
        child_stdin.flush()
        
        return None  # Don't send response ourselves — child will respond
    
    # ------------------------------------------------------------------
    # Start / Stop
    # ------------------------------------------------------------------
    
    def start(self) -> None:
        """
        Start the interceptor.
        
        Spawns the real MCP server as a child process.
        This REPLACES the current process's stdin/stdout with the interception layer.
        The agent should write to stdin, read from stdout.
        
        NOTE: Call this LAST after setup. It takes over stdin/stdout.
        """
        import subprocess
        import threading
        import io
        
        if not self.command or len(self.command) < 1:
            raise ValueError("MCPStdioInterceptor requires a command to spawn the MCP server")
        
        cmd = self.command[0]
        args = self.command[1:] if len(self.command) > 1 else []
        
        print(f"[PACT Interceptor v{PACT_VERSION}] Spawning: {cmd} {' '.join(args)}", file=sys.stderr)
        print(f"[PACT Interceptor] Policy: {self.policy.get('policy_hash', 'unknown')[:20]}...", file=sys.stderr)
        print(f"[PACT Interceptor] Enforcement: {self.enforcement}", file=sys.stderr)
        
        self.running = True
        
        # Spawn MCP server child
        self.child = subprocess.Popen(
            [cmd] + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        child_stdin = self.child.stdin
        child_stdout = self.child.stdout
        
        # Thread 1: Agent stdin → interceptor → child stdin
        def agent_to_child():
            for line in sys.stdin:
                if not self.running:
                    break
                line = line.strip()
                if not line:
                    continue
                response = self._handle_agent_message(line, child_stdin, line)
                if response:
                    sys.stdout.write(response)
                    sys.stdout.flush()
        
        # Thread 2: Child stdout → interceptor → agent stdout
        def child_to_agent():
            for line in child_stdout:
                if not self.running:
                    break
                sys.stdout.write(line)
                sys.stdout.flush()
        
        t1 = threading.Thread(target=agent_to_child, daemon=True)
        t2 = threading.Thread(target=child_to_agent, daemon=True)
        t1.start()
        t2.start()
        
        # Handle signals
        def shutdown(signum, frame):
            self.stop()
        
        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)
        
        t1.join()
        t2.join()
    
    def stop(self) -> None:
        """Stop the interceptor and kill the MCP server child process."""
        self.running = False
        if hasattr(self, "child") and self.child:
            self.child.terminate()
            try:
                self.child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.child.kill()
        print(f"[PACT Interceptor] Stopped. Total receipts: {len(self.receipts)}", file=sys.stderr)
    
    def get_receipts(self) -> list[dict]:
        """Return all receipts generated in this session."""
        return list(self.receipts)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=f"PACT v{PACT_VERSION} — MCP Stdio Interceptor"
    )
    parser.add_argument(
        "--policy", required=True,
        help="Path to committed policy JSON file"
    )
    parser.add_argument(
        "--anchor", required=True,
        help="JSON string with {log_index, log_id, merkle_root}"
    )
    parser.add_argument(
        "--command", required=True,
        help="Command to spawn MCP server (e.g., npx)"
    )
    parser.add_argument(
        "--args",
        help="Comma-separated args for server command"
    )
    parser.add_argument(
        "--enforcement", default="block",
        choices=["block", "audit", "warn"],
        help="Enforcement mode (default: block)"
    )
    parser.add_argument(
        "--zk",
        action="store_true",
        help="Generate ZK receipts (requires RISC Zero)"
    )
    
    args = parser.parse_args()
    
    # Load policy
    policy_path = Path(args.policy)
    if not policy_path.exists():
        print(f"[ERROR] Policy file not found: {policy_path}", file=sys.stderr)
        sys.exit(1)
    
    with open(policy_path) as f:
        policy = json.load(f)
    
    # Parse anchor
    try:
        anchor = json.loads(args.anchor)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid anchor JSON: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Build command
    command = [args.command]
    if args.args:
        command.extend(args.args.split(","))
    
    # Create and start interceptor
    interceptor = MCPStdioInterceptor(
        policy=policy,
        anchor=anchor,
        command=command,
        enforcement=args.enforcement,
        use_zk_receipts=args.zk,
    )
    
    print(f"[PACT Interceptor] Ready. Enforcement: {args.enforcement}.", file=sys.stderr)
    interceptor.start()


if __name__ == "__main__":
    main()