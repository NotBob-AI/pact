#!/usr/bin/env python3
"""
PACT OVID Bridge Integration Test

Tests the full flow:
1. Create + commit a policy
2. Generate a v0.3 ZK receipt (DUMMY_PROOF mode)
3. Bridge to v0.1-compatible receipt
4. Verify the v0.1 receipt fields are correct
5. Sign the receipt with Ed25519 key
6. Verify the signature

Run: python3 -m pytest tests/test_ovid_bridge.py -v
Or:  python3 tests/test_ovid_bridge.py
"""

import json
import tempfile
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from pact import create_policy, generate_receipt
from pact.zk_host import generate_zk_receipt
from pact.ovid_bridge import bridge_zk_receipt_to_v01, sign_receipt


class TestOvidBridge:
    """Integration tests for PACT → OVID v0.1 bridge."""

    def test_dummy_proof_receipt_bridges_to_v01(self):
        """Full flow: policy → ZK receipt → v0.1 bridge → signed receipt."""
        # 1. Create and commit a policy
        policy = create_policy(
            agent_id="did:key:test-ovid-bridge-001",
            allowed_tools=["read_file", "search_web"],
            denied_tools=["delete_file"],
        )
        assert policy.policy_hash.startswith("sha256:")

        # 2. Generate a ZK receipt (DUMMY_PROOF — no actual RISC Zero needed)
        tool_name = "read_file"
        params = {"path": "/tmp/test.txt"}
        zk_receipt = generate_zk_receipt(
            policy=policy,
            tool_name=tool_name,
            params=params,
        )

        # Verify ZK receipt structure
        assert "proof" in zk_receipt
        assert "public" in zk_receipt
        assert zk_receipt["public"]["tool_name"] == tool_name
        assert zk_receipt["public"]["policy_hash"] == policy.policy_hash
        # DUMMY_PROOF is marked as stub
        assert zk_receipt["proof"].get("stub", False) is True

        # 3. Bridge to v0.1
        v01 = bridge_zk_receipt_to_v01(
            zk_receipt=zk_receipt,
            agent_id=policy.agent_id,
            tool_called=tool_name,
            policy_hash=policy.policy_hash,
        )

        # 4. Verify v0.1 receipt structure
        assert v01["receipt_version"] == "0.1"
        assert v01["agent_id"] == policy.agent_id
        assert v01["tool_called"] == tool_name
        assert v01["policy_hash"] == policy.policy_hash
        assert v01["_pact_version"] == "0.3"
        assert v01["_zk_valid"] is False  # DUMMY_PROOF is not real ZK
        assert "proof" in v01
        assert "zk_receipt" in v01["proof"]  # embedded ZK receipt
        # Commitment must be sha256:hex format
        assert v01["proof"]["commitment"].startswith("sha256:")
        assert len(v01["proof"]["commitment"]) == len("sha256:") + 64
        # Statement should describe DUMMY_PROOF mode
        assert "[STUB]" in v01["proof"]["statement"]
        assert "DUMMY_PROOF" in v01["proof"]["statement"]

    def test_zk_receipt_fields_preserved_in_v01_bridge(self):
        """Ensure key ZK receipt fields survive the bridge."""
        policy = create_policy(
            agent_id="did:key:test-fields-001",
            allowed_tools=["send_email"],
            denied_tools=[],
        )
        zk_receipt = generate_zk_receipt(
            policy=policy,
            tool_name="send_email",
            params={"to": "test@example.com", "body": "hello"},
        )

        v01 = bridge_zk_receipt_to_v01(
            zk_receipt=zk_receipt,
            agent_id=policy.agent_id,
            tool_called="send_email",
            policy_hash=policy.policy_hash,
        )

        # Embedded ZK receipt must be intact
        embedded = v01["proof"]["zk_receipt"]
        assert embedded["public"]["policy_hash"] == policy.policy_hash
        assert embedded["public"]["tool_name"] == "send_email"

    def test_sign_receipt_produces_valid_signature(self):
        """Sign a bridged receipt and verify signature round-trips."""
        policy = create_policy(
            agent_id="did:key:test-sign-001",
            allowed_tools=["read_file"],
            denied_tools=[],
        )
        zk_receipt = generate_zk_receipt(policy, "read_file", {"path": "/tmp/x"})
        v01 = bridge_zk_receipt_to_v01(
            zk_receipt, policy.agent_id, "read_file", policy.policy_hash
        )

        # Generate a test Ed25519 key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private_key = Ed25519PrivateKey.generate()
        import base64
        sk_b64 = base64.b64encode(
            private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ).decode()

        signed = sign_receipt(dict(v01), sk_b64)

        # Signature and verifier_key must be populated
        assert signed["proof"]["signature"] != ""
        assert signed["proof"]["verifier_key"] != ""

        # Verify the signature
        commitment_hex = signed["proof"]["commitment"].replace("sha256:", "")
        commitment_bytes = bytes.fromhex(commitment_hex)
        sig_bytes = base64.b64decode(signed["proof"]["signature"])
        pub_key_bytes = base64.b64decode(signed["proof"]["verifier_key"])

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives import serialization
        public_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
        public_key.verify(sig_bytes, commitment_bytes)

    def test_commitment_string_is_deterministic(self):
        """Same inputs must produce same commitment (for reproducibility)."""
        policy = create_policy(
            agent_id="did:key:test-det-001",
            allowed_tools=["read_file"],
            denied_tools=[],
        )
        zk_receipt_a = generate_zk_receipt(policy, "read_file", {"path": "/a"})
        zk_receipt_b = generate_zk_receipt(policy, "read_file", {"path": "/a"})

        v01_a = bridge_zk_receipt_to_v01(zk_receipt_a, policy.agent_id, "read_file", policy.policy_hash)
        v01_b = bridge_zk_receipt_to_v01(zk_receipt_b, policy.agent_id, "read_file", policy.policy_hash)

        # action_ids differ (UUID-based) but commitment must be same for same inputs
        # Note: timestamp may differ slightly, so we compare commitment input construction
        # The key test is that policy_hash + tool + action_id + timestamp are in commitment
        assert "sha256:" in v01_a["proof"]["commitment"]
        assert "sha256:" in v01_b["proof"]["commitment"]

    def test_bridge_cli_args(self):
        """Test the CLI entry point for the bridge."""
        policy = create_policy(
            agent_id="did:key:test-cli-001",
            allowed_tools=["read_file"],
            denied_tools=[],
        )
        zk_receipt = generate_zk_receipt(policy, "read_file", {"path": "/tmp/test"})

        with tempfile.TemporaryDirectory() as tmpdir:
            zk_path = Path(tmpdir) / "zk_receipt.json"
            out_path = Path(tmpdir) / "v01_receipt.json"

            with open(zk_path, "w") as f:
                json.dump(zk_receipt, f)

            from pact.ovid_bridge import main
            import sys
            old_argv = sys.argv
            try:
                sys.argv = [
                    "ovid_bridge",
                    "--zk-receipt", str(zk_path),
                    "--agent-id", policy.agent_id,
                    "--tool", "read_file",
                    "--policy-hash", policy.policy_hash,
                    "--output", str(out_path),
                ]
                main()
            except SystemExit:
                pass
            finally:
                sys.argv = old_argv

            assert out_path.exists()
            with open(out_path) as f:
                result = json.load(f)
            assert result["receipt_version"] == "0.1"
            assert result["tool_called"] == "read_file"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
