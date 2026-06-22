"""Tests for PACT v0.8.1 causal binding."""

from pact.causal_binding import (
    compute_causal_hash,
    hash_tool_params,
    form_causal_commitment,
    verify_causal_binding,
    PACTReceipt,
    PolicyCommitment,
    ToolCall,
    ZKProof,
    verify_causal_receipt,
    PACT_CAUSAL_VERSION,
)


class TestCausalHash:
    """Unit tests for causal hash computation."""

    def test_causal_hash_deterministic(self):
        h1 = compute_causal_hash("sha256:abc", "sha256:def", "run1", "genesis")
        h2 = compute_causal_hash("sha256:abc", "sha256:def", "run1", "genesis")
        assert h1 == h2

    def test_causal_hash_order_matters(self):
        h1 = compute_causal_hash("sha256:abc", "sha256:def", "run1", "genesis")
        h2 = compute_causal_hash("sha256:def", "sha256:abc", "run1", "genesis")
        assert h1 != h2

    def test_causal_hash_different_runs(self):
        h1 = compute_causal_hash("sha256:abc", "sha256:def", "run1", "genesis")
        h2 = compute_causal_hash("sha256:abc", "sha256:def", "run2", "genesis")
        assert h1 != h2

    def test_causal_hash_different_prev(self):
        h1 = compute_causal_hash("sha256:abc", "sha256:def", "run1", "genesis")
        h2 = compute_causal_hash("sha256:abc", "sha256:def", "run1", "sha256:prevhash")
        assert h1 != h2


class TestHashToolParams:
    """Unit tests for tool params hashing."""

    def test_same_params_same_hash(self):
        h1 = hash_tool_params("read_file", {"path": "/tmp/a"})
        h2 = hash_tool_params("read_file", {"path": "/tmp/a"})
        assert h1 == h2

    def test_different_params_different_hash(self):
        h1 = hash_tool_params("read_file", {"path": "/tmp/a"})
        h2 = hash_tool_params("read_file", {"path": "/tmp/b"})
        assert h1 != h2

    def test_different_tool_different_hash(self):
        h1 = hash_tool_params("read_file", {"path": "/tmp/a"})
        h2 = hash_tool_params("write_file", {"path": "/tmp/a"})
        assert h1 != h2

    def test_arg_order_independent(self):
        h1 = hash_tool_params("read_file", {"a": "1", "b": "2"})
        h2 = hash_tool_params("read_file", {"b": "2", "a": "1"})
        assert h1 == h2


class TestFormCausalCommitment:
    """Unit tests for causal commitment formation."""

    def test_commitment_includes_all_fields(self):
        commitment = form_causal_commitment("sha256:abc", "sha256:def")
        assert commitment.policy_hash == "sha256:abc"
        assert commitment.params_hash == "sha256:def"
        assert commitment.run_id is not None
        assert commitment.causal_hash.startswith("sha256:")
        assert commitment.timestamp != ""

    def test_custom_run_id(self):
        commitment = form_causal_commitment(
            "sha256:abc", "sha256:def", run_id="custom-run-id"
        )
        assert commitment.run_id == "custom-run-id"

    def test_chaining_prev_commitment(self):
        first = form_causal_commitment("sha256:abc", "sha256:def")
        second = form_causal_commitment(
            "sha256:abc", "sha256:xyz", prev_commit_hash=first.causal_hash
        )
        assert second.prev_commit_hash == first.causal_hash
        assert second.causal_hash != first.causal_hash


class TestVerifyCausalBinding:
    """Unit tests for causal binding verification."""

    def test_valid_binding(self):
        commitment = form_causal_commitment("sha256:abc", "sha256:def")
        result = verify_causal_binding(commitment, "sha256:abc", "sha256:def")
        assert result["valid"] is True

    def test_policy_hash_mismatch_blocks(self):
        commitment = form_causal_commitment("sha256:abc", "sha256:def")
        result = verify_causal_binding(commitment, "sha256:WRONG", "sha256:def")
        assert result["valid"] is False
        assert "policy_hash" in result["reason"]

    def test_params_hash_mismatch_blocks(self):
        commitment = form_causal_commitment("sha256:abc", "sha256:def")
        result = verify_causal_binding(commitment, "sha256:abc", "sha256:WRONG")
        assert result["valid"] is False
        assert "params_hash" in result["reason"]

    def test_both_mismatch(self):
        commitment = form_causal_commitment("sha256:abc", "sha256:def")
        result = verify_causal_binding(commitment, "sha256:WRONG", "sha256:WRONG2")
        assert result["valid"] is False


class TestCausalReceipt:
    """Integration tests for full receipt with causal binding."""

    def test_receipt_version(self):
        receipt = PACTReceipt()
        assert receipt.version == PACT_CAUSAL_VERSION

    def test_receipt_roundtrip(self):
        from pact.causal_binding import receipt_to_dict
        policy = PolicyCommitment(
            policy_hash="sha256:abc",
            params_hash="sha256:def",
            run_id="run-123",
            causal_hash="sha256:chain",
            log_index=1,
            log_id="log-1",
            merkle_root="sha256:merkle",
            merkle_proof=[],
        )
        tool_call = ToolCall(
            tool_name="read_file",
            tool_input_hash="sha256:input",
            timestamp="2026-06-22T13:00:00Z",
            action_id="action-1",
        )
        receipt = PACTReceipt(policy=policy, tool_call=tool_call)
        d = receipt_to_dict(receipt)
        assert d["version"] == PACT_CAUSAL_VERSION
        assert d["policy"]["params_hash"] == "sha256:def"
        assert d["policy"]["run_id"] == "run-123"
        assert d["policy"]["causal_hash"] == "sha256:chain"

    def test_verify_causal_receipt_full(self):
        params_hash = hash_tool_params("read_file", {"path": "/tmp/test"})
        policy_hash = "sha256:pol123"
        commitment = form_causal_commitment(policy_hash, params_hash)
        policy = PolicyCommitment(
            policy_hash=policy_hash,
            params_hash=params_hash,
            run_id=commitment.run_id,
            causal_hash=commitment.causal_hash,
            log_index=0,
            log_id="log-0",
            merkle_root="sha256:root",
            merkle_proof=[],
        )
        tool_call = ToolCall(
            tool_name="read_file",
            tool_input_hash="sha256:input",
            timestamp="2026-06-22T13:00:00Z",
            action_id="action-1",
        )
        receipt = PACTReceipt(policy=policy, tool_call=tool_call)
        result = verify_causal_receipt(receipt, policy_hash, params_hash)
        assert result["valid"] is True
        assert "v0.8.1" in result["reason"]
