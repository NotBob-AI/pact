"""Tests for transparency.py (Layer 1: Siglog transparency log adapter)"""

import json
import hashlib
import pytest
from unittest.mock import patch, MagicMock
from pact.transparency import (
    _sha256,
    register_policy,
    append_receipt,
    get_checkpoint,
    verify_receipt_inclusion,
    verify_policy_commitment,
)


class TestSha256:
    def test_string_input(self):
        h = _sha256("hello")
        expected = hashlib.sha256(b"hello").hexdigest()
        assert h == expected

    def test_bytes_input(self):
        h = _sha256(b"hello")
        expected = hashlib.sha256(b"hello").hexdigest()
        assert h == expected


class TestRegisterPolicy:
    @patch("pact.transparency.requests.post")
    def test_registers_hash_not_plaintext(self, mock_post):
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {"log_id": "abc123", "tree_size": 42}
        mock_post.return_value = mock_response

        result = register_policy('{"tools": ["read"]}', "test-policy")

        # Verify sha256 was computed before submission
        expected_hash = hashlib.sha256('{"tools": ["read"]}'.encode()).hexdigest()
        assert result["policy_hash"] == expected_hash

        # Verify siglog received the hash, not plaintext
        call_body = mock_post.call_args[1]["json"]["payload"]
        assert call_body["entry_type"] == "policy_commitment"
        assert call_body["policy_hash"] == expected_hash
        assert '{"tools": ["read"]}' not in str(call_body)

    @patch("pact.transparency.requests.post")
    def test_returns_log_info(self, mock_post):
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {"log_id": "abc123", "tree_size": 42}
        mock_post.return_value = mock_response

        result = register_policy("{}")

        assert result["log_id"] == "abc123"
        assert result["tree_size"] == 42
        assert result["policy_hash"] is not None
        assert "timestamp" in result


class TestAppendReceipt:
    @patch("pact.transparency.requests.post")
    def test_submits_receipt_hash_only(self, mock_post):
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {"log_id": "receipt001", "tree_size": 99}
        mock_post.return_value = mock_response

        receipt_hash = "abcd1234" * 8  # 64-char hex
        result = append_receipt(receipt_hash, "receipt-001")

        call_body = mock_post.call_args[1]["json"]["payload"]
        assert call_body["entry_type"] == "receipt_anchor"
        assert call_body["receipt_hash"] == receipt_hash
        assert call_body["receipt_id"] == "receipt-001"

    @patch("pact.transparency.requests.post")
    def test_raises_on_failure(self, mock_post):
        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.status_code = 500
        mock_response.text = "internal error"
        mock_post.return_value = mock_response

        with pytest.raises(RuntimeError, match="siglog append failed"):
            append_receipt("hash", "id")


class TestGetCheckpoint:
    @patch("pact.transparency.requests.get")
    def test_returns_checkpoint(self, mock_get):
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {"size": 100, "hash": "checkpoint-hash"}
        mock_get.return_value = mock_response

        result = get_checkpoint()
        assert result["size"] == 100

    @patch("pact.transparency.requests.get")
    def test_returns_none_on_404(self, mock_get):
        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = get_checkpoint()
        assert result is None


class TestVerifyReceiptInclusion:
    @patch("pact.transparency.requests.get")
    def test_verified_true(self, mock_get):
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {"proof": "merkle-proof-data"}
        mock_get.return_value = mock_response

        result = verify_receipt_inclusion("somehash", "log-id-123")
        assert result["verified"] is True
        assert "note" in result  # verification note from Rust guest

    @patch("pact.transparency.requests.get")
    def test_verified_false_on_error(self, mock_get):
        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = verify_receipt_inclusion("somehash", "missing-log-id")
        assert result["verified"] is False


class TestVerifyPolicyCommitment:
    @patch("pact.transparency.requests.get")
    def test_registered_when_found(self, mock_get):
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = [{"policy_hash": "somehash", "log_id": "abc"}]
        mock_get.return_value = mock_response

        result = verify_policy_commitment("somehash")
        assert result["registered"] is True

    @patch("pact.transparency.requests.get")
    def test_not_registered_when_missing(self, mock_get):
        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = verify_policy_commitment("unknown-hash")
        assert result["registered"] is False
