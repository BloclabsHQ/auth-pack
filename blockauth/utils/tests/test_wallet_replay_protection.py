"""
Tests for wallet signature replay protection.

Covers:
- Structured message parsing (nonce, timestamp)
- Timestamp expiry rejection
- Nonce reuse rejection
- Valid signature flow with replay protection
- Edge cases: future timestamps, missing fields, short nonces
"""

import json
import time
from unittest.mock import MagicMock

import pytest
from django.core.cache import cache

from blockauth.utils.web3.wallet import WalletAuthenticator


@pytest.fixture(autouse=True)
def clear_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def authenticator():
    return WalletAuthenticator()


def _make_message(nonce="test-nonce-0000-1111", timestamp=None, body="Sign in to TestApp"):
    if timestamp is None:
        timestamp = int(time.time())
    return json.dumps({"nonce": nonce, "timestamp": timestamp, "body": body})


class TestParseMessage:
    def test_valid_json_message(self, authenticator):
        msg = _make_message()
        nonce, ts = authenticator._parse_message(msg)
        assert len(nonce) >= 16
        assert isinstance(ts, int)

    def test_plain_text_rejected(self, authenticator):
        with pytest.raises(ValueError, match="JSON"):
            authenticator._parse_message("Sign in to MyApp")

    def test_missing_nonce_rejected(self, authenticator):
        msg = json.dumps({"timestamp": int(time.time()), "body": "hello"})
        with pytest.raises(ValueError, match="nonce"):
            authenticator._parse_message(msg)

    def test_short_nonce_rejected(self, authenticator):
        msg = json.dumps({"nonce": "short", "timestamp": int(time.time())})
        with pytest.raises(ValueError, match="nonce"):
            authenticator._parse_message(msg)

    def test_missing_timestamp_rejected(self, authenticator):
        msg = json.dumps({"nonce": "a" * 32, "body": "hello"})
        with pytest.raises(ValueError, match="timestamp"):
            authenticator._parse_message(msg)

    def test_non_numeric_timestamp_rejected(self, authenticator):
        msg = json.dumps({"nonce": "a" * 32, "timestamp": "not-a-number"})
        with pytest.raises(ValueError, match="numeric"):
            authenticator._parse_message(msg)


class TestTimestampValidation:
    def test_valid_timestamp(self, authenticator):
        # Should not raise
        authenticator._validate_timestamp(int(time.time()))

    def test_expired_message_rejected(self, authenticator):
        old_ts = int(time.time()) - 600  # 10 minutes ago, default TTL is 5 min
        with pytest.raises(ValueError, match="expired"):
            authenticator._validate_timestamp(old_ts)

    def test_future_timestamp_rejected(self, authenticator):
        future_ts = int(time.time()) + 120
        with pytest.raises(ValueError, match="future"):
            authenticator._validate_timestamp(future_ts)


class TestNonceReuse:
    def test_fresh_nonce_allowed(self, authenticator):
        # Should not raise
        authenticator._validate_nonce("unique-nonce-12345678", "0xabc")

    def test_consumed_nonce_rejected(self, authenticator):
        nonce = "unique-nonce-12345678"
        address = "0xabc"
        authenticator._consume_nonce(nonce, address)
        with pytest.raises(ValueError, match="already been used"):
            authenticator._validate_nonce(nonce, address)

    def test_same_nonce_different_address_allowed(self, authenticator):
        nonce = "unique-nonce-12345678"
        authenticator._consume_nonce(nonce, "0xabc")
        # Different address should still work
        authenticator._validate_nonce(nonce, "0xdef")


class TestVerifySignatureIntegration:
    """Integration tests using mocked web3 signature recovery."""

    ADDRESS = "0x" + "aB" * 20  # fake test address

    def _mock_recovery(self, authenticator, recovered_address):
        authenticator.w3.eth.account.recover_message = MagicMock(return_value=recovered_address)

    def test_valid_signature_succeeds(self, authenticator):
        msg = _make_message()
        sig = "0x" + "ab" * 65  # noqa: S105 fake test signature
        self._mock_recovery(authenticator, self.ADDRESS)

        result = authenticator.verify_signature(self.ADDRESS, msg, sig)
        assert result is True

    def test_replay_same_nonce_fails(self, authenticator):
        nonce = "fixed-nonce-for-replay-test1"
        msg = _make_message(nonce=nonce)
        sig = "0x" + "ab" * 65  # noqa: S105
        self._mock_recovery(authenticator, self.ADDRESS)

        # First call succeeds
        assert authenticator.verify_signature(self.ADDRESS, msg, sig) is True

        # Replay with same nonce fails
        with pytest.raises(ValueError, match="already been used"):
            authenticator.verify_signature(self.ADDRESS, msg, sig)

    def test_wrong_address_returns_false(self, authenticator):
        msg = _make_message()
        sig = "0x" + "ab" * 65  # noqa: S105
        self._mock_recovery(authenticator, "0xDEADBEEF" + "0" * 32)

        result = authenticator.verify_signature(self.ADDRESS, msg, sig)
        assert result is False

    def test_expired_message_rejected_before_sig_check(self, authenticator):
        msg = _make_message(timestamp=int(time.time()) - 600)
        sig = "0x" + "ab" * 65  # noqa: S105

        with pytest.raises(ValueError, match="expired"):
            authenticator.verify_signature(self.ADDRESS, msg, sig)

    def test_nonce_not_consumed_on_bad_signature(self, authenticator):
        """If signature check fails, nonce should NOT be consumed."""
        nonce = "test-nonce-bad-sig-01"
        msg = _make_message(nonce=nonce)
        sig = "0x" + "ab" * 65  # noqa: S105
        self._mock_recovery(authenticator, "0xWRONG" + "0" * 34)

        result = authenticator.verify_signature(self.ADDRESS, msg, sig)
        assert result is False

        # Nonce should still be valid (not consumed) since sig was wrong
        authenticator._validate_nonce(nonce, self.ADDRESS)  # should not raise

    def test_invalid_signature_length(self, authenticator):
        msg = _make_message()
        sig = "0x" + "ab" * 30  # too short

        with pytest.raises(ValueError, match="length"):
            authenticator.verify_signature(self.ADDRESS, msg, sig)
