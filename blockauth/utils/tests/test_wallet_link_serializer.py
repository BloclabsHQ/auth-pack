"""
Unit tests for WalletLinkSerializer.

WalletAuthenticator.verify_signature is mocked throughout — replay protection
and crypto are covered by test_wallet_replay_protection.py.
"""

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from blockauth.serializers.wallet_serializers import WalletLinkSerializer
from blockauth.utils.custom_exception import WalletConflictError


def _make_request(wallet_address=None):
    """Return a mock request whose user has the given wallet_address."""
    user = MagicMock()
    user.pk = "user-test-uuid-123"
    user.wallet_address = wallet_address
    request = MagicMock()
    request.user = user
    return request


def _make_data(wallet_address="0xabcdef1234567890abcdef1234567890abcdef12"):
    return {
        "wallet_address": wallet_address,
        "message": json.dumps({
            "nonce": "test-nonce-0000-1111-2222",
            "timestamp": int(time.time()),
            "body": "Link wallet to TestApp",
        }),
        "signature": "0x" + "a" * 130,
    }


class TestValidateWalletAddress:
    def test_valid_address_is_lowercased(self):
        request = _make_request()
        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth, \
             patch("blockauth.serializers.wallet_serializers._User") as mock_user_model:
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            s = WalletLinkSerializer(
                data=_make_data("0xABCDEF1234567890ABCDEF1234567890ABCDEF12"),
                context={"request": request},
            )
            assert s.is_valid(), s.errors
            assert s.validated_data["wallet_address"] == "0xabcdef1234567890abcdef1234567890abcdef12"

    def test_address_without_0x_prefix_is_invalid(self):
        request = _make_request()
        s = WalletLinkSerializer(
            data=_make_data("abcdef1234567890abcdef1234567890abcdef12"),
            context={"request": request},
        )
        assert not s.is_valid()
        assert "wallet_address" in s.errors

    def test_address_wrong_length_is_invalid(self):
        request = _make_request()
        s = WalletLinkSerializer(
            data=_make_data("0xshort"),
            context={"request": request},
        )
        assert not s.is_valid()
        assert "wallet_address" in s.errors


class TestSignatureVerification:
    def test_verify_signature_returns_false_gives_400(self):
        request = _make_request()
        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth:
            mock_auth.return_value.verify_signature.return_value = False
            s = WalletLinkSerializer(data=_make_data(), context={"request": request})
            assert not s.is_valid()
            assert "signature" in s.errors

    def test_expired_message_gives_400(self):
        request = _make_request()
        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth:
            mock_auth.return_value.verify_signature.side_effect = ValueError("Message has expired. Please sign a new message.")
            s = WalletLinkSerializer(data=_make_data(), context={"request": request})
            assert not s.is_valid()
            assert "message" in s.errors
            assert "expired" in str(s.errors["message"]).lower()

    def test_nonce_reused_gives_400(self):
        request = _make_request()
        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth:
            mock_auth.return_value.verify_signature.side_effect = ValueError("Nonce has already been used. Please sign a new message.")
            s = WalletLinkSerializer(data=_make_data(), context={"request": request})
            assert not s.is_valid()
            assert "message" in s.errors


class TestBusinessRules:
    def test_wallet_in_use_by_another_user_raises_conflict(self):
        request = _make_request(wallet_address=None)
        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth, \
             patch("blockauth.serializers.wallet_serializers._User") as mock_user_model:
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = True
            s = WalletLinkSerializer(data=_make_data(), context={"request": request})
            with pytest.raises(WalletConflictError):
                s.is_valid(raise_exception=True)

    def test_user_already_has_wallet_gives_400(self):
        existing = "0x1111111111111111111111111111111111111111"
        request = _make_request(wallet_address=existing)
        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth, \
             patch("blockauth.serializers.wallet_serializers._User") as mock_user_model:
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            s = WalletLinkSerializer(data=_make_data(), context={"request": request})
            assert not s.is_valid()
            assert "wallet_address" in s.errors

    def test_valid_unlinked_user_passes_validation(self):
        request = _make_request(wallet_address=None)
        with patch("blockauth.serializers.wallet_serializers.WalletAuthenticator") as mock_auth, \
             patch("blockauth.serializers.wallet_serializers._User") as mock_user_model:
            mock_auth.return_value.verify_signature.return_value = True
            mock_user_model.objects.filter.return_value.exclude.return_value.exists.return_value = False
            s = WalletLinkSerializer(data=_make_data(), context={"request": request})
            assert s.is_valid(), s.errors
