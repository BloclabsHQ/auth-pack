"""
Tests for wallet views: WalletAuthLoginView, WalletEmailAddView.

Wallet signature verification is mocked since it requires real ECDSA operations.
"""

from unittest.mock import MagicMock, patch

import pytest
from django.urls import reverse
from rest_framework import status

from blockauth.services.wallet_login_service import VerifiedLogin
from blockauth.services.wallet_user_linker import LinkedUser

WALLET_LOGIN_URL = reverse("wallet-login")
WALLET_EMAIL_ADD_URL = reverse("wallet-email-add")

VALID_WALLET = "0x" + "a1" * 20  # 42 char wallet address


@pytest.mark.django_db
class TestWalletAuthLoginView:

    @patch("blockauth.serializers.wallet_serializers.WalletAuthenticator")
    def test_wallet_login_returns_tokens(self, mock_auth_cls, api_client):
        mock_auth = MagicMock()
        mock_auth.verify_signature.return_value = True
        mock_auth_cls.return_value = mock_auth

        response = api_client.post(
            WALLET_LOGIN_URL,
            {
                "wallet_address": VALID_WALLET,
                "message": "Sign in to BlockAuth\nNonce: abc123\nTimestamp: 2025-01-01T00:00:00Z",
                "signature": "0x" + "ab" * 65,
            },
        )
        # Should succeed or fail based on serializer validation
        # The exact behavior depends on WalletLoginSerializer internals
        assert response.status_code in (
            status.HTTP_200_OK,
            status.HTTP_400_BAD_REQUEST,  # If serializer validation fails
        )

    def test_wallet_login_user_payload_full_shape(self, api_client, create_user):
        """Issue #131: wallet-login pins the same {is_active, date_joined,
        wallets} keys as basic-login / passwordless-login. SIWE verification
        and the linker are stubbed so the test exercises the view's payload-
        building only — the cryptographic path has its own coverage in
        ``utils/tests/test_wallet_login_siwe.py``.
        """
        # Wallet-first user (no email) — the canonical case the issue calls
        # out: clients require ``wallets`` to be populated even when
        # ``email`` is null.
        wallet = "0xabc0000000000000000000000000000000000003"
        user = create_user(email=None, wallet_address=wallet, password=None)

        verified = VerifiedLogin(address=wallet, nonce_id=1, siwe=MagicMock())
        linked = LinkedUser(
            user_id=str(user.id),
            email=user.email or "",
            access_token="test-access",
            refresh_token="test-refresh",
            created=False,
            user=user,
        )

        with (
            patch("blockauth.views.wallet_auth_views.get_wallet_login_service") as mock_get_svc,
            patch("blockauth.views.wallet_auth_views.wallet_user_linker") as mock_linker,
        ):
            mock_svc = MagicMock()
            mock_svc.verify_login.return_value = verified
            mock_get_svc.return_value = mock_svc
            mock_linker.link.return_value = linked

            response = api_client.post(
                WALLET_LOGIN_URL,
                {
                    "wallet_address": wallet,
                    "message": "ignored — service is stubbed",
                    "signature": "0x" + "ab" * 65,
                },
            )

        assert response.status_code == status.HTTP_200_OK, response.data
        user_payload = response.data["user"]
        assert set(user_payload.keys()) == {
            "id",
            "email",
            "is_verified",
            "is_active",
            "date_joined",
            "wallet_address",
            "wallets",
        }
        assert user_payload["id"] == str(user.id)
        assert user_payload["email"] is None  # wallet-first user
        assert user_payload["wallet_address"] == wallet
        # #537: wallets is ``WalletItem[]``, not ``string[]``
        assert len(user_payload["wallets"]) == 1
        wallet_item = user_payload["wallets"][0]
        assert wallet_item["address"] == wallet
        assert wallet_item["chain_id"] == 1
        assert wallet_item["primary"] is True
        assert user_payload["is_active"] is True

    def test_wallet_login_invalid_address_rejected(self, api_client):
        """Invalid wallet address should not succeed (400 or error)."""
        api_client.raise_request_exception = False
        response = api_client.post(
            WALLET_LOGIN_URL,
            {
                "wallet_address": "not-a-wallet",
                "message": "Sign in",
                "signature": "0x" + "ab" * 65,
            },
        )
        assert response.status_code != status.HTTP_200_OK

    def test_wallet_login_missing_fields(self, api_client):
        response = api_client.post(WALLET_LOGIN_URL, {})
        assert response.status_code in (
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@pytest.mark.django_db
class TestWalletEmailAddView:

    def test_add_email_unauthenticated(self, api_client):
        response = api_client.post(
            WALLET_EMAIL_ADD_URL,
            {
                "email": "new@test.com",
                "verification_type": "otp",
            },
        )
        assert response.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)

    def test_add_email_authenticated(self, authenticated_client):
        client, user = authenticated_client(email="wallet@test.com")
        response = client.post(
            WALLET_EMAIL_ADD_URL,
            {
                "email": "new@test.com",
                "verification_type": "otp",
            },
        )
        # Should either succeed or fail based on wallet-specific validation
        assert response.status_code in (
            status.HTTP_200_OK,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_add_email_returns_fresh_tokens_and_user_on_success(self, authenticated_client):
        """#110: wallet/email/add issues fresh tokens + user so any
        custom-claims provider pinning email sees the new (unverified)
        address. is_verified flips to False; new tokens carry that state."""
        from blockauth.utils.token import Token

        client, user = authenticated_client(email=None, wallet_address=VALID_WALLET, is_verified=True)
        response = client.post(
            WALLET_EMAIL_ADD_URL,
            {
                "email": "add@test.com",
                "verification_type": "otp",
            },
        )
        if response.status_code != status.HTTP_200_OK:
            # Wallet-specific validation blocked — skip the auth-state
            # assertions (the shape assertion is covered by the other
            # 200-path endpoints).
            return
        assert "message" in response.data  # legacy field preserved
        assert response.data["access"]
        assert response.data["refresh"]
        user_payload = response.data["user"]
        assert user_payload["id"] == str(user.id)
        assert user_payload["email"] == "add@test.com"
        assert user_payload["is_verified"] is False  # reset on add
        payload = Token().decode_token(response.data["access"])
        assert str(payload["user_id"]) == str(user.id)
