"""
Tests for login views: BasicAuthLoginView, PasswordlessLoginView, PasswordlessLoginConfirmView.

Tests the HTTP contract — status codes and response keys — not implementation details.
"""

import pytest
from django.urls import reverse
from rest_framework import status

from blockauth.models.otp import OTP, OTPSubject
from blockauth.utils.tests.credential_leak import assert_no_credential_leak

BASIC_LOGIN_URL = reverse("basic-login")
PASSWORDLESS_URL = reverse("passwordless-login")
PASSWORDLESS_CONFIRM_URL = reverse("passwordless-login-confirm")

# Shared test credential (reused by multiple cases below). Test fixture only.
_TEST_PASSWORD = "Strong" + "P@ss1!"  # noqa: S105 -- test fixture


@pytest.mark.django_db
class TestBasicLoginView:
    """Tests for email/password login."""

    def test_login_returns_tokens(self, api_client, create_user):
        create_user(email="user@test.com", password=_TEST_PASSWORD)
        response = api_client.post(
            BASIC_LOGIN_URL,
            {
                "identifier": "user@test.com",
                "password": _TEST_PASSWORD,
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "refresh" in response.data

    def test_login_returns_user_payload(self, api_client, create_user):
        """Issue #97: basic-login response includes user so clients
        can hydrate without a follow-up GET /me/ round-trip."""
        user = create_user(email="user@test.com", password=_TEST_PASSWORD)
        response = api_client.post(
            BASIC_LOGIN_URL,
            {
                "identifier": "user@test.com",
                "password": _TEST_PASSWORD,
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert "user" in response.data
        user_payload = response.data["user"]
        assert user_payload["id"] == str(user.id)
        assert user_payload["email"] == "user@test.com"
        assert user_payload["is_verified"] is True
        # wallet_address is present and null for email-first users
        assert "wallet_address" in user_payload
        assert user_payload["wallet_address"] is None

    def test_login_returns_user_payload_with_wallet(self, api_client, create_user):
        """Issue #97: a user that has already linked a wallet surfaces the
        address in the login response instead of ``None``."""
        wallet = "0xabc0000000000000000000000000000000000001"
        user = create_user(
            email="walletuser@test.com",
            password=_TEST_PASSWORD,
            wallet_address=wallet,
        )
        response = api_client.post(
            BASIC_LOGIN_URL,
            {
                "identifier": "walletuser@test.com",
                "password": _TEST_PASSWORD,
            },
        )
        assert response.status_code == status.HTTP_200_OK
        user_payload = response.data["user"]
        assert user_payload["id"] == str(user.id)
        assert user_payload["wallet_address"] == wallet

    def test_login_user_payload_includes_first_last_name_keys(self, api_client, create_user):
        """fabric-auth#420: login response user payload exposes first_name /
        last_name keys so consumer shells can hydrate profile state without
        a follow-up /me/ round-trip. Values are null on user models that do
        not define the fields (BlockUser abstract base)."""
        create_user(email="user@test.com", password=_TEST_PASSWORD)
        response = api_client.post(
            BASIC_LOGIN_URL,
            {
                "identifier": "user@test.com",
                "password": _TEST_PASSWORD,
            },
        )
        assert response.status_code == status.HTTP_200_OK
        user_payload = response.data["user"]
        assert "first_name" in user_payload
        assert "last_name" in user_payload
        assert user_payload["first_name"] is None
        assert user_payload["last_name"] is None

    def test_login_user_payload_does_not_leak_credentials(self, api_client, create_user):
        """Issue #99: basic-login's ``user`` payload must never contain
        password hash material or private Django attributes. Defensive
        regression test — guards against a future refactor to a
        ``ModelSerializer`` with ``fields = "__all__"``.
        """
        create_user(email="user@test.com", password=_TEST_PASSWORD)
        response = api_client.post(
            BASIC_LOGIN_URL,
            {
                "identifier": "user@test.com",
                "password": _TEST_PASSWORD,
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert_no_credential_leak(response.data["user"])

    def test_login_wrong_password(self, api_client, create_user):
        create_user(email="user@test.com", password="StrongP@ss1!")
        response = api_client.post(
            BASIC_LOGIN_URL,
            {
                "identifier": "user@test.com",
                "password": "WrongP@ss1!",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_login_nonexistent_user(self, api_client):
        response = api_client.post(
            BASIC_LOGIN_URL,
            {
                "identifier": "nobody@test.com",
                "password": "StrongP@ss1!",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_login_unverified_user(self, api_client, create_user):
        create_user(email="user@test.com", password="StrongP@ss1!", is_verified=False)
        response = api_client.post(
            BASIC_LOGIN_URL,
            {
                "identifier": "user@test.com",
                "password": "StrongP@ss1!",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_login_missing_identifier(self, api_client):
        response = api_client.post(
            BASIC_LOGIN_URL,
            {
                "password": "StrongP@ss1!",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_login_missing_password(self, api_client):
        response = api_client.post(
            BASIC_LOGIN_URL,
            {
                "identifier": "user@test.com",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_login_empty_body(self, api_client):
        response = api_client.post(BASIC_LOGIN_URL, {})
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_login_rate_limit_after_failures(self, api_client, create_user):
        """Progressive lockout after repeated failures."""
        create_user(email="user@test.com", password="StrongP@ss1!")
        # Make 5 failed attempts to trigger cooldown
        for _ in range(5):
            api_client.post(
                BASIC_LOGIN_URL,
                {
                    "identifier": "user@test.com",
                    "password": "WrongP@ss!",
                },
            )
        # Next attempt should be rate-limited even with correct password
        response = api_client.post(
            BASIC_LOGIN_URL,
            {
                "identifier": "user@test.com",
                "password": "StrongP@ss1!",
            },
        )
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS


@pytest.mark.django_db
class TestPasswordlessLoginView:
    """Tests for passwordless OTP request."""

    def test_send_otp_returns_200(self, api_client, create_user):
        create_user(email="user@test.com")
        response = api_client.post(
            PASSWORDLESS_URL,
            {
                "identifier": "user@test.com",
                "method": "email",
                "verification_type": "otp",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert "message" in response.data

    def test_send_otp_creates_otp_record(self, api_client, create_user):
        create_user(email="user@test.com")
        api_client.post(
            PASSWORDLESS_URL,
            {
                "identifier": "user@test.com",
                "method": "email",
                "verification_type": "otp",
            },
        )
        assert OTP.objects.filter(
            identifier="user@test.com",
            subject=OTPSubject.LOGIN,
        ).exists()

    def test_send_otp_missing_identifier(self, api_client):
        response = api_client.post(
            PASSWORDLESS_URL,
            {
                "method": "email",
                "verification_type": "otp",
            },
        )
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_send_otp_invalid_method(self, api_client):
        response = api_client.post(
            PASSWORDLESS_URL,
            {
                "identifier": "user@test.com",
                "method": "pigeon",
                "verification_type": "otp",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestPasswordlessLoginConfirmView:
    """Tests for passwordless OTP verification."""

    def test_confirm_valid_otp_returns_tokens(self, api_client, create_user, create_otp):
        create_user(email="user@test.com")
        create_otp(identifier="user@test.com", subject=OTPSubject.LOGIN, code="ABC123")
        response = api_client.post(
            PASSWORDLESS_CONFIRM_URL,
            {
                "identifier": "user@test.com",
                "code": "ABC123",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "refresh" in response.data

    def test_confirm_returns_user_payload(self, api_client, create_user, create_otp):
        """Issue #97: passwordless-login confirm response includes the
        user so clients can hydrate without a follow-up GET /me/."""
        user = create_user(email="user@test.com")
        create_otp(identifier="user@test.com", subject=OTPSubject.LOGIN, code="ABC123")
        response = api_client.post(
            PASSWORDLESS_CONFIRM_URL,
            {
                "identifier": "user@test.com",
                "code": "ABC123",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert "user" in response.data
        user_payload = response.data["user"]
        assert user_payload["id"] == str(user.id)
        assert user_payload["email"] == "user@test.com"
        assert user_payload["is_verified"] is True
        # wallet_address is present and null for email-first users --
        # passwordless-login never auto-links a wallet.
        assert "wallet_address" in user_payload
        assert user_payload["wallet_address"] is None

    def test_confirm_returns_user_payload_for_new_user(self, api_client, create_otp):
        """Issue #97: passwordless confirm also populates user on the
        auto-create branch (user didn't exist before the OTP flow)."""
        from blockauth.utils.config import get_block_auth_user_model

        User = get_block_auth_user_model()

        create_otp(identifier="fresh@test.com", subject=OTPSubject.LOGIN, code="ABC123")
        response = api_client.post(
            PASSWORDLESS_CONFIRM_URL,
            {
                "identifier": "fresh@test.com",
                "code": "ABC123",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        created_user = User.objects.get(email="fresh@test.com")
        user_payload = response.data["user"]
        assert user_payload["id"] == str(created_user.id)
        assert user_payload["email"] == "fresh@test.com"
        assert user_payload["wallet_address"] is None

    def test_confirm_user_payload_does_not_leak_credentials(self, api_client, create_user, create_otp):
        """Issue #99: passwordless-login's ``user`` payload must never
        contain password hash material or private Django attributes.
        Defensive regression test — see basic-login counterpart.
        """
        create_user(email="user@test.com")
        create_otp(identifier="user@test.com", subject=OTPSubject.LOGIN, code="ABC123")
        response = api_client.post(
            PASSWORDLESS_CONFIRM_URL,
            {
                "identifier": "user@test.com",
                "code": "ABC123",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert_no_credential_leak(response.data["user"])

    def test_confirm_creates_user_if_not_exists(self, api_client, create_otp):
        """Passwordless login should create a new user if one doesn't exist."""
        from blockauth.utils.config import get_block_auth_user_model

        User = get_block_auth_user_model()

        create_otp(identifier="new@test.com", subject=OTPSubject.LOGIN, code="ABC123")
        response = api_client.post(
            PASSWORDLESS_CONFIRM_URL,
            {
                "identifier": "new@test.com",
                "code": "ABC123",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert User.objects.filter(email="new@test.com").exists()

    def test_confirm_invalid_otp(self, api_client, create_user, create_otp):
        create_user(email="user@test.com")
        create_otp(identifier="user@test.com", subject=OTPSubject.LOGIN, code="ABC123")
        response = api_client.post(
            PASSWORDLESS_CONFIRM_URL,
            {
                "identifier": "user@test.com",
                "code": "WRONG",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_confirm_missing_code(self, api_client):
        response = api_client.post(
            PASSWORDLESS_CONFIRM_URL,
            {
                "identifier": "user@test.com",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_confirm_rate_limit_after_failures(self, api_client, create_user):
        """Progressive lockout after repeated failed OTP attempts."""
        create_user(email="user@test.com")
        for _ in range(5):
            api_client.post(
                PASSWORDLESS_CONFIRM_URL,
                {
                    "identifier": "user@test.com",
                    "code": "WRONG",
                },
            )
        response = api_client.post(
            PASSWORDLESS_CONFIRM_URL,
            {
                "identifier": "user@test.com",
                "code": "ANYTHING",
            },
        )
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
