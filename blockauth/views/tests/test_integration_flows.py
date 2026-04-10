"""
Integration tests for end-to-end authentication flows.

Each test exercises a complete authentication flow as a single sequential test,
hitting real endpoints with DRF's APIClient and creating real DB records.
"""

import pytest
from django.urls import reverse

from blockauth.models.otp import OTP, OTPSubject

STRONG_PASS = "TestP@ss123!"
STRONG_PASS_NEW = "NewStr0ng!Pass99"


def _get_otp_code(identifier, subject=None):
    """Retrieve the most recent OTP code from DB for an identifier."""
    qs = OTP.objects.filter(identifier=identifier)
    if subject:
        qs = qs.filter(subject=subject)
    otp = qs.order_by("-created_at").first()
    assert otp is not None, f"No OTP found for {identifier}"
    return otp.code


@pytest.mark.django_db
class TestSignupLoginRefreshFlow:
    """Flow: Signup -> Confirm OTP -> Login -> Refresh token."""

    def test_full_signup_login_refresh(self, api_client):
        email = "signup-flow@test.com"

        # 1. Signup
        resp = api_client.post(
            reverse("signup"),
            {"identifier": email, "password": STRONG_PASS, "method": "email"},
            format="json",
        )
        assert resp.status_code == 200, resp.data

        # 2. Confirm signup with OTP from DB
        code = _get_otp_code(email, subject=OTPSubject.SIGNUP)
        resp = api_client.post(
            reverse("signup-confirm"),
            {"identifier": email, "code": code},
            format="json",
        )
        assert resp.status_code == 200, resp.data

        # 3. Login with same credentials
        resp = api_client.post(
            reverse("basic-login"),
            {"identifier": email, "password": STRONG_PASS},
            format="json",
        )
        assert resp.status_code == 200, resp.data
        assert "access" in resp.data
        assert "refresh" in resp.data
        refresh_token = resp.data["refresh"]

        # 4. Refresh token
        resp = api_client.post(
            reverse("refresh-token"),
            {"refresh_token": refresh_token},
            format="json",
        )
        assert resp.status_code == 200, resp.data
        assert "access" in resp.data
        assert "refresh" in resp.data


@pytest.mark.django_db
class TestPasswordResetFlow:
    """Flow: Create user -> Request password reset -> Confirm with OTP -> Login with new password."""

    def test_full_password_reset(self, api_client, create_user):
        email = "reset-flow@test.com"
        create_user(email=email, password=STRONG_PASS, is_verified=True)

        # 1. Request password reset
        resp = api_client.post(
            reverse("password-reset"),
            {"identifier": email, "method": "email"},
            format="json",
        )
        assert resp.status_code == 200, resp.data

        # 2. Confirm password reset with OTP + new password
        code = _get_otp_code(email, subject=OTPSubject.PASSWORD_RESET)
        resp = api_client.post(
            reverse("password-reset-confirm"),
            {
                "identifier": email,
                "code": code,
                "new_password": STRONG_PASS_NEW,
                "confirm_password": STRONG_PASS_NEW,
            },
            format="json",
        )
        assert resp.status_code == 200, resp.data

        # 3. Login with new password succeeds
        resp = api_client.post(
            reverse("basic-login"),
            {"identifier": email, "password": STRONG_PASS_NEW},
            format="json",
        )
        assert resp.status_code == 200, resp.data
        assert "access" in resp.data


@pytest.mark.django_db
class TestPasswordlessLoginFlow:
    """Flow: Request passwordless OTP -> Confirm OTP -> Get tokens (user auto-created)."""

    def test_full_passwordless_login(self, api_client):
        email = "passwordless@test.com"

        # 1. Request passwordless login OTP
        resp = api_client.post(
            reverse("passwordless-login"),
            {"identifier": email, "method": "email"},
            format="json",
        )
        assert resp.status_code == 200, resp.data

        # 2. Confirm OTP — user is created automatically
        code = _get_otp_code(email, subject=OTPSubject.LOGIN)
        resp = api_client.post(
            reverse("passwordless-login-confirm"),
            {"identifier": email, "code": code},
            format="json",
        )
        assert resp.status_code == 200, resp.data
        assert "access" in resp.data
        assert "refresh" in resp.data

        # 3. Verify user was created and verified in DB
        from blockauth.utils.config import get_block_auth_user_model

        User = get_block_auth_user_model()
        user = User.objects.get(email=email)
        assert user.is_verified is True


@pytest.mark.django_db
class TestEmailChangeFlow:
    """Flow: Authenticated user -> Request email change -> Confirm with OTP -> Verify DB updated."""

    def test_full_email_change(self, authenticated_client):
        old_email = "email-change@test.com"
        new_email = "new-email@test.com"
        client, user = authenticated_client(email=old_email, password=STRONG_PASS)

        # 1. Request email change
        resp = client.post(
            reverse("email-change"),
            {
                "new_email": new_email,
                "current_password": STRONG_PASS,
            },
            format="json",
        )
        assert resp.status_code == 200, resp.data

        # 2. Confirm email change with OTP sent to new email
        code = _get_otp_code(new_email, subject=OTPSubject.EMAIL_CHANGE)
        resp = client.post(
            reverse("confirm-email-change"),
            {"identifier": new_email, "code": code},
            format="json",
        )
        assert resp.status_code == 200, resp.data

        # 3. Verify user email was updated in DB
        user.refresh_from_db()
        assert user.email == new_email


@pytest.mark.django_db
class TestPasswordChangeFlow:
    """Flow: Authenticated user -> Change password -> Login with new password."""

    def test_full_password_change(self, api_client, authenticated_client):
        email = "pw-change@test.com"
        client, user = authenticated_client(email=email, password=STRONG_PASS)

        # 1. Change password (authenticated)
        resp = client.post(
            reverse("change-password"),
            {
                "old_password": STRONG_PASS,
                "new_password": STRONG_PASS_NEW,
                "confirm_password": STRONG_PASS_NEW,
            },
            format="json",
        )
        assert resp.status_code == 200, resp.data

        # 2. Login with new password (fresh unauthenticated client)
        resp = api_client.post(
            reverse("basic-login"),
            {"identifier": email, "password": STRONG_PASS_NEW},
            format="json",
        )
        assert resp.status_code == 200, resp.data
        assert "access" in resp.data
