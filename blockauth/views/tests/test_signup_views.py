"""
Tests for signup views: SignUpView, SignUpResendOTPView, SignUpConfirmView.
"""

import pytest
from django.contrib.auth.hashers import make_password
from django.urls import reverse
from rest_framework import status
from unittest.mock import patch

from blockauth.models.otp import OTP, OTPSubject

SIGNUP_URL = reverse("signup")
SIGNUP_RESEND_URL = reverse("signup-otp-resend")
SIGNUP_CONFIRM_URL = reverse("signup-confirm")

# Shared test credential — same value the conftest create_user fixture uses
_TEST_PW = "StrongP@ss1!"

_SIGNUP_REQUEST = {
    "identifier": "new@test.com",
    "method": "email",
    "verification_type": "otp",
}


def _make_signup_otp_payload(pw=_TEST_PW):
    """Return a realistic OTP payload matching what SignUpView stores."""
    from blockauth.enums import AuthenticationType

    return {
        "hashed_password": make_password(pw),
        "authentication_types": [AuthenticationType.EMAIL],
    }


@pytest.mark.django_db
class TestSignUpView:

    def test_signup_with_email(self, api_client):
        response = api_client.post(SIGNUP_URL, {**_SIGNUP_REQUEST, "password": _TEST_PW})
        assert response.status_code == status.HTTP_200_OK
        assert "message" in response.data

    def test_signup_creates_otp_without_user_row(self, api_client):
        """Ghost-free flow: SignUpView creates the OTP but NOT the user row.
        The user row is created in SignUpConfirmView after inbox ownership is
        proven (fabric-auth#516).
        """
        from blockauth.utils.config import get_block_auth_user_model

        User = get_block_auth_user_model()

        api_client.post(SIGNUP_URL, {**_SIGNUP_REQUEST, "password": _TEST_PW})

        # OTP must exist with a payload carrying the hashed credential
        otp = OTP.objects.filter(identifier="new@test.com", subject=OTPSubject.SIGNUP).first()
        assert otp is not None, "SIGNUP OTP must be created"
        assert otp.payload is not None, "OTP payload must carry signup data"
        assert "hashed_password" in otp.payload
        assert "authentication_types" in otp.payload

        # No user row until confirm
        assert not User.objects.filter(email="new@test.com").exists(), (
            "fabric_user row must not exist until SignUpConfirmView succeeds"
        )

    def test_signup_otp_send_failure_leaves_no_user_row(self, api_client):
        """If send_otp raises, no orphan fabric_user row is left behind and
        the same email can be retried immediately (fabric-auth#516 regression guard).
        """
        from blockauth.utils.config import get_block_auth_user_model

        User = get_block_auth_user_model()

        with patch(
            "blockauth.views.basic_auth_views.send_otp",
            side_effect=Exception("SES sandbox rejection"),
        ):
            response = api_client.post(SIGNUP_URL, {**_SIGNUP_REQUEST, "password": _TEST_PW})

        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert not User.objects.filter(email="new@test.com").exists(), (
            "No fabric_user row must remain after a failed OTP send"
        )

    def test_signup_retry_after_otp_send_failure_succeeds(self, api_client):
        """A Creator can retry signup with the same email after a failed OTP send."""
        from blockauth.utils.config import get_block_auth_user_model

        User = get_block_auth_user_model()

        # First attempt — OTP send fails
        with patch(
            "blockauth.views.basic_auth_views.send_otp",
            side_effect=Exception("SES sandbox rejection"),
        ):
            api_client.post(SIGNUP_URL, {**_SIGNUP_REQUEST, "password": _TEST_PW})

        # Second attempt — OTP send is live; no user row exists to block code 4002
        response = api_client.post(SIGNUP_URL, {**_SIGNUP_REQUEST, "password": _TEST_PW})

        assert response.status_code == status.HTTP_200_OK, (
            "Retry with the same email must succeed after a failed OTP send — "
            "code 4002 must not fire when no user row exists"
        )
        assert not User.objects.filter(email="new@test.com").exists(), (
            "User row must still not exist until confirm"
        )

    def test_signup_duplicate_email_blocked_after_confirm(self, api_client, create_user):
        """Existing verified Creator blocks re-signup (code 4002 unchanged)."""
        create_user(email="exists@test.com", is_verified=True)
        response = api_client.post(
            SIGNUP_URL,
            {"identifier": "exists@test.com", "method": "email", "verification_type": "otp", "password": _TEST_PW},
        )
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_signup_weak_password(self, api_client):
        response = api_client.post(SIGNUP_URL, {**_SIGNUP_REQUEST, "password": "weak"})
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_signup_missing_fields(self, api_client):
        response = api_client.post(SIGNUP_URL, {})
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_signup_invalid_email(self, api_client):
        response = api_client.post(SIGNUP_URL, {**_SIGNUP_REQUEST, "identifier": "not-an-email"})
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)


@pytest.mark.django_db
class TestSignUpResendOTPView:

    def test_resend_for_pending_otp_no_user_row(self, api_client, create_otp):
        """Ghost-free path: resend works when there's a pending OTP but no user row."""
        create_otp(
            identifier="pending@test.com",
            subject=OTPSubject.SIGNUP,
            payload=_make_signup_otp_payload(),
        )
        response = api_client.post(
            SIGNUP_RESEND_URL,
            {"identifier": "pending@test.com", "method": "email", "verification_type": "otp"},
        )
        assert response.status_code == status.HTTP_200_OK

    def test_resend_for_unverified_user(self, api_client, create_user):
        """Legacy path: unverified user row triggers resend."""
        create_user(email="unverified@test.com", is_verified=False)
        response = api_client.post(
            SIGNUP_RESEND_URL,
            {"identifier": "unverified@test.com", "method": "email", "verification_type": "otp"},
        )
        assert response.status_code == status.HTTP_200_OK

    def test_resend_for_nonexistent_user(self, api_client):
        """No user, no pending OTP — still returns 200 (enumeration protection)."""
        response = api_client.post(
            SIGNUP_RESEND_URL,
            {"identifier": "nobody@test.com", "method": "email", "verification_type": "otp"},
        )
        assert response.status_code == status.HTTP_200_OK

    def test_resend_carries_payload_to_new_otp(self, api_client, create_otp):
        """Resend must carry the hashed-credential payload to the new OTP so
        SignUpConfirmView can still create the user row after a resend."""
        create_otp(
            identifier="resend@test.com",
            subject=OTPSubject.SIGNUP,
            payload=_make_signup_otp_payload(),
        )

        api_client.post(
            SIGNUP_RESEND_URL,
            {"identifier": "resend@test.com", "method": "email", "verification_type": "otp"},
        )

        new_otp = OTP.objects.filter(
            identifier="resend@test.com", subject=OTPSubject.SIGNUP, is_used=False
        ).first()
        assert new_otp is not None, "New OTP must be created on resend"
        assert new_otp.payload is not None, "New OTP must carry payload from original"
        assert "hashed_password" in new_otp.payload

    def test_resend_missing_fields(self, api_client):
        response = api_client.post(SIGNUP_RESEND_URL, {})
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)


@pytest.mark.django_db
class TestSignUpConfirmView:

    def test_confirm_creates_user_from_otp_payload(self, api_client, create_otp):
        """Ghost-free path: user row must be created by SignUpConfirmView
        from the OTP payload (fabric-auth#516).
        """
        from blockauth.utils.config import get_block_auth_user_model

        User = get_block_auth_user_model()

        create_otp(
            identifier="new@test.com",
            subject=OTPSubject.SIGNUP,
            code="ABC123",
            payload=_make_signup_otp_payload(),
        )

        response = api_client.post(
            SIGNUP_CONFIRM_URL,
            {"identifier": "new@test.com", "code": "ABC123"},
        )

        assert response.status_code == status.HTTP_200_OK, response.content
        user = User.objects.filter(email="new@test.com").first()
        assert user is not None, "fabric_user row must be created on confirm"
        assert user.is_verified is True

    def test_confirm_credential_is_usable_after_creation(self, api_client, create_otp):
        """Credential hashed at signup time must still authenticate after confirm."""
        create_otp(
            identifier="new@test.com",
            subject=OTPSubject.SIGNUP,
            code="ABC123",
            payload=_make_signup_otp_payload(_TEST_PW),
        )

        api_client.post(
            SIGNUP_CONFIRM_URL,
            {"identifier": "new@test.com", "code": "ABC123"},
        )

        from blockauth.utils.config import get_block_auth_user_model

        user = get_block_auth_user_model().objects.get(email="new@test.com")
        assert user.check_password(_TEST_PW), "Credential stored via payload must authenticate"

    def test_confirm_valid_otp_verifies_user_legacy(self, api_client, create_user, create_otp):
        """Legacy path: pre-existing unverified user row is verified on confirm."""
        from blockauth.utils.config import get_block_auth_user_model

        User = get_block_auth_user_model()

        user = create_user(email="new@test.com", is_verified=False)
        create_otp(identifier="new@test.com", subject=OTPSubject.SIGNUP, code="ABC123")

        response = api_client.post(
            SIGNUP_CONFIRM_URL,
            {"identifier": "new@test.com", "code": "ABC123"},
        )
        assert response.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.is_verified is True

    def test_confirm_invalid_otp(self, api_client, create_otp):
        create_otp(
            identifier="new@test.com",
            subject=OTPSubject.SIGNUP,
            code="ABC123",
            payload=_make_signup_otp_payload(),
        )
        response = api_client.post(
            SIGNUP_CONFIRM_URL,
            {"identifier": "new@test.com", "code": "WRONG"},
        )
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_confirm_missing_code(self, api_client):
        response = api_client.post(SIGNUP_CONFIRM_URL, {"identifier": "new@test.com"})
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_confirm_returns_tokens_and_user(self, api_client, create_otp):
        """fabric-auth#420: signup confirmation issues JWTs + user payload."""
        create_otp(
            identifier="new@test.com",
            subject=OTPSubject.SIGNUP,
            code="ABC123",
            payload=_make_signup_otp_payload(),
        )

        response = api_client.post(
            SIGNUP_CONFIRM_URL,
            {"identifier": "new@test.com", "code": "ABC123"},
        )
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "refresh" in response.data
        assert response.data["access"]
        assert response.data["refresh"]

        user_payload = response.data["user"]
        assert user_payload["email"] == "new@test.com"
        assert user_payload["is_verified"] is True
        assert user_payload["wallet_address"] is None
        # Issue #131: AuthUser shell schema requires is_active, date_joined, wallets[]
        assert user_payload["is_active"] is True
        assert "date_joined" in user_payload
        assert user_payload["wallets"] == []

    def test_confirm_access_token_decodes_for_new_user(self, api_client, create_otp):
        """Access token issued on confirm must decode with the newly created user's id."""
        from blockauth.utils.token import Token

        create_otp(
            identifier="newtok@test.com",
            subject=OTPSubject.SIGNUP,
            code="ABC123",
            payload=_make_signup_otp_payload(),
        )

        response = api_client.post(
            SIGNUP_CONFIRM_URL,
            {"identifier": "newtok@test.com", "code": "ABC123"},
        )
        assert response.status_code == status.HTTP_200_OK

        from blockauth.utils.config import get_block_auth_user_model

        user = get_block_auth_user_model().objects.get(email="newtok@test.com")
        decoded = Token().decode_token(response.data["access"])
        assert str(decoded["user_id"]) == str(user.id)
