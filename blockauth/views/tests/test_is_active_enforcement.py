"""SEC-03: ``is_active=False`` must block login and token use.

Downstream user models that define a real ``is_active`` column follow
Django's standard "disable account" convention. These tests pin that
an inactive user cannot log in, cannot keep using an already-issued
access token, cannot refresh, and cannot obtain tokens via the
passwordless confirm path.
"""

import pytest
from django.urls import reverse
from rest_framework import status

from blockauth.models.otp import OTPSubject
from blockauth.utils.token import Token, generate_auth_token

BASIC_LOGIN_URL = reverse("basic-login")
PASSWORDLESS_CONFIRM_URL = reverse("passwordless-login-confirm")
PASSWORD_CHANGE_URL = reverse("change-password")
REFRESH_URL = reverse("refresh-token")

STRONG_PASS = "TestP@ss123!"
STRONG_PASS_NEW = "NewTestP@ss456!"


@pytest.mark.django_db
class TestIsActiveEnforcement:
    def test_basic_login_rejects_inactive_user(self, api_client, create_user):
        create_user(email="inactive@test.com", password=STRONG_PASS, is_verified=True, is_active=False)
        response = api_client.post(
            BASIC_LOGIN_URL,
            {"identifier": "inactive@test.com", "password": STRONG_PASS},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "access" not in response.data
        assert "refresh" not in response.data

    def test_issued_access_token_rejected_after_deactivation(self, api_client, create_user):
        user = create_user(email="deactivated@test.com", password=STRONG_PASS)
        access, _ = generate_auth_token(token_class=Token(), user_id=str(user.id))
        user.is_active = False
        user.save(update_fields=["is_active"])

        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        response = api_client.post(
            PASSWORD_CHANGE_URL,
            {
                "old_password": STRONG_PASS,
                "new_password": STRONG_PASS_NEW,
                "confirm_password": STRONG_PASS_NEW,
            },
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_refresh_rejected_after_deactivation(self, api_client, create_user):
        user = create_user(email="refresh@test.com", password=STRONG_PASS)
        _, refresh = generate_auth_token(token_class=Token(), user_id=str(user.id))
        user.is_active = False
        user.save(update_fields=["is_active"])

        response = api_client.post(REFRESH_URL, {"refresh_token": refresh})
        # The view has no authentication classes, so DRF coerces
        # AuthenticationFailed (401) to 403 — the same status an invalid
        # refresh token gets on this endpoint. No tokens are issued.
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "access" not in response.data

    def test_passwordless_confirm_rejects_inactive_user(self, api_client, create_user, create_otp):
        create_user(email="otp-inactive@test.com", is_verified=True, is_active=False)
        create_otp(identifier="otp-inactive@test.com", subject=OTPSubject.LOGIN, code="ABC123")
        response = api_client.post(
            PASSWORDLESS_CONFIRM_URL,
            {"identifier": "otp-inactive@test.com", "code": "ABC123"},
        )
        # Same DRF 401->403 coercion as the refresh view (no
        # authentication classes on this AllowAny endpoint).
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "access" not in response.data
        assert "refresh" not in response.data
