"""
Tests for email views: EmailChangeView, EmailChangeConfirmView.
"""

import pytest
from django.urls import reverse
from rest_framework import status

from blockauth.models.otp import OTPSubject

EMAIL_CHANGE_URL = reverse("email-change")
EMAIL_CHANGE_CONFIRM_URL = reverse("confirm-email-change")

STRONG_PASS = "TestP@ss123!"


@pytest.mark.django_db
class TestEmailChangeView:

    def test_request_email_change(self, authenticated_client):
        client, user = authenticated_client(email="old@test.com", password=STRONG_PASS)
        response = client.post(
            EMAIL_CHANGE_URL,
            {
                "new_email": "new@test.com",
                "current_password": STRONG_PASS,
                "verification_type": "otp",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        assert "message" in response.data

    def test_email_change_wrong_current_password(self, authenticated_client):
        client, user = authenticated_client(email="old@test.com", password=STRONG_PASS)
        response = client.post(
            EMAIL_CHANGE_URL,
            {
                "new_email": "new@test.com",
                "current_password": "WrongP@ss!",
                "verification_type": "otp",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_email_change_duplicate_email(self, authenticated_client, create_user):
        create_user(email="taken@test.com")
        client, user = authenticated_client(email="old@test.com", password=STRONG_PASS)
        response = client.post(
            EMAIL_CHANGE_URL,
            {
                "new_email": "taken@test.com",
                "current_password": STRONG_PASS,
                "verification_type": "otp",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_email_change_unauthenticated(self, api_client):
        response = api_client.post(
            EMAIL_CHANGE_URL,
            {
                "new_email": "new@test.com",
                "current_password": STRONG_PASS,
                "verification_type": "otp",
            },
        )
        assert response.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)


@pytest.mark.django_db
class TestEmailChangeConfirmView:

    def test_confirm_email_change(self, authenticated_client, create_otp):
        client, user = authenticated_client(email="old@test.com", password=STRONG_PASS)
        create_otp(identifier="new@test.com", subject=OTPSubject.EMAIL_CHANGE, code="ABC123")

        response = client.post(
            EMAIL_CHANGE_CONFIRM_URL,
            {
                "identifier": "new@test.com",
                "code": "ABC123",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.email == "new@test.com"

    def test_confirm_invalid_otp(self, authenticated_client, create_otp):
        client, user = authenticated_client(email="old@test.com", password=STRONG_PASS)
        create_otp(identifier="new@test.com", subject=OTPSubject.EMAIL_CHANGE, code="ABC123")

        response = client.post(
            EMAIL_CHANGE_CONFIRM_URL,
            {
                "identifier": "new@test.com",
                "code": "WRONG",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_confirm_unauthenticated(self, api_client):
        response = api_client.post(
            EMAIL_CHANGE_CONFIRM_URL,
            {
                "identifier": "new@test.com",
                "code": "ABC123",
            },
        )
        assert response.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)

    def test_confirm_returns_fresh_tokens_and_user(self, authenticated_client, create_otp):
        """#110: email change confirmation issues fresh tokens + user so
        any custom-claims provider that pins email into the access token
        sees the new value. `message` is preserved for back-compat."""
        from blockauth.utils.token import Token

        client, user = authenticated_client(email="old@test.com", password=STRONG_PASS)
        create_otp(identifier="new@test.com", subject=OTPSubject.EMAIL_CHANGE, code="ABC123")

        response = client.post(
            EMAIL_CHANGE_CONFIRM_URL,
            {
                "identifier": "new@test.com",
                "code": "ABC123",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        # Additive: legacy `message` still there
        assert "message" in response.data
        # New: full auth state
        assert response.data["access"]
        assert response.data["refresh"]
        user_payload = response.data["user"]
        assert user_payload["id"] == str(user.id)
        assert user_payload["email"] == "new@test.com"
        # Access token decodes to the correct user
        payload = Token().decode_token(response.data["access"])
        assert str(payload["user_id"]) == str(user.id)
