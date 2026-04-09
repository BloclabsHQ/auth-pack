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
        response = client.post(EMAIL_CHANGE_URL, {
            "new_email": "new@test.com",
            "current_password": STRONG_PASS,
            "verification_type": "otp",
        })
        assert response.status_code == status.HTTP_200_OK
        assert "message" in response.data

    def test_email_change_wrong_current_password(self, authenticated_client):
        client, user = authenticated_client(email="old@test.com", password=STRONG_PASS)
        response = client.post(EMAIL_CHANGE_URL, {
            "new_email": "new@test.com",
            "current_password": "WrongP@ss!",
            "verification_type": "otp",
        })
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_email_change_duplicate_email(self, authenticated_client, create_user):
        create_user(email="taken@test.com")
        client, user = authenticated_client(email="old@test.com", password=STRONG_PASS)
        response = client.post(EMAIL_CHANGE_URL, {
            "new_email": "taken@test.com",
            "current_password": STRONG_PASS,
            "verification_type": "otp",
        })
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_email_change_unauthenticated(self, api_client):
        response = api_client.post(EMAIL_CHANGE_URL, {
            "new_email": "new@test.com",
            "current_password": STRONG_PASS,
            "verification_type": "otp",
        })
        assert response.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)


@pytest.mark.django_db
class TestEmailChangeConfirmView:

    def test_confirm_email_change(self, authenticated_client, create_otp):
        client, user = authenticated_client(email="old@test.com", password=STRONG_PASS)
        create_otp(identifier="new@test.com", subject=OTPSubject.EMAIL_CHANGE, code="ABC123")

        response = client.post(EMAIL_CHANGE_CONFIRM_URL, {
            "identifier": "new@test.com",
            "code": "ABC123",
        })
        assert response.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.email == "new@test.com"

    def test_confirm_invalid_otp(self, authenticated_client, create_otp):
        client, user = authenticated_client(email="old@test.com", password=STRONG_PASS)
        create_otp(identifier="new@test.com", subject=OTPSubject.EMAIL_CHANGE, code="ABC123")

        response = client.post(EMAIL_CHANGE_CONFIRM_URL, {
            "identifier": "new@test.com",
            "code": "WRONG",
        })
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_confirm_unauthenticated(self, api_client):
        response = api_client.post(EMAIL_CHANGE_CONFIRM_URL, {
            "identifier": "new@test.com",
            "code": "ABC123",
        })
        assert response.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)
