"""
Tests for password views: PasswordResetView, PasswordResetConfirmView, PasswordChangeView.
"""

import pytest
from django.urls import reverse
from rest_framework import status

from blockauth.models.otp import OTPSubject

PASSWORD_RESET_URL = reverse("password-reset")
PASSWORD_RESET_CONFIRM_URL = reverse("password-reset-confirm")
PASSWORD_CHANGE_URL = reverse("change-password")

# Test credentials (not real secrets)
STRONG_PASS = "TestP@ss123!"
STRONG_PASS_NEW = "NewTestP@ss456!"
WEAK_PASS = "weak"


@pytest.mark.django_db
class TestPasswordResetView:

    def test_reset_existing_user(self, api_client, create_user):
        create_user(email="user@test.com")
        response = api_client.post(PASSWORD_RESET_URL, {
            "identifier": "user@test.com",
            "method": "email",
            "verification_type": "otp",
        })
        assert response.status_code == status.HTTP_200_OK
        assert "message" in response.data

    def test_reset_nonexistent_user_same_response(self, api_client):
        """Should return same response for non-existent users (prevent enumeration)."""
        response = api_client.post(PASSWORD_RESET_URL, {
            "identifier": "nobody@test.com",
            "method": "email",
            "verification_type": "otp",
        })
        assert response.status_code == status.HTTP_200_OK

    def test_reset_missing_fields(self, api_client):
        response = api_client.post(PASSWORD_RESET_URL, {})
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)


@pytest.mark.django_db
class TestPasswordResetConfirmView:

    def test_reset_confirm_with_valid_otp(self, api_client, create_user, create_otp):
        user = create_user(email="user@test.com", password=STRONG_PASS)
        create_otp(identifier="user@test.com", subject=OTPSubject.PASSWORD_RESET, code="ABC123")

        response = api_client.post(PASSWORD_RESET_CONFIRM_URL, {
            "identifier": "user@test.com",
            "code": "ABC123",
            "new_password": STRONG_PASS_NEW,
            "confirm_password": STRONG_PASS_NEW,
        })
        assert response.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.check_password(STRONG_PASS_NEW)

    def test_reset_confirm_invalid_otp(self, api_client, create_user, create_otp):
        create_user(email="user@test.com")
        create_otp(identifier="user@test.com", subject=OTPSubject.PASSWORD_RESET, code="ABC123")

        response = api_client.post(PASSWORD_RESET_CONFIRM_URL, {
            "identifier": "user@test.com",
            "code": "WRONG",
            "new_password": STRONG_PASS_NEW,
            "confirm_password": STRONG_PASS_NEW,
        })
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_reset_confirm_passwords_dont_match(self, api_client, create_user, create_otp):
        create_user(email="user@test.com")
        create_otp(identifier="user@test.com", subject=OTPSubject.PASSWORD_RESET, code="ABC123")

        response = api_client.post(PASSWORD_RESET_CONFIRM_URL, {
            "identifier": "user@test.com",
            "code": "ABC123",
            "new_password": STRONG_PASS_NEW,
            "confirm_password": "DifferentP@ss!",
        })
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_reset_confirm_weak_new(self, api_client, create_user, create_otp):
        create_user(email="user@test.com")
        create_otp(identifier="user@test.com", subject=OTPSubject.PASSWORD_RESET, code="ABC123")

        response = api_client.post(PASSWORD_RESET_CONFIRM_URL, {
            "identifier": "user@test.com",
            "code": "ABC123",
            "new_password": WEAK_PASS,
            "confirm_password": WEAK_PASS,
        })
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)


@pytest.mark.django_db
class TestPasswordChangeView:

    def test_change_authenticated(self, authenticated_client):
        client, user = authenticated_client(password=STRONG_PASS)
        response = client.post(PASSWORD_CHANGE_URL, {
            "old_password": STRONG_PASS,
            "new_password": STRONG_PASS_NEW,
            "confirm_password": STRONG_PASS_NEW,
        })
        assert response.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.check_password(STRONG_PASS_NEW)

    def test_change_wrong_old(self, authenticated_client):
        client, user = authenticated_client(password=STRONG_PASS)
        response = client.post(PASSWORD_CHANGE_URL, {
            "old_password": "WrongP@ss!",
            "new_password": STRONG_PASS_NEW,
            "confirm_password": STRONG_PASS_NEW,
        })
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_change_unauthenticated(self, api_client):
        response = api_client.post(PASSWORD_CHANGE_URL, {
            "old_password": STRONG_PASS,
            "new_password": STRONG_PASS_NEW,
            "confirm_password": STRONG_PASS_NEW,
        })
        assert response.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)

    def test_change_weak_new(self, authenticated_client):
        client, user = authenticated_client(password=STRONG_PASS)
        response = client.post(PASSWORD_CHANGE_URL, {
            "old_password": STRONG_PASS,
            "new_password": WEAK_PASS,
            "confirm_password": WEAK_PASS,
        })
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)
