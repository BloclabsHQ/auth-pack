"""
Tests for signup views: SignUpView, SignUpResendOTPView, SignUpConfirmView.
"""

import pytest
from django.urls import reverse
from rest_framework import status

from blockauth.models.otp import OTP, OTPSubject

SIGNUP_URL = reverse("signup")
SIGNUP_RESEND_URL = reverse("signup-otp-resend")
SIGNUP_CONFIRM_URL = reverse("signup-confirm")


@pytest.mark.django_db
class TestSignUpView:

    def test_signup_with_email(self, api_client):
        response = api_client.post(SIGNUP_URL, {
            "identifier": "new@test.com",
            "password": "StrongP@ss1!",
            "method": "email",
            "verification_type": "otp",
        })
        assert response.status_code == status.HTTP_200_OK
        assert "message" in response.data

    def test_signup_creates_user_and_otp(self, api_client):
        from blockauth.utils.config import get_block_auth_user_model
        User = get_block_auth_user_model()

        api_client.post(SIGNUP_URL, {
            "identifier": "new@test.com",
            "password": "StrongP@ss1!",
            "method": "email",
            "verification_type": "otp",
        })
        assert User.objects.filter(email="new@test.com").exists()
        assert OTP.objects.filter(identifier="new@test.com", subject=OTPSubject.SIGNUP).exists()

    def test_signup_duplicate_email(self, api_client, create_user):
        create_user(email="exists@test.com")
        response = api_client.post(SIGNUP_URL, {
            "identifier": "exists@test.com",
            "password": "StrongP@ss1!",
            "method": "email",
            "verification_type": "otp",
        })
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_signup_weak_password(self, api_client):
        response = api_client.post(SIGNUP_URL, {
            "identifier": "new@test.com",
            "password": "weak",
            "method": "email",
            "verification_type": "otp",
        })
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_signup_missing_fields(self, api_client):
        response = api_client.post(SIGNUP_URL, {})
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_signup_invalid_email(self, api_client):
        response = api_client.post(SIGNUP_URL, {
            "identifier": "not-an-email",
            "password": "StrongP@ss1!",
            "method": "email",
            "verification_type": "otp",
        })
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)


@pytest.mark.django_db
class TestSignUpResendOTPView:

    def test_resend_for_unverified_user(self, api_client, create_user):
        create_user(email="unverified@test.com", is_verified=False)
        response = api_client.post(SIGNUP_RESEND_URL, {
            "identifier": "unverified@test.com",
            "method": "email",
            "verification_type": "otp",
        })
        # Should return 200 regardless (prevent user enumeration)
        assert response.status_code == status.HTTP_200_OK

    def test_resend_for_nonexistent_user(self, api_client):
        response = api_client.post(SIGNUP_RESEND_URL, {
            "identifier": "nobody@test.com",
            "method": "email",
            "verification_type": "otp",
        })
        # Same response to prevent enumeration
        assert response.status_code == status.HTTP_200_OK

    def test_resend_missing_fields(self, api_client):
        response = api_client.post(SIGNUP_RESEND_URL, {})
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)


@pytest.mark.django_db
class TestSignUpConfirmView:

    def test_confirm_valid_otp_verifies_user(self, api_client, create_user, create_otp):
        from blockauth.utils.config import get_block_auth_user_model
        User = get_block_auth_user_model()

        user = create_user(email="new@test.com", is_verified=False)
        create_otp(identifier="new@test.com", subject=OTPSubject.SIGNUP, code="ABC123")

        response = api_client.post(SIGNUP_CONFIRM_URL, {
            "identifier": "new@test.com",
            "code": "ABC123",
        })
        assert response.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.is_verified is True

    def test_confirm_invalid_otp(self, api_client, create_user, create_otp):
        create_user(email="new@test.com", is_verified=False)
        create_otp(identifier="new@test.com", subject=OTPSubject.SIGNUP, code="ABC123")

        response = api_client.post(SIGNUP_CONFIRM_URL, {
            "identifier": "new@test.com",
            "code": "WRONG",
        })
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_confirm_missing_code(self, api_client):
        response = api_client.post(SIGNUP_CONFIRM_URL, {
            "identifier": "new@test.com",
        })
        assert response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_429_TOO_MANY_REQUESTS)
