"""SEC-08: email case variants are one account."""

import pytest
from django.urls import reverse
from rest_framework import status

from blockauth.models.otp import OTPSubject

SIGNUP_URL = reverse("signup")
SIGNUP_CONFIRM_URL = reverse("signup-confirm")
LOGIN_URL = reverse("basic-login")
PASSWORDLESS_CONFIRM_URL = reverse("passwordless-login-confirm")
_PASSWORD = "StrongP@ss1!"


def _signup_payload(password=_PASSWORD):
    from django.contrib.auth.hashers import make_password

    from blockauth.enums import AuthenticationType

    return {
        "hashed_password": make_password(password),
        "authentication_types": [AuthenticationType.EMAIL],
    }


@pytest.mark.django_db
def test_login_accepts_other_email_case(api_client, create_user):
    """SEC-08: an account created as User@Example.com signs in as user@example.com."""
    create_user(email="User@Example.com", password=_PASSWORD, is_verified=True)
    response = api_client.post(
        LOGIN_URL,
        {"identifier": "user@example.com", "password": _PASSWORD},
        format="json",
    )
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
def test_otp_confirms_with_other_email_case(api_client, create_otp):
    """SEC-08: a code issued to User@Example.com confirms as user@example.com."""
    from blockauth.utils.config import get_block_auth_user_model

    create_otp(
        identifier="User@Example.com",
        subject=OTPSubject.SIGNUP,
        code="ABC123",
        payload=_signup_payload(),
    )
    response = api_client.post(
        SIGNUP_CONFIRM_URL,
        {"identifier": "user@example.com", "code": "ABC123"},
        format="json",
    )
    assert response.status_code == status.HTTP_200_OK
    User = get_block_auth_user_model()
    assert User.objects.filter(email__iexact="user@example.com").count() == 1
    assert User.objects.get(email__iexact="user@example.com").email == "user@example.com"


@pytest.mark.django_db
def test_signup_does_not_open_a_second_account_for_email_case(api_client, create_user):
    """SEC-08: signup with another case of an existing email is rejected."""
    create_user(email="User@Example.com", password=_PASSWORD, is_verified=True)
    response = api_client.post(
        SIGNUP_URL,
        {
            "identifier": "user@example.com",
            "method": "email",
            "verification_type": "otp",
            "password": _PASSWORD,
        },
        format="json",
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
def test_passwordless_confirm_reuses_mixed_case_email(api_client, create_user, create_otp):
    """SEC-08: passwordless confirm for the lowercase form reuses the existing account."""
    from blockauth.utils.config import get_block_auth_user_model

    create_user(email="User@Example.com", password=_PASSWORD, is_verified=True)
    create_otp(identifier="user@example.com", subject=OTPSubject.LOGIN, code="ABC123")
    response = api_client.post(
        PASSWORDLESS_CONFIRM_URL,
        {"identifier": "user@example.com", "code": "ABC123"},
        format="json",
    )
    assert response.status_code == status.HTTP_200_OK
    User = get_block_auth_user_model()
    assert User.objects.filter(email__iexact="user@example.com").count() == 1
