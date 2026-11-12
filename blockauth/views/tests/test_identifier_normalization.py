"""SEC-08: email case variants are one account."""

import pytest
from django.urls import reverse
from rest_framework import status

from blockauth.models.otp import OTP, OTPSubject
from blockauth.utils.config import get_block_auth_user_model

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
    """SEC-08: another case of an existing email does not open an account."""
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
    assert response.status_code == status.HTTP_200_OK
    User = get_block_auth_user_model()
    email = "user@example.com"
    assert User.objects.filter(email__iexact=email).count() == 1
    assert not OTP.objects.filter(identifier__iexact=email).exists()


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


_STORED = "Legacy@Test.com"
_NORMAL = "legacy@test.com"
_NEW_PASSWORD = "NewStrongP@ss2!"
RESET_CONFIRM_URL = reverse("password-reset-confirm")


@pytest.mark.django_db
def test_reset_confirm_mixed_case(api_client, create_user, create_otp):
    """SEC-08: reset confirm finds a mixed-case stored email."""
    user = create_user(email=_STORED, password=_PASSWORD)
    create_otp(
        identifier=_NORMAL,
        subject=OTPSubject.PASSWORD_RESET,
        code="ABC123",
    )
    response = api_client.post(
        RESET_CONFIRM_URL,
        {
            "identifier": _NORMAL,
            "code": "ABC123",
            "new_password": _NEW_PASSWORD,
            "confirm_password": _NEW_PASSWORD,
        },
        format="json",
    )
    assert response.status_code == status.HTTP_200_OK
    user.refresh_from_db()
    assert user.check_password(_NEW_PASSWORD)


@pytest.mark.django_db
def test_legacy_signup_confirm_mixed_case(api_client, create_user, create_otp):
    """SEC-08: legacy signup confirm finds a mixed-case email."""
    user = create_user(email=_STORED, is_verified=False)
    create_otp(
        identifier=_NORMAL,
        subject=OTPSubject.SIGNUP,
        code="ABC123",
    )
    response = api_client.post(
        SIGNUP_CONFIRM_URL,
        {"identifier": _NORMAL, "code": "ABC123"},
        format="json",
    )
    assert response.status_code == status.HTTP_200_OK
    user.refresh_from_db()
    assert user.is_verified is True
    User = get_block_auth_user_model()
    assert User.objects.filter(email__iexact=_NORMAL).count() == 1


@pytest.mark.django_db
def test_wallet_email_confirm_mixed_case(api_client, create_user, create_otp):
    """SEC-08: wallet email confirm finds a mixed-case email."""
    user = create_user(email=_STORED, is_verified=False)
    create_otp(
        identifier=_NORMAL,
        subject=OTPSubject.WALLET_EMAIL_VERIFICATION,
        code="ABC123",
    )
    response = api_client.post(
        SIGNUP_CONFIRM_URL,
        {"identifier": _NORMAL, "code": "ABC123"},
        format="json",
    )
    assert response.status_code == status.HTTP_200_OK
    user.refresh_from_db()
    assert user.is_verified is True
