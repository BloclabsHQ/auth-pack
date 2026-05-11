"""Unit tests for blockauth.utils.social.social_login_data.

Focused on the provider-tagging branch that decides whether a successful
sign-in should record the provider in `BlockUser.authentication_types`.
The Apple branch was previously omitted, leaving Apple Creators with
an empty list that downstream readers (admin UI, account-issuance
service, consent-revoked handler) depend on.
"""

import pytest

from blockauth.enums import AuthenticationType
from blockauth.utils.config import get_block_auth_user_model
from blockauth.utils.social import social_login_data


@pytest.mark.django_db
def test_social_login_data_tags_apple_authentication_type():
    """A successful Apple sign-in records APPLE in authentication_types."""
    user_model = get_block_auth_user_model()
    user = user_model.objects.create(email="apple-tagged@example.com")

    social_login_data(
        email=user.email,
        name="",
        provider_data={
            "provider": "apple",
            "user_info": {"sub": "apple-sub-1"},
            "preexisting_user": user,
        },
    )

    user.refresh_from_db()
    assert AuthenticationType.APPLE.value in (user.authentication_types or [])


@pytest.mark.django_db
def test_social_login_data_tags_google_authentication_type():
    """Regression: existing Google tagging still works."""
    user_model = get_block_auth_user_model()
    user = user_model.objects.create(email="google-tagged@example.com")

    social_login_data(
        email=user.email,
        name="",
        provider_data={
            "provider": "google",
            "user_info": {"sub": "google-sub-1"},
            "preexisting_user": user,
        },
    )

    user.refresh_from_db()
    assert AuthenticationType.GOOGLE.value in (user.authentication_types or [])
