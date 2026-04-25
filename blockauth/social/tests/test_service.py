"""SocialIdentityService.upsert_and_link behavior.

Covers: existing identity match, new identity linked to existing user via
authoritative email, conflict on non-authoritative provider, brand-new user
creation, refresh-token encryption round-trip.

Uses django.contrib.auth.get_user_model() (auth.User in tests) — matches
the SocialIdentity.user FK target. The user-model mismatch deviation
documented in Tasks 2.2/2.3 applies here too.
"""

import base64

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings

from blockauth.social.exceptions import SocialIdentityConflictError
from blockauth.social.models import SocialIdentity
from blockauth.social.service import SocialIdentityService

User = get_user_model()


@pytest.fixture
def encryption_key_b64(aes_key):
    return base64.b64encode(aes_key).decode()


@pytest.fixture(autouse=True)
def _settings(encryption_key_b64):
    with override_settings(BLOCK_AUTH_SETTINGS={"SOCIAL_IDENTITY_ENCRYPTION_KEY": encryption_key_b64}):
        yield


@pytest.mark.django_db
def test_existing_identity_returns_same_user():
    user = User.objects.create_user(username="x_user", email="x@gmail.com", password="pw")
    SocialIdentity.objects.create(
        provider="google", subject="g_sub_1", user=user, email_at_link="x@gmail.com", email_verified_at_link=True
    )

    returned_user, identity, created = SocialIdentityService().upsert_and_link(
        provider="google",
        subject="g_sub_1",
        email="x@gmail.com",
        email_verified=True,
        extra_claims={},
    )

    assert returned_user.id == user.id
    assert identity.provider == "google"
    assert created is False


@pytest.mark.django_db
def test_new_identity_links_to_existing_user_via_authoritative_email():
    user = User.objects.create_user(username="bob_user", email="bob@gmail.com", password="pw")

    returned_user, identity, created = SocialIdentityService().upsert_and_link(
        provider="google",
        subject="g_sub_new",
        email="bob@gmail.com",
        email_verified=True,
        extra_claims={},
    )

    assert returned_user.id == user.id
    assert identity.subject == "g_sub_new"
    assert created is False


@pytest.mark.django_db
def test_apple_with_existing_email_raises_conflict():
    User.objects.create_user(username="bob2_user", email="bob@gmail.com", password="pw")

    with pytest.raises(SocialIdentityConflictError) as excinfo:
        SocialIdentityService().upsert_and_link(
            provider="apple",
            subject="a_sub_1",
            email="bob@gmail.com",
            email_verified=True,
            extra_claims={},
        )
    assert excinfo.value.provider == "apple"


@pytest.mark.django_db
def test_brand_new_user_created():
    returned_user, identity, created = SocialIdentityService().upsert_and_link(
        provider="google",
        subject="g_sub_first",
        email="newuser@gmail.com",
        email_verified=True,
        extra_claims={},
    )

    assert returned_user.email == "newuser@gmail.com"
    assert identity.provider == "google"
    assert created is True


@pytest.mark.django_db
def test_refresh_token_encrypted_round_trip():
    service = SocialIdentityService()
    _, identity, _ = service.upsert_and_link(
        provider="apple",
        subject="a_sub_refresh",
        email="apple@example.com",
        email_verified=False,
        extra_claims={},
        refresh_token="apple-refresh-token-xyz",
    )

    blob = bytes(identity.encrypted_refresh_token)
    assert blob != b"apple-refresh-token-xyz"

    decrypted = service.decrypt_refresh_token(identity)
    assert decrypted == "apple-refresh-token-xyz"
