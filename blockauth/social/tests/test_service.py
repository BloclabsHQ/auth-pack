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
    import time

    user = User.objects.create_user(username="x_user", email="x@gmail.com", password="pw")
    initial = SocialIdentity.objects.create(
        provider="google", subject="g_sub_1", user=user, email_at_link="x@gmail.com", email_verified_at_link=True
    )
    initial_last_used = initial.last_used_at
    # Briefly sleep so the auto_now bump on `last_used_at` lands on a strictly
    # later timestamp (DB-level resolution can collapse sub-millisecond gaps).
    time.sleep(0.01)

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
    identity.refresh_from_db()
    assert identity.last_used_at > initial_last_used


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


@pytest.mark.django_db
def test_concurrent_create_loses_gracefully(monkeypatch):
    """If a concurrent sign-in already created the (provider, subject), the
    losing call must return the winner's identity rather than surfacing the
    raw IntegrityError to the caller.

    We simulate the race by monkeypatching the existing-identity lookup so
    the service skips Branch 1 even though the row exists, then the actual
    `identity.save()` collides on the unique constraint and the recovery
    path runs.
    """
    user_a = User.objects.create_user(username="alice", email="alice@gmail.com", password="pw")
    winner = SocialIdentity.objects.create(
        provider="google",
        subject="g_race",
        user=user_a,
        email_at_link="alice@gmail.com",
        email_verified_at_link=True,
    )

    # Force the existing-identity lookup to miss exactly once, so the service
    # falls through to a save() that hits the unique constraint.
    original_filter = SocialIdentity.objects.filter
    call_count = {"n": 0}

    def fake_filter(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # First call is the existing-identity check inside upsert_and_link.
            # Pretend nothing's there to force the new-insert path.
            return original_filter(provider="__nonexistent__", subject="__nonexistent__")
        return original_filter(*args, **kwargs)

    monkeypatch.setattr(SocialIdentity.objects, "filter", fake_filter)

    service = SocialIdentityService()
    returned_user, identity, created = service.upsert_and_link(
        provider="google",
        subject="g_race",
        email="alice@gmail.com",
        email_verified=True,
        extra_claims={},
    )

    assert returned_user.id == user_a.id
    assert identity.pk == winner.pk
    assert created is False


@pytest.mark.django_db
def test_decrypt_refresh_token_returns_none_without_key(encryption_key_b64):
    """A service instantiated without an encryption key returns None for
    `decrypt_refresh_token` even when an encrypted blob is present on the
    identity row. Pins the contract that key removal degrades gracefully
    rather than raising at decrypt time.
    """
    # Step 1: store a token using a configured key.
    service_with_key = SocialIdentityService()
    _, identity, _ = service_with_key.upsert_and_link(
        provider="apple",
        subject="a_no_key",
        email="apple@example.com",
        email_verified=False,
        extra_claims={},
        refresh_token="apple-tok",
    )
    assert identity.encrypted_refresh_token is not None

    # Step 2: simulate a deployment with the key removed.
    with override_settings(BLOCK_AUTH_SETTINGS={}):
        keyless_service = SocialIdentityService()
        assert keyless_service.decrypt_refresh_token(identity) is None


@pytest.mark.django_db
def test_link_uses_case_insensitive_email_match():
    """User stored with mixed-case email is found when the IdP returns lowercase.

    Pins the __iexact match introduced to avoid duplicate User rows that
    differ only in case.
    """
    user = User.objects.create_user(username="case_user", email="CaseUser@Gmail.com", password="pw")

    returned_user, identity, _ = SocialIdentityService().upsert_and_link(
        provider="google",
        subject="g_case_test",
        email="caseuser@gmail.com",
        email_verified=True,
        extra_claims={},
    )

    assert returned_user.id == user.id


@pytest.mark.django_db
def test_existing_identity_syncs_changed_verified_email():
    """Apple Hide -> Share (and similar IdP-side email changes) overwrite the
    stored email on an already-linked identity. Pins the
    `_sync_user_email_from_provider` behavior — the bug was that subsequent
    sign-ins kept the relay address even after the user re-consented to share
    the real one.
    """
    user = User.objects.create_user(
        username="apple_relay_user",
        email="abc123@privaterelay.appleid.com",
        password="pw",
    )
    SocialIdentity.objects.create(
        provider="apple",
        subject="a_sub_relay",
        user=user,
        email_at_link="abc123@privaterelay.appleid.com",
        email_verified_at_link=True,
    )

    SocialIdentityService().upsert_and_link(
        provider="apple",
        subject="a_sub_relay",
        email="real.user@example.com",
        email_verified=True,
        extra_claims={"is_private_email": False},
    )

    user.refresh_from_db()
    assert user.email == "real.user@example.com"


@pytest.mark.django_db
def test_existing_identity_keeps_email_when_unchanged():
    """No-op when the IdP returns the same email (modulo case). Avoids a
    needless write on every sign-in."""
    user = User.objects.create_user(
        username="stable_email_user",
        email="stable@example.com",
        password="pw",
    )
    SocialIdentity.objects.create(
        provider="google",
        subject="g_stable",
        user=user,
        email_at_link="stable@example.com",
        email_verified_at_link=True,
    )

    SocialIdentityService().upsert_and_link(
        provider="google",
        subject="g_stable",
        email="STABLE@example.com",
        email_verified=True,
        extra_claims={},
    )

    user.refresh_from_db()
    assert user.email == "stable@example.com"


@pytest.mark.django_db
def test_existing_identity_skips_email_sync_when_unverified():
    """Don't overwrite a verified email with an unverified one — the unverified
    address could be spoofed and the user could lose access to the account."""
    user = User.objects.create_user(
        username="unverified_signin_user",
        email="trusted@example.com",
        password="pw",
    )
    SocialIdentity.objects.create(
        provider="facebook",
        subject="fb_sub",
        user=user,
        email_at_link="trusted@example.com",
        email_verified_at_link=True,
    )

    SocialIdentityService().upsert_and_link(
        provider="facebook",
        subject="fb_sub",
        email="attacker@example.com",
        email_verified=False,
        extra_claims={},
    )

    user.refresh_from_db()
    assert user.email == "trusted@example.com"


@pytest.mark.django_db
def test_existing_identity_skips_email_sync_on_collision():
    """Refusing the sync when the new email already belongs to another user
    prevents a silent merge of two distinct accounts. The integrator gets a
    warning log and can decide on a manual remediation path."""
    user_a = User.objects.create_user(
        username="user_a",
        email="abc123@privaterelay.appleid.com",
        password="pw",
    )
    User.objects.create_user(
        username="user_b",
        email="real.user@example.com",
        password="pw",
    )
    SocialIdentity.objects.create(
        provider="apple",
        subject="a_sub_collision",
        user=user_a,
        email_at_link="abc123@privaterelay.appleid.com",
        email_verified_at_link=True,
    )

    SocialIdentityService().upsert_and_link(
        provider="apple",
        subject="a_sub_collision",
        email="real.user@example.com",
        email_verified=True,
        extra_claims={"is_private_email": False},
    )

    user_a.refresh_from_db()
    assert user_a.email == "abc123@privaterelay.appleid.com"
