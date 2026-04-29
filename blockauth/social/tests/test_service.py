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

from blockauth.social.exceptions import (
    SocialIdentityConflictError,
    SocialIdentityUserUnavailableError,
)
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
def test_existing_identity_refuses_user_hidden_by_default_manager(monkeypatch):
    """FK traversal can still resolve soft-deleted users through Django's base
    manager. The service must honor the user model's default-manager scope and
    fail closed before syncing fields or minting tokens."""
    user = User.objects.create_user(
        username="hidden_user",
        email="hidden@example.com",
        password="pw",
    )
    SocialIdentity.objects.create(
        provider="apple",
        subject="a_hidden",
        user=user,
        email_at_link="hidden@example.com",
        email_verified_at_link=True,
    )

    original_filter = User._default_manager.filter

    def fake_filter(*args, **kwargs):
        if kwargs == {"pk": user.pk}:
            return original_filter(pk=-1)
        return original_filter(*args, **kwargs)

    monkeypatch.setattr(User._default_manager, "filter", fake_filter)

    with pytest.raises(SocialIdentityUserUnavailableError) as excinfo:
        SocialIdentityService().upsert_and_link(
            provider="apple",
            subject="a_hidden",
            email="updated@example.com",
            email_verified=True,
            extra_claims={},
        )

    assert excinfo.value.provider == "apple"
    assert excinfo.value.existing_user_id == str(user.pk)

    user.refresh_from_db()
    assert user.email == "hidden@example.com"


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


@pytest.mark.django_db
def test_existing_identity_skips_email_sync_on_db_unique_violation(monkeypatch):
    """Soft-delete-style integrator schemas with managers that hide rows from
    the in-memory collision check can still trip a DB-level unique constraint
    on `email`. When the save raises `IntegrityError`, the sync must skip
    cleanly — restore the in-memory email, log a warning, return False — and
    the surrounding `upsert_and_link` must still complete. The savepoint
    around the failing save is what keeps the outer transaction usable on
    postgres; without it, the post-sync `existing_identity.save(...)` would
    raise `TransactionManagementError`."""
    import time

    from django.db import IntegrityError

    user = User.objects.create_user(
        username="db_collide_user",
        email="abc123@privaterelay.appleid.com",
        password="pw",
    )
    identity = SocialIdentity.objects.create(
        provider="apple",
        subject="a_sub_db_collide",
        user=user,
        email_at_link="abc123@privaterelay.appleid.com",
        email_verified_at_link=True,
    )
    initial_last_used_at = identity.last_used_at
    time.sleep(0.01)  # auto_now resolution can collapse same-microsecond saves

    # Force the save to raise IntegrityError without seeding a second User
    # row — simulates "soft-deleted row hidden from the manager but still
    # holding the unique constraint." Patch the unbound `User.save` so the
    # call inside `_sync_user_email_from_provider` raises while leaving the
    # rest of the suite unaffected.
    original_save = User.save

    def fake_save(self, *args, **kwargs):
        if kwargs.get("update_fields") == ["email"]:
            raise IntegrityError("duplicate key violates unique constraint")
        return original_save(self, *args, **kwargs)

    monkeypatch.setattr(User, "save", fake_save)

    returned_user, returned_identity, created = SocialIdentityService().upsert_and_link(
        provider="apple",
        subject="a_sub_db_collide",
        email="real.user@example.com",
        email_verified=True,
        extra_claims={"is_private_email": False},
    )

    monkeypatch.setattr(User, "save", original_save)
    user.refresh_from_db()
    assert user.email == "abc123@privaterelay.appleid.com"

    # The post-sync `existing_identity.save(update_fields=["last_used_at"])`
    # inside `upsert_and_link` must still succeed after the swallowed
    # IntegrityError — that's what the savepoint protects.
    assert returned_user.id == user.id
    assert created is False
    returned_identity.refresh_from_db()
    assert returned_identity.last_used_at > initial_last_used_at


# ---------------------------------------------------------------------------
# Identity-completion helpers — exercised directly because they're the
# primary mechanism for keeping `is_verified` and `authentication_types`
# in sync across BlockUser-derived integrators.
# ---------------------------------------------------------------------------

from tests.models import (  # noqa: E402  (import at top of file would force Django app loading before pytest_configure)
    TestBlockUser,
)


def test_authentication_type_for_known_provider_returns_enum_value():
    assert SocialIdentityService._authentication_type_for("apple") == "APPLE"
    assert SocialIdentityService._authentication_type_for("google") == "GOOGLE"
    assert SocialIdentityService._authentication_type_for("facebook") == "FACEBOOK"
    assert SocialIdentityService._authentication_type_for("linkedin") == "LINKEDIN"


def test_authentication_type_for_unknown_provider_returns_none():
    """Unknown providers must NOT silently end up as free-form strings in
    `authentication_types` — the helper logs and returns None so the caller
    skips the seed."""
    assert SocialIdentityService._authentication_type_for("microsoft") is None


def test_build_create_user_kwargs_seeds_block_user_fields_when_present():
    """BlockUser-derived models receive `is_verified=True` and the provider's
    AuthenticationType in `authentication_types` baked into the initial
    create_user call — no second save needed."""
    kwargs = SocialIdentityService._build_create_user_kwargs(
        TestBlockUser,
        "real.user@example.com",
        provider="apple",
        email_verified=True,
    )

    assert kwargs["email"] == "real.user@example.com"
    assert kwargs["is_verified"] is True
    assert kwargs["authentication_types"] == ["APPLE"]


def test_build_create_user_kwargs_skips_seeds_for_models_without_those_fields():
    """auth.User has neither `is_verified` nor `authentication_types`. The
    helper must skip those seeds silently so the kwargs stay valid for
    `auth.User.objects.create_user(**kwargs)`."""
    kwargs = SocialIdentityService._build_create_user_kwargs(
        User,
        "x@example.com",
        provider="google",
        email_verified=True,
    )

    assert "is_verified" not in kwargs
    assert "authentication_types" not in kwargs
    assert kwargs["email"] == "x@example.com"


def test_build_create_user_kwargs_filters_extra_user_fields_to_model_schema():
    """`extra_user_fields` is filtered against the user model's declared
    fields and drops empty values. Keeps the call generic across schemas."""
    kwargs = SocialIdentityService._build_create_user_kwargs(
        User,
        "x@example.com",
        provider="google",
        email_verified=True,
        extra_user_fields={
            "first_name": "Alice",
            "last_name": "Smith",
            "wallet_address": "0xdeadbeef",  # not on auth.User
            "middle_name": "",  # empty -> dropped
        },
    )

    assert kwargs["first_name"] == "Alice"
    assert kwargs["last_name"] == "Smith"
    assert "wallet_address" not in kwargs
    assert "middle_name" not in kwargs


@pytest.mark.django_db
def test_apply_identity_completion_flips_is_verified_and_appends_auth_type():
    """First successful sign-in via a verified IdP brings the user up to
    `is_verified=True` and adds the provider's enum value to
    `authentication_types`. Returns True so callers can assert a write
    happened."""
    user = TestBlockUser.objects.create(
        email="completion@example.com",
        is_verified=False,
        authentication_types=[],
    )

    wrote = SocialIdentityService._apply_identity_completion(user=user, provider="apple", email_verified=True)

    assert wrote is True
    user.refresh_from_db()
    assert user.is_verified is True
    assert user.authentication_types == ["APPLE"]


@pytest.mark.django_db
def test_apply_identity_completion_is_idempotent_on_repeat_signin():
    """A second sign-in for the same provider produces no DB write — the
    enum value is already present and `is_verified` is already True."""
    user = TestBlockUser.objects.create(
        email="repeat@example.com",
        is_verified=True,
        authentication_types=["APPLE"],
    )

    wrote = SocialIdentityService._apply_identity_completion(user=user, provider="apple", email_verified=True)

    assert wrote is False


@pytest.mark.django_db
def test_apply_identity_completion_appends_second_provider_without_dropping_first():
    """A user who originally signed in via Google and now signs in via Apple
    should end up with both providers in `authentication_types`."""
    user = TestBlockUser.objects.create(
        email="multi@example.com",
        is_verified=True,
        authentication_types=["GOOGLE"],
    )

    SocialIdentityService._apply_identity_completion(user=user, provider="apple", email_verified=True)

    user.refresh_from_db()
    assert user.authentication_types == ["GOOGLE", "APPLE"]
