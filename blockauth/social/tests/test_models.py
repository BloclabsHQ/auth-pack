"""SocialIdentity model behaviour: uniqueness, FK cascade, indexes, encryption blob storage.

Uses Django's `get_user_model()` (which resolves to the test environment's
`auth.User`) — matches the pattern used by `passkey/tests/` and `totp/tests/`
in this codebase, which also reference `settings.AUTH_USER_MODEL` for the
user FK in their models.
"""

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError

from blockauth.social.models import SocialIdentity

User = get_user_model()


@pytest.mark.django_db
def test_provider_subject_uniqueness():
    user_a = User.objects.create_user(username="user_a", email="a@example.com", password="pw")
    user_b = User.objects.create_user(username="user_b", email="b@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="google", subject="g_sub_1", user=user_a, email_at_link="a@example.com", email_verified_at_link=True
    )
    with pytest.raises(IntegrityError):
        SocialIdentity.objects.create(
            provider="google",
            subject="g_sub_1",
            user=user_b,
            email_at_link="b@example.com",
            email_verified_at_link=True,
        )


@pytest.mark.django_db
def test_user_cascade_deletes_identities():
    user = User.objects.create_user(username="user_c", email="c@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple", subject="a_sub_1", user=user, email_at_link="c@example.com", email_verified_at_link=False
    )
    user.delete()
    assert SocialIdentity.objects.count() == 0


@pytest.mark.django_db
def test_encrypted_refresh_token_is_bytes():
    user = User.objects.create_user(username="user_d", email="d@example.com", password="pw")
    blob = b"\x00\x01\x02test-bytes"
    identity = SocialIdentity.objects.create(
        provider="apple",
        subject="a_sub_2",
        user=user,
        email_at_link="d@example.com",
        email_verified_at_link=True,
        encrypted_refresh_token=blob,
    )
    identity.refresh_from_db()
    assert bytes(identity.encrypted_refresh_token) == blob


@pytest.mark.django_db
def test_one_user_can_have_multiple_providers():
    user = User.objects.create_user(username="user_e", email="e@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="google", subject="g1", user=user, email_at_link="e@example.com", email_verified_at_link=True
    )
    SocialIdentity.objects.create(
        provider="linkedin", subject="l1", user=user, email_at_link="e@example.com", email_verified_at_link=True
    )
    SocialIdentity.objects.create(
        provider="apple", subject="a1", user=user, email_at_link="e@example.com", email_verified_at_link=False
    )
    assert user.social_identities.count() == 3


@pytest.mark.django_db
def test_email_verified_at_link_false_is_storable():
    """Apple's email is user-supplied and never authoritative — `False` must be a valid value."""
    user = User.objects.create_user(username="user_f", email="f@example.com", password="pw")
    identity = SocialIdentity.objects.create(
        provider="apple",
        subject="a_sub_3",
        user=user,
        email_at_link="f@example.com",
        email_verified_at_link=False,
    )
    identity.refresh_from_db()
    assert identity.email_verified_at_link is False


@pytest.mark.django_db
def test_email_verified_at_link_required():
    """Field is non-nullable with no default — omission must fail at the DB constraint."""
    user = User.objects.create_user(username="user_g", email="g@example.com", password="pw")
    with pytest.raises(IntegrityError):
        SocialIdentity.objects.create(
            provider="google",
            subject="g_sub_2",
            user=user,
            email_at_link="g@example.com",
            # email_verified_at_link intentionally omitted
        )


@pytest.mark.django_db
def test_last_used_at_updates_on_save():
    """auto_now=True must bump last_used_at on every save so SocialIdentityService.upsert
    can use the column to track recent activity."""
    import time

    user = User.objects.create_user(username="user_h", email="h@example.com", password="pw")
    identity = SocialIdentity.objects.create(
        provider="linkedin",
        subject="l_sub_1",
        user=user,
        email_at_link="h@example.com",
        email_verified_at_link=True,
    )
    initial_last_used_at = identity.last_used_at
    time.sleep(0.01)  # auto_now resolution can collapse same-microsecond saves
    identity.email_at_link = "h_new@example.com"
    identity.save()
    identity.refresh_from_db()
    assert identity.last_used_at > initial_last_used_at


def test_social_identity_table_name_is_package_scoped():
    assert SocialIdentity._meta.db_table == "blockauth_social_identity"
