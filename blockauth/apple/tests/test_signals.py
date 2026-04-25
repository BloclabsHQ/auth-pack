"""pre_delete signal: when a User is deleted, every Apple SocialIdentity
attached to it must trigger a revocation call before the cascade removes the
SocialIdentity rows.
"""

import base64
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings

from blockauth.social.models import SocialIdentity
from blockauth.social.service import SocialIdentityService

User = get_user_model()


@pytest.mark.django_db
def test_user_delete_revokes_each_apple_identity(aes_key):
    with override_settings(
        BLOCK_AUTH_SETTINGS={"SOCIAL_IDENTITY_ENCRYPTION_KEY": base64.b64encode(aes_key).decode()}
    ):
        user = User.objects.create_user(username="apple_user", email="apple-user@example.com", password="pw")
        service = SocialIdentityService()
        # Create the apple identities directly attached to the user, not via
        # upsert_and_link's create-new-user path.
        SocialIdentity.objects.create(
            provider="apple",
            subject="a_sub_1",
            user=user,
            email_at_link=None,
            email_verified_at_link=False,
            encrypted_refresh_token=service._encryptor.encrypt("refresh-1", b"social_identity:apple:a_sub_1"),
        )
        SocialIdentity.objects.create(
            provider="apple",
            subject="a_sub_2",
            user=user,
            email_at_link=None,
            email_verified_at_link=False,
            encrypted_refresh_token=service._encryptor.encrypt("refresh-2", b"social_identity:apple:a_sub_2"),
        )

        with patch("blockauth.apple.signals.AppleRevocationClient.revoke") as mock_revoke:
            user.delete()

        revoked_tokens = sorted([call.args[0] for call in mock_revoke.call_args_list])
        assert revoked_tokens == ["refresh-1", "refresh-2"]


@pytest.mark.django_db
def test_user_delete_skips_non_apple_identities(aes_key):
    with override_settings(
        BLOCK_AUTH_SETTINGS={"SOCIAL_IDENTITY_ENCRYPTION_KEY": base64.b64encode(aes_key).decode()}
    ):
        user = User.objects.create_user(username="google_user", email="google-user@gmail.com", password="pw")
        SocialIdentity.objects.create(
            provider="google",
            subject="g_sub_1",
            user=user,
            email_at_link="google-user@gmail.com",
            email_verified_at_link=True,
        )

        with patch("blockauth.apple.signals.AppleRevocationClient.revoke") as mock_revoke:
            user.delete()

        assert mock_revoke.call_count == 0


@pytest.mark.django_db
def test_user_delete_continues_when_one_identity_decrypt_fails(aes_key):
    """Corrupt ciphertext on one identity must not block revocation of others.

    Pins the InvalidTag/ValueError catch path in signals.py — without it,
    a key-rotation incident leaving one row's ciphertext invalid would
    halt the whole revocation loop and leak refresh tokens for all
    later identities."""
    with override_settings(
        BLOCK_AUTH_SETTINGS={"SOCIAL_IDENTITY_ENCRYPTION_KEY": base64.b64encode(aes_key).decode()}
    ):
        user = User.objects.create_user(username="mixed_user", email="mixed@example.com", password="pw")
        service = SocialIdentityService()
        # First identity: ciphertext deliberately corrupted.
        SocialIdentity.objects.create(
            provider="apple",
            subject="a_corrupt",
            user=user,
            email_at_link=None,
            email_verified_at_link=False,
            encrypted_refresh_token=b"\x00" * 64,  # garbage; auth tag will fail
        )
        # Second identity: valid ciphertext, must still get revoked.
        SocialIdentity.objects.create(
            provider="apple",
            subject="a_valid",
            user=user,
            email_at_link=None,
            email_verified_at_link=False,
            encrypted_refresh_token=service._encryptor.encrypt("good-refresh", b"social_identity:apple:a_valid"),
        )

        with patch("blockauth.apple.signals.AppleRevocationClient.revoke") as mock_revoke:
            user.delete()  # must succeed despite corrupted blob

        revoked_tokens = [call.args[0] for call in mock_revoke.call_args_list]
        assert revoked_tokens == ["good-refresh"]


@pytest.mark.django_db
def test_user_delete_skips_identity_without_refresh_token(aes_key):
    """An identity without an encrypted_refresh_token must be silently skipped."""
    with override_settings(
        BLOCK_AUTH_SETTINGS={"SOCIAL_IDENTITY_ENCRYPTION_KEY": base64.b64encode(aes_key).decode()}
    ):
        user = User.objects.create_user(username="no_token_user", email="notoken@example.com", password="pw")
        SocialIdentity.objects.create(
            provider="apple",
            subject="a_no_token",
            user=user,
            email_at_link=None,
            email_verified_at_link=False,
            encrypted_refresh_token=None,
        )

        with patch("blockauth.apple.signals.AppleRevocationClient.revoke") as mock_revoke:
            user.delete()

        assert mock_revoke.call_count == 0
