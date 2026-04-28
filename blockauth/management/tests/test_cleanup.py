"""
Tests for the blockauth_cleanup management command.
"""

import secrets
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import connection
from django.utils import timezone

from blockauth.models.otp import OTP
from blockauth.passkey.models import PasskeyChallenge
from blockauth.totp.models import TOTPVerificationLog

User = get_user_model()


@pytest.fixture(scope="session")
def _create_tables(django_db_setup, django_db_blocker):
    """Create the blockauth tables that have no migrations."""
    with django_db_blocker.unblock():
        with connection.schema_editor() as schema_editor:
            for model in [OTP, PasskeyChallenge, TOTPVerificationLog]:
                try:
                    schema_editor.create_model(model)
                except Exception:
                    pass  # table already exists


@pytest.fixture(autouse=True)
def _use_tables(_create_tables):
    """Ensure tables exist for every test."""


def _run_command(*args):
    """Run blockauth_cleanup and return stdout."""
    out = StringIO()
    call_command("blockauth_cleanup", *args, stdout=out)
    return out.getvalue()


def _create_otp(is_used=False, created_at=None):
    otp = OTP.objects.create(
        identifier="test@example.com",
        code="ABC123",
        is_used=is_used,
        subject="login",
    )
    if created_at is not None:
        OTP.objects.filter(pk=otp.pk).update(created_at=created_at)
    return otp


def _create_challenge(expires_at=None, is_used=False):
    return PasskeyChallenge.objects.create(
        challenge=secrets.token_urlsafe(32),
        challenge_type="registration",
        expires_at=expires_at or (timezone.now() + timedelta(minutes=5)),
        is_used=is_used,
    )


def _create_totp_log(created_at=None):
    user, _ = User.objects.get_or_create(
        username="totp_test_user",
        defaults={"email": "totp@example.com"},
    )
    log = TOTPVerificationLog.objects.create(
        user=user,
        success=True,
        verification_type="totp",
    )
    if created_at is not None:
        TOTPVerificationLog.objects.filter(pk=log.pk).update(created_at=created_at)
    return log


# ---------------------------------------------------------------
# OTP cleanup tests
# ---------------------------------------------------------------
@pytest.mark.django_db(transaction=True)
class TestOTPCleanup:
    def test_deletes_used_otp(self):
        _create_otp(is_used=True)
        _create_otp(is_used=False)  # fresh, should survive

        output = _run_command()
        assert "1 OTP" in output
        assert OTP.objects.count() == 1

    def test_deletes_expired_otp(self):
        now = timezone.now()
        _create_otp(created_at=now - timedelta(hours=25))
        _create_otp()  # fresh

        output = _run_command()
        assert "1 OTP" in output
        assert OTP.objects.count() == 1

    def test_keeps_fresh_unused_otp(self):
        _create_otp(is_used=False)

        output = _run_command()
        assert "0 OTP" in output
        assert OTP.objects.count() == 1

    def test_custom_retention(self):
        now = timezone.now()
        _create_otp(created_at=now - timedelta(hours=2))

        # Default 24h retention: should survive
        output = _run_command()
        assert "0 OTP" in output

        # With 1h retention: should be deleted
        with patch(
            "blockauth.management.commands.blockauth_cleanup._get_retention",
            side_effect=lambda key, default: 1 if key == "CLEANUP_OTP_RETENTION_HOURS" else default,
        ):
            output = _run_command()
            assert "1 OTP" in output


# ---------------------------------------------------------------
# PasskeyChallenge cleanup tests
# ---------------------------------------------------------------
@pytest.mark.django_db(transaction=True)
class TestChallengeCleanup:
    def test_deletes_expired_challenge(self):
        now = timezone.now()
        _create_challenge(expires_at=now - timedelta(minutes=10))
        _create_challenge()  # active

        output = _run_command()
        assert "1 challenges" in output
        assert PasskeyChallenge.objects.count() == 1

    def test_deletes_used_challenge(self):
        _create_challenge(is_used=True)

        output = _run_command()
        assert "1 challenges" in output
        assert PasskeyChallenge.objects.count() == 0

    def test_keeps_active_challenge(self):
        _create_challenge()

        output = _run_command()
        assert "0 challenges" in output
        assert PasskeyChallenge.objects.count() == 1


# ---------------------------------------------------------------
# TOTPVerificationLog cleanup tests
# ---------------------------------------------------------------
@pytest.mark.django_db(transaction=True)
class TestTOTPLogCleanup:
    def test_deletes_old_logs(self):
        now = timezone.now()
        _create_totp_log(created_at=now - timedelta(days=31))
        _create_totp_log()

        output = _run_command()
        assert "1 TOTP logs" in output
        assert TOTPVerificationLog.objects.count() == 1

    def test_keeps_recent_logs(self):
        now = timezone.now()
        _create_totp_log(created_at=now - timedelta(days=29))

        output = _run_command()
        assert "0 TOTP logs" in output
        assert TOTPVerificationLog.objects.count() == 1


# ---------------------------------------------------------------
# Dry-run tests
# ---------------------------------------------------------------
@pytest.mark.django_db(transaction=True)
class TestDryRun:
    def test_dry_run_does_not_delete(self):
        now = timezone.now()
        _create_otp(is_used=True)
        _create_challenge(is_used=True)
        _create_totp_log(created_at=now - timedelta(days=31))

        output = _run_command("--dry-run")
        assert "[dry-run]" in output
        assert "1 OTP" in output
        assert "1 challenges" in output
        assert "1 TOTP logs" in output

        # Nothing deleted
        assert OTP.objects.count() == 1
        assert PasskeyChallenge.objects.count() == 1
        assert TOTPVerificationLog.objects.count() == 1


# ---------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------
@pytest.mark.django_db(transaction=True)
class TestIdempotency:
    def test_running_twice_is_safe(self):
        _create_otp(is_used=True)

        _run_command()
        output = _run_command()
        assert "0 OTP" in output


# ---------------------------------------------------------------
# Empty database
# ---------------------------------------------------------------
@pytest.mark.django_db(transaction=True)
class TestEmptyDatabase:
    def test_no_records(self):
        output = _run_command()
        assert "0 OTP" in output
        assert "0 challenges" in output
        assert "0 TOTP logs" in output
        assert "(0 total)" in output
