"""
Django ORM storage tests for TOTP 2FA.

Exercises ``DjangoTOTP2FAStore`` directly against the database (the service
suite covers ``TOTPService`` against an in-memory mock). Focuses on the
re-creation contract: which existing rows block ``create`` and which are
safely replaced.

Uses Django's ``get_user_model()`` (which resolves to the test environment's
``auth.User``) — matching ``social/tests/`` and the ``settings.AUTH_USER_MODEL``
FK on ``TOTP2FA``.
"""

import pytest
from django.contrib.auth import get_user_model

from blockauth.totp.constants import TOTPStatus
from blockauth.totp.exceptions import TOTPAlreadyEnabledError
from blockauth.totp.models import TOTP2FA
from blockauth.totp.services.encryption import FernetSecretEncryption
from blockauth.totp.services.totp_service import TOTPService
from blockauth.totp.storage.django_storage import DjangoTOTP2FAStore

User = get_user_model()


def _make_user(username: str = "totp_user") -> "User":
    return User.objects.create_user(username=username, email=f"{username}@example.com", password="pw")


# =============================================================================
# Store.create re-creation contract
# =============================================================================


@pytest.mark.django_db
def test_create_replaces_unconfirmed_pending_row():
    """An unconfirmed PENDING_CONFIRMATION row is resumable: a second create
    overwrites it (fresh secret) instead of raising."""
    store = DjangoTOTP2FAStore()
    user = _make_user()
    uid = str(user.pk)

    store.create(user_id=uid, encrypted_secret="enc:first", status=TOTPStatus.PENDING_CONFIRMATION.value)

    # Setup started but never confirmed → starting over must succeed.
    data = store.create(user_id=uid, encrypted_secret="enc:second", status=TOTPStatus.PENDING_CONFIRMATION.value)

    assert data.status == TOTPStatus.PENDING_CONFIRMATION.value
    assert data.encrypted_secret == "enc:second"
    # The stale row is replaced, not duplicated (user FK is OneToOne).
    assert TOTP2FA.objects.filter(user_id=user.pk).count() == 1


@pytest.mark.django_db
def test_create_replaces_disabled_row():
    """A DISABLED row is replaced on create (re-enrollment after disable)."""
    store = DjangoTOTP2FAStore()
    user = _make_user()
    uid = str(user.pk)

    store.create(user_id=uid, encrypted_secret="enc:first", status=TOTPStatus.PENDING_CONFIRMATION.value)
    store.update_status(uid, TOTPStatus.DISABLED.value)

    data = store.create(user_id=uid, encrypted_secret="enc:second", status=TOTPStatus.PENDING_CONFIRMATION.value)

    assert data.encrypted_secret == "enc:second"
    assert TOTP2FA.objects.filter(user_id=user.pk).count() == 1


@pytest.mark.django_db
def test_create_rejects_enabled_row():
    """A genuinely ENABLED device still blocks create with a 409-mapped error."""
    store = DjangoTOTP2FAStore()
    user = _make_user()
    uid = str(user.pk)

    store.create(user_id=uid, encrypted_secret="enc:first", status=TOTPStatus.PENDING_CONFIRMATION.value)
    store.update_status(uid, TOTPStatus.ENABLED.value)

    with pytest.raises(TOTPAlreadyEnabledError):
        store.create(user_id=uid, encrypted_secret="enc:second", status=TOTPStatus.PENDING_CONFIRMATION.value)

    # The enabled row is untouched.
    assert store.get_by_user_id(uid).encrypted_secret == "enc:first"


# =============================================================================
# Service + Django store integration (the reported repro)
# =============================================================================


def _service() -> TOTPService:
    return TOTPService(
        store=DjangoTOTP2FAStore(),
        encryption_service=FernetSecretEncryption(master_key="test-master-key-12345"),
    )


@pytest.mark.django_db
def test_setup_totp_resumes_unconfirmed_enrollment():
    """setup_totp() over an unconfirmed enrollment regenerates the secret and
    stays pending, rather than dead-ending on TOTPAlreadyEnabledError."""
    service = _service()
    user = _make_user()
    uid = str(user.pk)

    first = service.setup_totp(user_id=uid, account_name="totp_user@example.com")
    second = service.setup_totp(user_id=uid, account_name="totp_user@example.com")

    assert second.secret != first.secret
    # The abandoned enrollment's backup codes are invalidated and a fresh set is
    # issued — the row is deleted and repopulated, not merged.
    assert set(second.backup_codes) != set(first.backup_codes)
    assert service.get_backup_codes_remaining(uid) == service.config.backup_codes_count
    assert service.get_status(uid) == TOTPStatus.PENDING_CONFIRMATION.value

    # The persisted secret is the new one, so confirmation must use it.
    code = TOTPService.generate_totp(second.secret)[0]
    assert service.confirm_setup(uid, code) is True
    assert service.get_status(uid) == TOTPStatus.ENABLED.value


@pytest.mark.django_db
def test_setup_totp_still_blocks_enabled_device():
    """Once confirmed/enabled, setup_totp() raises — the 409 path is preserved."""
    service = _service()
    user = _make_user()
    uid = str(user.pk)

    result = service.setup_totp(user_id=uid, account_name="totp_user@example.com")
    service.confirm_setup(uid, TOTPService.generate_totp(result.secret)[0])

    with pytest.raises(TOTPAlreadyEnabledError):
        service.setup_totp(user_id=uid, account_name="totp_user@example.com")
