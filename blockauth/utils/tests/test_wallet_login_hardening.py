"""Tests for the upstream port's hardening items not exercised elsewhere.

Covers:

* #3 — startup validation for ``WALLET_LOGIN_EXPECTED_DOMAINS`` in non-DEBUG.
* #10 — throttle scoping per (IP, wallet_address, scope).
* #11 — ``prune_wallet_nonces`` management command.
"""

from __future__ import annotations

from datetime import timedelta
from io import StringIO

import pytest
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.utils import timezone

from blockauth.apps import validate_wallet_login_settings
from blockauth.models.wallet_login_nonce import WalletLoginNonce

# =============================================================================
# Hardening #3 — startup validation
# =============================================================================


class TestStartupValidation:
    def test_debug_true_is_permissive(self, settings):
        settings.DEBUG = True
        settings.WALLET_LOGIN_EXPECTED_DOMAINS = ()
        # Must not raise.
        validate_wallet_login_settings()

    def test_empty_allowlist_in_production_raises(self, settings):
        settings.DEBUG = False
        settings.WALLET_LOGIN_EXPECTED_DOMAINS = ()
        settings.WALLET_LOGIN_SKIP_STARTUP_VALIDATION = False
        with pytest.raises(ImproperlyConfigured, match="non-empty"):
            validate_wallet_login_settings()

    def test_production_with_allowlist_is_accepted(self, settings):
        settings.DEBUG = False
        settings.WALLET_LOGIN_EXPECTED_DOMAINS = ("app.example.com",)
        settings.WALLET_LOGIN_SKIP_STARTUP_VALIDATION = False
        validate_wallet_login_settings()

    def test_non_iterable_allowlist_raises(self, settings):
        settings.DEBUG = False
        settings.WALLET_LOGIN_EXPECTED_DOMAINS = "app.example.com"  # str, not tuple
        settings.WALLET_LOGIN_SKIP_STARTUP_VALIDATION = False
        with pytest.raises(ImproperlyConfigured, match="list, tuple or set"):
            validate_wallet_login_settings()

    def test_blank_entry_rejected(self, settings):
        settings.DEBUG = False
        settings.WALLET_LOGIN_EXPECTED_DOMAINS = ("app.example.com", "")
        settings.WALLET_LOGIN_SKIP_STARTUP_VALIDATION = False
        with pytest.raises(ImproperlyConfigured, match="invalid entries"):
            validate_wallet_login_settings()

    def test_skip_flag_bypasses_check(self, settings):
        settings.DEBUG = False
        settings.WALLET_LOGIN_EXPECTED_DOMAINS = ()
        settings.WALLET_LOGIN_SKIP_STARTUP_VALIDATION = True
        validate_wallet_login_settings()


# =============================================================================
# Hardening #10 — throttle scoping
# =============================================================================


class _FakeRequest:
    """Minimal stand-in for a DRF request used by the throttle."""

    def __init__(self, *, ip: str, address: str | None):
        self.META = {"REMOTE_ADDR": ip}
        self.data: dict = {}
        if address is not None:
            self.data["address"] = address


class TestWalletThrottleScoping:
    @pytest.fixture(autouse=True)
    def _clear_cache(self):
        cache.clear()
        yield
        cache.clear()

    def test_different_addresses_get_independent_buckets(self):
        from blockauth.utils.rate_limiter import WalletChallengeThrottle

        throttle = WalletChallengeThrottle(rate=(2, 60))
        req_a = _FakeRequest(ip="198.51.100.7", address="0x" + "a" * 40)
        req_b = _FakeRequest(ip="198.51.100.7", address="0x" + "b" * 40)

        assert throttle.allow_request(req_a, None) is True
        assert throttle.allow_request(req_a, None) is True
        # Address-A bucket is now full — next request for A is denied.
        assert throttle.allow_request(req_a, None) is False
        # Address-B on the same IP is still allowed.
        assert throttle.allow_request(req_b, None) is True

    def test_challenge_and_login_scopes_are_independent(self):
        from blockauth.utils.rate_limiter import (
            WalletChallengeThrottle,
            WalletLoginThrottle,
        )

        req = _FakeRequest(ip="198.51.100.7", address="0x" + "a" * 40)
        challenge = WalletChallengeThrottle(rate=(1, 60))
        login = WalletLoginThrottle(rate=(1, 60))

        assert challenge.allow_request(req, None) is True
        assert challenge.allow_request(req, None) is False
        # Login endpoint has its own bucket.
        assert login.allow_request(req, None) is True

    def test_rejects_when_address_missing_but_ip_present(self):
        """No address -> still gets a bucket keyed on IP + scope."""
        from blockauth.utils.rate_limiter import WalletLoginThrottle

        throttle = WalletLoginThrottle(rate=(1, 60))
        req = _FakeRequest(ip="198.51.100.7", address=None)
        assert throttle.allow_request(req, None) is True
        assert throttle.allow_request(req, None) is False


# =============================================================================
# Hardening #11 — reaper management command
# =============================================================================


@pytest.mark.django_db
class TestPruneWalletNonces:
    def _create(self, *, nonce, expires_at, consumed_at=None):
        now = timezone.now()
        return WalletLoginNonce.objects.create(
            address="0x" + "a" * 40,
            nonce=nonce,
            domain="example.com",
            uri="https://example.com/",
            chain_id=1,
            issued_at=now,
            expires_at=expires_at,
            consumed_at=consumed_at,
        )

    def test_removes_expired_rows(self):
        now = timezone.now()
        self._create(nonce="expired_" + "a" * 24, expires_at=now - timedelta(seconds=1))
        self._create(nonce="live_" + "b" * 28, expires_at=now + timedelta(minutes=5))

        out = StringIO()
        call_command("prune_wallet_nonces", stdout=out)
        remaining = list(WalletLoginNonce.objects.values_list("nonce", flat=True))
        assert len(remaining) == 1
        assert remaining[0].startswith("live_")
        assert "Deleted 1" in out.getvalue()

    def test_removes_old_consumed_rows(self):
        now = timezone.now()
        # Still in TTL but consumed long ago — should be reaped.
        self._create(
            nonce="consumed_old_" + "a" * 16,
            expires_at=now + timedelta(minutes=1),
            consumed_at=now - timedelta(hours=2),
        )
        # Consumed recently — keep (caller may want to inspect it).
        self._create(
            nonce="consumed_new_" + "b" * 16,
            expires_at=now + timedelta(minutes=1),
            consumed_at=now - timedelta(minutes=1),
        )

        call_command("prune_wallet_nonces", "--older-than", "3600", stdout=StringIO())
        remaining = list(WalletLoginNonce.objects.values_list("nonce", flat=True))
        assert len(remaining) == 1
        assert remaining[0].startswith("consumed_new_")

    def test_dry_run_does_not_delete(self):
        now = timezone.now()
        self._create(nonce="expired_" + "a" * 24, expires_at=now - timedelta(seconds=1))

        out = StringIO()
        call_command("prune_wallet_nonces", "--dry-run", stdout=out)
        assert WalletLoginNonce.objects.count() == 1
        assert "dry-run" in out.getvalue()
