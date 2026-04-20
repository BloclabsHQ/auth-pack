"""Tests for ``blockauth.observability`` and the wallet-login emission points (#118).

Split into three concerns:

1. The callback-resolution contract — missing setting, bad dotted path,
   non-callable target all fall back to the no-op. A raising callback is
   caught and does not fail the caller.

2. Each of the five wallet-login events fires from the expected site
   with the expected tags. We register an in-memory callback via
   ``override_settings`` and capture events, then drive real HTTP
   requests / service calls / the management command.

3. Latency emission covers both success and failure outcomes so a
   consumer's histogram doesn't miss rejections.
"""

from __future__ import annotations

from datetime import timedelta
from io import StringIO
from typing import Any, Dict, List, Optional

import pytest
from django.core.cache import cache
from django.core.management import call_command
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone as django_timezone
from eth_account import Account
from eth_account.messages import encode_defunct
from rest_framework.test import APIClient

from blockauth import observability
from blockauth.models.wallet_login_nonce import WalletLoginNonce
from blockauth.services.wallet_login_service import reset_wallet_login_service
from blockauth.utils.siwe import build_siwe_message

_TEST_PRIVATE_KEY = "0x" + "1" * 64
_TEST_ACCOUNT = Account.from_key(_TEST_PRIVATE_KEY)
_TEST_ADDRESS = _TEST_ACCOUNT.address
_TEST_ADDRESS_LC = _TEST_ADDRESS.lower()


# =============================================================================
# Capture helper
# =============================================================================

#: Module-level recorder so ``override_settings`` can reach it by dotted
#: path. Each test clears it in the fixture below.
_events: List[Dict[str, Any]] = []


def _record(event, tags=None, *, duration_s=None, count=1):
    _events.append(
        {"event": event, "tags": tags or {}, "duration_s": duration_s, "count": count},
    )


def _record_raising(event, tags=None, *, duration_s=None, count=1):
    raise RuntimeError("metrics callback blew up")


_NOT_CALLABLE = "not a callable"


@pytest.fixture(autouse=True)
def _reset_observability():
    _events.clear()
    observability.reset_callback_cache()
    yield
    _events.clear()
    observability.reset_callback_cache()


@pytest.fixture(autouse=True)
def _override_wallet_login_settings(settings):
    settings.WALLET_LOGIN_EXPECTED_DOMAINS = ("example.com",)
    settings.WALLET_LOGIN_DEFAULT_CHAIN_ID = 1
    settings.WALLET_LOGIN_NONCE_TTL_SECONDS = 300
    reset_wallet_login_service()
    yield
    reset_wallet_login_service()


@pytest.fixture(autouse=True)
def _clear_cache_between_tests():
    cache.clear()
    yield
    cache.clear()


def _sign(message: str) -> str:
    signed = _TEST_ACCOUNT.sign_message(encode_defunct(text=message))
    sig_hex = signed.signature.hex()
    return sig_hex if sig_hex.startswith("0x") else "0x" + sig_hex


def _find(event: str) -> Optional[Dict[str, Any]]:
    for entry in _events:
        if entry["event"] == event:
            return entry
    return None


# =============================================================================
# Callback resolution contract
# =============================================================================


class TestCallbackResolution:
    def test_missing_setting_is_noop(self):
        # No METRICS_CALLBACK set — the autouse fixture clears
        # BLOCK_AUTH_SETTINGS between tests, so this emit must simply
        # succeed without raising and without side effects.
        observability.emit("wallet_login.success", {"flow": "siwe"})
        assert _events == []

    @override_settings(BLOCK_AUTH_SETTINGS={"METRICS_CALLBACK": "does.not.exist.callable"})
    def test_unimportable_callback_falls_back_to_noop(self, caplog):
        # First call logs and caches the no-op.
        observability.emit("wallet_login.success", {"flow": "siwe"})
        assert _events == []
        assert any("could not be imported" in rec.getMessage() for rec in caplog.records)

    @override_settings(
        BLOCK_AUTH_SETTINGS={
            "METRICS_CALLBACK": "blockauth.utils.tests.test_observability._NOT_CALLABLE",
        }
    )
    def test_non_callable_target_falls_back_to_noop(self, caplog):
        observability.emit("wallet_login.success", {"flow": "siwe"})
        assert _events == []
        assert any("non-callable" in rec.getMessage() for rec in caplog.records)

    @override_settings(
        BLOCK_AUTH_SETTINGS={
            "METRICS_CALLBACK": "blockauth.utils.tests.test_observability._record_raising",
        }
    )
    def test_callback_exception_is_swallowed(self, caplog):
        # A broken metrics pipe must never fail the caller. The emit
        # returns normally; the exception is logged.
        observability.emit("wallet_login.success", {"flow": "siwe"})
        assert any("METRICS_CALLBACK raised" in rec.getMessage() for rec in caplog.records)

    @override_settings(
        BLOCK_AUTH_SETTINGS={
            "METRICS_CALLBACK": "blockauth.utils.tests.test_observability._record",
        }
    )
    def test_setting_change_invalidates_cache(self):
        # Resolve once under the record callback.
        observability.emit("wallet_login.success", {"flow": "siwe"})
        assert len(_events) == 1

        # Flip to a different callback via override_settings. The
        # setting_changed signal clears the cache, so the next emit
        # resolves afresh.
        with override_settings(BLOCK_AUTH_SETTINGS={"METRICS_CALLBACK": None}):
            observability.emit("wallet_login.success", {"flow": "siwe"})
            # No new entry — callback resolved to no-op this time.
            assert len(_events) == 1


# =============================================================================
# Wallet-login emission sites
# =============================================================================


@pytest.fixture
def _record_callback(settings):
    settings.BLOCK_AUTH_SETTINGS = {
        "METRICS_CALLBACK": "blockauth.utils.tests.test_observability._record",
    }
    observability.reset_callback_cache()
    yield
    observability.reset_callback_cache()


@pytest.mark.django_db
@pytest.mark.usefixtures("_record_callback")
class TestWalletLoginEmissions:
    def _challenge_then_login(self, client):
        challenge = client.post(
            reverse("wallet-login-challenge"),
            {"address": _TEST_ADDRESS_LC},
            format="json",
        )
        assert challenge.status_code == 200, challenge.content
        message = challenge.json()["message"]
        return client.post(
            reverse("wallet-login"),
            {
                "wallet_address": _TEST_ADDRESS_LC,
                "message": message,
                "signature": _sign(message),
            },
            format="json",
        )

    def test_challenge_issued_fires_on_success(self):
        client = APIClient()
        resp = client.post(
            reverse("wallet-login-challenge"),
            {"address": _TEST_ADDRESS_LC},
            format="json",
        )
        assert resp.status_code == 200
        assert _find("wallet_login.challenge_issued") is not None

    def test_success_fires_with_siwe_flow_tag(self):
        client = APIClient()
        resp = self._challenge_then_login(client)
        assert resp.status_code == 200, resp.content

        success = _find("wallet_login.success")
        assert success is not None
        assert success["tags"] == {"flow": "siwe"}

    def test_failure_fires_with_service_error_code(self):
        client = APIClient()
        issued = django_timezone.now()
        rogue = build_siwe_message(
            domain="phisher.example",
            address=_TEST_ADDRESS,
            uri="https://phisher.example/",
            chain_id=1,
            nonce="abcdef1234567890abcdef1234567890",
            issued_at=issued,
            expiration_time=issued + timedelta(minutes=5),
        )
        resp = client.post(
            reverse("wallet-login"),
            {
                "wallet_address": _TEST_ADDRESS_LC,
                "message": rogue,
                "signature": _sign(rogue),
            },
            format="json",
        )
        assert resp.status_code == 401
        failure = _find("wallet_login.failure")
        assert failure is not None
        assert failure["tags"] == {"code": "domain_mismatch"}

    def test_failure_fires_with_validation_error_code(self):
        """Serializer-level validation failures get a distinct code so
        Grafana can keep "malformed request" separate from
        service-layer rejections.
        """
        client = APIClient()
        # Missing ``signature`` field triggers the DRF validation path
        # before the service layer ever sees the request.
        resp = client.post(
            reverse("wallet-login"),
            {"wallet_address": _TEST_ADDRESS_LC, "message": "x"},
            format="json",
        )
        assert resp.status_code == 400
        failure = _find("wallet_login.failure")
        assert failure is not None
        assert failure["tags"] == {"code": "validation_error"}

    def test_latency_fires_on_success_path(self):
        client = APIClient()
        resp = self._challenge_then_login(client)
        assert resp.status_code == 200, resp.content
        latency = _find("wallet_login.latency")
        assert latency is not None
        assert latency["tags"] == {"outcome": "success"}
        assert latency["duration_s"] is not None
        assert latency["duration_s"] >= 0.0

    def test_latency_fires_on_failure_path(self):
        """A rejected login must still produce a latency sample so
        slow-failure trends are visible. Regression guard: moving the
        emit out of the ``finally`` would silently drop failure
        latency.
        """
        client = APIClient()
        resp = client.post(
            reverse("wallet-login"),
            {"wallet_address": _TEST_ADDRESS_LC, "message": "x"},
            format="json",
        )
        assert resp.status_code == 400
        latency = _find("wallet_login.latency")
        assert latency is not None
        assert latency["tags"] == {"outcome": "failure"}


# =============================================================================
# Management command emission
# =============================================================================


@pytest.mark.django_db
@pytest.mark.usefixtures("_record_callback")
class TestPruneNonceEmission:
    def test_pruned_event_carries_deleted_count(self):
        now = django_timezone.now()
        # Three expired rows, all will be reaped in a single batch.
        for idx in range(3):
            WalletLoginNonce.objects.create(
                address="0x" + "a" * 40,
                nonce=f"exp{idx:03d}" + "0" * 26,
                domain="example.com",
                uri="https://example.com/",
                chain_id=1,
                issued_at=now,
                expires_at=now - timedelta(seconds=1),
            )
        call_command("prune_wallet_nonces", stdout=StringIO())

        pruned = _find("wallet_nonce.pruned")
        assert pruned is not None
        assert pruned["count"] == 3

    def test_pruned_event_not_fired_when_nothing_to_delete(self):
        call_command("prune_wallet_nonces", stdout=StringIO())
        assert _find("wallet_nonce.pruned") is None

    def test_dry_run_does_not_emit(self):
        now = django_timezone.now()
        WalletLoginNonce.objects.create(
            address="0x" + "a" * 40,
            nonce="expired" + "0" * 25,
            domain="example.com",
            uri="https://example.com/",
            chain_id=1,
            issued_at=now,
            expires_at=now - timedelta(seconds=1),
        )
        call_command("prune_wallet_nonces", "--dry-run", stdout=StringIO())
        assert _find("wallet_nonce.pruned") is None
