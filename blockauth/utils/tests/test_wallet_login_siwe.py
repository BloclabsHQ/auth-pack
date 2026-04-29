"""Tests for the SIWE-backed wallet login flow (issue #90).

Covers:

* Service-layer signature verification + malleability rejection.
* Service-layer nonce lifecycle (replay, chain mismatch, address mismatch,
  forged domain, unknown nonce, not-before).
* HTTP endpoint round-trip (challenge -> sign -> login -> replay-rejected).
* Hardening item #4 — ``WALLET_LOGIN_AUTO_CREATE=False`` no longer acts as
  a registration oracle by default.

The tests reuse a single deterministic test account so any stored
signatures match the expected signer. The private key is fixed test junk
and must never hit a real network.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

import pytest
from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone as django_timezone
from eth_account import Account
from eth_account.messages import encode_defunct
from rest_framework import status
from rest_framework.test import APIClient

from blockauth.models.wallet_login_nonce import WalletLoginNonce
from blockauth.services.wallet_login_service import (
    _SECP256K1_N,
    WalletLoginError,
    WalletLoginService,
    reset_wallet_login_service,
)
from blockauth.utils.siwe import build_siwe_message
from blockauth.utils.tests.credential_leak import assert_no_credential_leak

# Deterministic test wallet — not a real account.
_TEST_PRIVATE_KEY = "0x" + "1" * 64
_TEST_ACCOUNT = Account.from_key(_TEST_PRIVATE_KEY)
_TEST_ADDRESS = _TEST_ACCOUNT.address  # EIP-55 checksummed
_TEST_ADDRESS_LC = _TEST_ADDRESS.lower()


def _sign(message: str) -> str:
    """Return a 0x-prefixed 65-byte signature from the fixed test key."""
    signed = _TEST_ACCOUNT.sign_message(encode_defunct(text=message))
    sig_hex = signed.signature.hex()
    return sig_hex if sig_hex.startswith("0x") else "0x" + sig_hex


def _perform_wallet_login(client, address):
    """Run the full challenge -> sign -> login round-trip and return the response.

    Factored out of the individual tests so the identical 15-line
    boilerplate (POST challenge, read message, sign, POST login) lives
    in one place. The issue #99 tests (credential leak + null email)
    and any future endpoint-level test should reuse this helper rather
    than duplicating the sequence.
    """
    challenge_resp = client.post(
        reverse("wallet-login-challenge"),
        {"address": address},
        format="json",
    )
    assert challenge_resp.status_code == 200, challenge_resp.content
    message = challenge_resp.json()["message"]
    signature = _sign(message)
    return client.post(
        reverse("wallet-login"),
        {
            "wallet_address": address,
            "message": message,
            "signature": signature,
        },
        format="json",
    )


@pytest.fixture(autouse=True)
def _override_domains(settings):
    """Apply the SIWE allow-list for every test in this module."""
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


@pytest.fixture
def svc():
    return WalletLoginService(expected_domains=("example.com",), default_chain_id=1)


@pytest.fixture
def siwe_and_sig():
    """Build a valid SIWE plaintext + matching signature for the test wallet."""
    issued = django_timezone.now().replace(microsecond=0)
    msg = build_siwe_message(
        domain="example.com",
        address=_TEST_ADDRESS,
        uri="https://example.com/",
        chain_id=1,
        nonce="abcdef1234567890abcdef1234567890",
        issued_at=issued,
        expiration_time=issued + timedelta(minutes=5),
    )
    return msg, _sign(msg), issued


# =============================================================================
# Service layer — signature verification & malleability
# =============================================================================


class TestSignatureVerify:
    def test_happy_path(self, svc, siwe_and_sig):
        message, sig, _ = siwe_and_sig
        svc._verify_signature(address=_TEST_ADDRESS_LC, message=message, signature=sig)

    def test_rejects_bad_length(self, svc, siwe_and_sig):
        message, _sig, _ = siwe_and_sig
        with pytest.raises(WalletLoginError) as exc_info:
            svc._verify_signature(address=_TEST_ADDRESS_LC, message=message, signature="0x1234")
        assert exc_info.value.code == "invalid_signature"

    def test_rejects_non_hex(self, svc, siwe_and_sig):
        message, _sig, _ = siwe_and_sig
        with pytest.raises(WalletLoginError) as exc_info:
            svc._verify_signature(
                address=_TEST_ADDRESS_LC,
                message=message,
                signature="0x" + "z" * 130,
            )
        assert exc_info.value.code == "invalid_signature"

    def test_rejects_malleable_high_s(self, svc, siwe_and_sig):
        message, sig, _ = siwe_and_sig
        sig_bytes = bytes.fromhex(sig[2:])
        r = int.from_bytes(sig_bytes[0:32], "big")
        s = int.from_bytes(sig_bytes[32:64], "big")
        v = sig_bytes[64]
        mal_s = _SECP256K1_N - s
        new_v = 27 + ((v - 27) ^ 1) if v in (27, 28) else (v ^ 1)
        mal_bytes = r.to_bytes(32, "big") + mal_s.to_bytes(32, "big") + bytes([new_v])
        with pytest.raises(WalletLoginError) as exc_info:
            svc._verify_signature(
                address=_TEST_ADDRESS_LC,
                message=message,
                signature="0x" + mal_bytes.hex(),
            )
        assert exc_info.value.code == "malleable_signature"

    def test_rejects_wrong_address(self, svc, siwe_and_sig):
        message, sig, _ = siwe_and_sig
        with pytest.raises(WalletLoginError) as exc_info:
            svc._verify_signature(address="0x" + "0" * 40, message=message, signature=sig)
        assert exc_info.value.code == "signature_mismatch"

    def test_library_regression_surfaces_as_internal_error(self, svc, siwe_and_sig):
        """Hardening #5 — unexpected exceptions must NOT look like bad input."""
        message, sig, _ = siwe_and_sig

        class _Boom(RuntimeError):
            pass

        with patch.object(svc._w3.eth.account, "recover_message", side_effect=_Boom("boom")):
            with pytest.raises(WalletLoginError) as exc_info:
                svc._verify_signature(address=_TEST_ADDRESS_LC, message=message, signature=sig)
        assert exc_info.value.code == "signature_internal_error"

    def test_eth_keys_validation_error_surfaces_as_internal_error(self, svc, siwe_and_sig):
        """Regression: ``eth_utils.ValidationError`` inherits from ``Exception``,
        not ``ValueError`` / ``TypeError``. A narrow catch on those two leaked
        the raw exception as a 500 instead of the neutral
        ``signature_internal_error`` envelope that the sibling
        ``recover_message`` block surfaces. This test pins the behaviour so
        a future narrowing of the catch regresses loudly.
        """
        from eth_utils import ValidationError as EthUtilsValidationError

        message, sig, _ = siwe_and_sig

        with patch(
            "blockauth.services.wallet_login_service.EthKeysSignature",
            side_effect=EthUtilsValidationError("bad sig"),
        ):
            with pytest.raises(WalletLoginError) as exc_info:
                svc._verify_signature(
                    address=_TEST_ADDRESS_LC,
                    message=message,
                    signature=sig,
                )
        assert exc_info.value.code == "signature_internal_error"


# =============================================================================
# Service layer — challenge + verify lifecycle
# =============================================================================


@pytest.mark.django_db
class TestIssueChallenge:
    def test_issues_unique_nonce_per_call(self, svc):
        first = svc.issue_challenge(address=_TEST_ADDRESS_LC)
        second = svc.issue_challenge(address=_TEST_ADDRESS_LC)
        assert first.nonce != second.nonce
        assert WalletLoginNonce.objects.count() == 2

    def test_nonce_has_ttl(self, svc):
        result = svc.issue_challenge(address=_TEST_ADDRESS_LC)
        row = WalletLoginNonce.objects.get(nonce=result.nonce)
        assert row.address == _TEST_ADDRESS_LC
        assert row.domain == "example.com"
        assert row.consumed_at is None
        assert (row.expires_at - row.issued_at) == timedelta(minutes=5)

    def test_rejects_bad_address(self, svc):
        with pytest.raises(WalletLoginError) as exc_info:
            svc.issue_challenge(address="not-an-address")
        assert exc_info.value.code == "invalid_address"

    def test_rejects_disallowed_domain(self, svc):
        with pytest.raises(WalletLoginError) as exc_info:
            svc.issue_challenge(address=_TEST_ADDRESS_LC, domain="phisher.example")
        assert exc_info.value.code == "domain_not_allowed"


@pytest.mark.django_db
class TestVerifyLogin:
    def test_happy_path_consumes_nonce(self, svc):
        challenge = svc.issue_challenge(address=_TEST_ADDRESS_LC)
        sig = _sign(challenge.message)
        result = svc.verify_login(
            wallet_address=_TEST_ADDRESS_LC,
            message=challenge.message,
            signature=sig,
        )
        assert result.address == _TEST_ADDRESS_LC
        row = WalletLoginNonce.objects.get(pk=result.nonce_id)
        assert row.consumed_at is not None

    def test_replay_rejected_after_consumption(self, svc):
        challenge = svc.issue_challenge(address=_TEST_ADDRESS_LC)
        sig = _sign(challenge.message)
        svc.verify_login(
            wallet_address=_TEST_ADDRESS_LC,
            message=challenge.message,
            signature=sig,
        )
        with pytest.raises(WalletLoginError) as exc_info:
            svc.verify_login(
                wallet_address=_TEST_ADDRESS_LC,
                message=challenge.message,
                signature=sig,
            )
        assert exc_info.value.code == "nonce_invalid"

    def test_rejects_expired_nonce(self, svc):
        challenge = svc.issue_challenge(address=_TEST_ADDRESS_LC)
        sig = _sign(challenge.message)
        WalletLoginNonce.objects.filter(nonce=challenge.nonce).update(
            expires_at=django_timezone.now() - timedelta(seconds=1)
        )
        with pytest.raises(WalletLoginError) as exc_info:
            svc.verify_login(
                wallet_address=_TEST_ADDRESS_LC,
                message=challenge.message,
                signature=sig,
            )
        # Either the plaintext expiration or the nonce row expiration may
        # trip first depending on timing.
        assert exc_info.value.code in {"expired", "nonce_expired"}

    def test_rejects_domain_mismatch(self, svc):
        """Client signs a message whose domain is not in the allow-list."""
        issued = django_timezone.now()
        rogue_msg = build_siwe_message(
            domain="phisher.example",
            address=_TEST_ADDRESS,
            uri="https://phisher.example/",
            chain_id=1,
            nonce="abcdef1234567890abcdef1234567890",
            issued_at=issued,
            expiration_time=issued + timedelta(minutes=5),
        )
        with pytest.raises(WalletLoginError) as exc_info:
            svc.verify_login(
                wallet_address=_TEST_ADDRESS_LC,
                message=rogue_msg,
                signature=_sign(rogue_msg),
            )
        assert exc_info.value.code == "domain_mismatch"

    def test_rejects_address_mismatch(self, svc):
        challenge = svc.issue_challenge(address=_TEST_ADDRESS_LC)
        sig = _sign(challenge.message)
        with pytest.raises(WalletLoginError) as exc_info:
            svc.verify_login(
                wallet_address="0x" + "0" * 40,
                message=challenge.message,
                signature=sig,
            )
        assert exc_info.value.code == "address_mismatch"

    def test_rejects_unknown_nonce(self, svc):
        issued = django_timezone.now()
        forged = build_siwe_message(
            domain="example.com",
            address=_TEST_ADDRESS,
            uri="https://example.com/",
            chain_id=1,
            nonce="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            issued_at=issued,
            expiration_time=issued + timedelta(minutes=5),
        )
        with pytest.raises(WalletLoginError) as exc_info:
            svc.verify_login(
                wallet_address=_TEST_ADDRESS_LC,
                message=forged,
                signature=_sign(forged),
            )
        assert exc_info.value.code == "nonce_invalid"

    def test_rejects_wrong_signature(self, svc):
        challenge = svc.issue_challenge(address=_TEST_ADDRESS_LC)
        other = Account.from_key("0x" + "2" * 64)
        signed = other.sign_message(encode_defunct(text=challenge.message))
        sig_hex = signed.signature.hex()
        bad_sig = sig_hex if sig_hex.startswith("0x") else "0x" + sig_hex
        with pytest.raises(WalletLoginError) as exc_info:
            svc.verify_login(
                wallet_address=_TEST_ADDRESS_LC,
                message=challenge.message,
                signature=bad_sig,
            )
        assert exc_info.value.code == "signature_mismatch"

    def test_rejects_not_yet_valid(self, svc):
        issued = django_timezone.now()
        future_msg = build_siwe_message(
            domain="example.com",
            address=_TEST_ADDRESS,
            uri="https://example.com/",
            chain_id=1,
            nonce="abcdef1234567890abcdef1234567890",
            issued_at=issued,
            not_before=issued + timedelta(minutes=10),
            expiration_time=issued + timedelta(minutes=15),
        )
        with pytest.raises(WalletLoginError) as exc_info:
            svc.verify_login(
                wallet_address=_TEST_ADDRESS_LC,
                message=future_msg,
                signature=_sign(future_msg),
            )
        assert exc_info.value.code == "not_yet_valid"

    def test_rejects_uri_host_mismatch(self, svc):
        """Issue #117 — URI host must match SIWE domain.

        A phisher domain whose URI points at a different host can pass the
        domain allow-list but authorize a different origin. The wallet UI
        typically shows the URI, not the domain, so the user sees the
        phisher origin and signs anyway. Reject with ``uri_host_mismatch``
        before the signature check so the metric bucket is distinct from
        the pre-existing ``domain_mismatch``.
        """
        issued = django_timezone.now()
        tampered = build_siwe_message(
            domain="example.com",
            address=_TEST_ADDRESS,
            uri="https://phisher.example/path",
            chain_id=1,
            nonce="abcdef1234567890abcdef1234567890",
            issued_at=issued,
            expiration_time=issued + timedelta(minutes=5),
        )
        with pytest.raises(WalletLoginError) as exc_info:
            svc.verify_login(
                wallet_address=_TEST_ADDRESS_LC,
                message=tampered,
                signature=_sign(tampered),
            )
        assert exc_info.value.code == "uri_host_mismatch"

    def test_accepts_uri_host_matching_domain(self, svc):
        """Issue #117 — matching URI host must continue to pass.

        Also covers port-only differences: ``https://example.com:8443/``
        has the same hostname as ``example.com`` and must not be rejected.
        """
        challenge = svc.issue_challenge(address=_TEST_ADDRESS_LC)
        # Rebuild the SIWE message reusing the server nonce but with a
        # port on the URI. Same host -> must still pass.
        tampered_uri = build_siwe_message(
            domain="example.com",
            address=_TEST_ADDRESS,
            uri="https://example.com:8443/",
            chain_id=1,
            nonce=challenge.nonce,
            issued_at=challenge.issued_at,
            expiration_time=challenge.expires_at,
        )
        result = svc.verify_login(
            wallet_address=_TEST_ADDRESS_LC,
            message=tampered_uri,
            signature=_sign(tampered_uri),
        )
        assert result.address == _TEST_ADDRESS_LC

    def test_rejects_uri_without_host(self, svc):
        """Issue #117 — URIs without a host (e.g. ``urn:...``) cannot be
        bound to a domain at all. Reject rather than silently accepting.
        """
        issued = django_timezone.now()
        tampered = build_siwe_message(
            domain="example.com",
            address=_TEST_ADDRESS,
            uri="urn:example:sign-in",
            chain_id=1,
            nonce="abcdef1234567890abcdef1234567890",
            issued_at=issued,
            expiration_time=issued + timedelta(minutes=5),
        )
        with pytest.raises(WalletLoginError) as exc_info:
            svc.verify_login(
                wallet_address=_TEST_ADDRESS_LC,
                message=tampered,
                signature=_sign(tampered),
            )
        assert exc_info.value.code == "uri_host_mismatch"

    def test_rejects_uri_subdomain_of_domain(self, svc):
        """Issue #117 — strict equality: subdomains are not the same host.

        Mirrors the existing "no wildcard suffixes" stance on
        ``WALLET_LOGIN_EXPECTED_DOMAINS``. If a deployment wants
        ``sub.example.com`` it must appear explicitly in the SIWE domain
        field (and the allow-list), not be implied by URI subdomaining.
        """
        issued = django_timezone.now()
        tampered = build_siwe_message(
            domain="example.com",
            address=_TEST_ADDRESS,
            uri="https://sub.example.com/",
            chain_id=1,
            nonce="abcdef1234567890abcdef1234567890",
            issued_at=issued,
            expiration_time=issued + timedelta(minutes=5),
        )
        with pytest.raises(WalletLoginError) as exc_info:
            svc.verify_login(
                wallet_address=_TEST_ADDRESS_LC,
                message=tampered,
                signature=_sign(tampered),
            )
        assert exc_info.value.code == "uri_host_mismatch"

    def test_rejects_nonce_chain_mismatch(self, svc):
        """Server minted a chain-1 nonce; signed message claims chain 137."""
        challenge = svc.issue_challenge(address=_TEST_ADDRESS_LC, chain_id=1)
        # Mint a parallel SIWE plaintext reusing the same nonce but a
        # different chain_id. The SIWE parser is fine with that; the service
        # should reject on nonce_chain_mismatch.
        issued = django_timezone.now()
        tampered = build_siwe_message(
            domain="example.com",
            address=_TEST_ADDRESS,
            uri="https://example.com/",
            chain_id=137,
            nonce=challenge.nonce,
            issued_at=issued,
            expiration_time=issued + timedelta(minutes=5),
        )
        with pytest.raises(WalletLoginError) as exc_info:
            svc.verify_login(
                wallet_address=_TEST_ADDRESS_LC,
                message=tampered,
                signature=_sign(tampered),
            )
        assert exc_info.value.code == "nonce_chain_mismatch"

    def test_accepts_authority_with_port(self):
        """Issue #125 — EIP-4361 §3.2 lets ``domain`` carry ``host:port``.

        MetaMask and other wallets bind ``siwe.domain`` to
        ``window.location.host`` which keeps the port. ``urlparse(uri).hostname``
        strips it. The pre-fix uri-host equality check therefore rejected
        every dapp on a non-default port (Vite/Webpack/Next dev servers,
        Docker host-forwarded ports, preview deploys on ``:8443``).
        """
        svc = WalletLoginService(
            expected_domains=("localhost",),
            default_chain_id=1,
        )
        challenge = svc.issue_challenge(
            address=_TEST_ADDRESS_LC,
            domain="localhost:5173",
            uri="https://localhost:5173",
        )
        assert challenge.domain == "localhost:5173"
        result = svc.verify_login(
            wallet_address=_TEST_ADDRESS_LC,
            message=challenge.message,
            signature=_sign(challenge.message),
        )
        assert result.address == _TEST_ADDRESS_LC

    def test_accepts_authority_with_port_when_allowlist_has_port(self):
        """Issue #125 — existing deployments with port-equipped allow-list
        entries (``localhost:5173``) keep working. Both sides of the
        membership test get port-stripped, so the entry matches the
        signed authority.
        """
        svc = WalletLoginService(
            expected_domains=("localhost:5173",),
            default_chain_id=1,
        )
        challenge = svc.issue_challenge(
            address=_TEST_ADDRESS_LC,
            domain="localhost:5173",
            uri="https://localhost:5173",
        )
        result = svc.verify_login(
            wallet_address=_TEST_ADDRESS_LC,
            message=challenge.message,
            signature=_sign(challenge.message),
        )
        assert result.address == _TEST_ADDRESS_LC

    def test_rejects_malformed_domain_when_allowlist_entry_has_no_host(self):
        """Issue #125 / CodeRabbit follow-up — a malformed allow-list entry
        whose authority parses to an empty host (e.g. ``":5173"``) must not
        seed an empty-host bucket that would then accept malformed inputs.
        """
        svc = WalletLoginService(
            expected_domains=(":5173",),
            default_chain_id=1,
        )
        with pytest.raises(WalletLoginError) as exc_info:
            svc.issue_challenge(address=_TEST_ADDRESS_LC, domain=":5173")
        assert exc_info.value.code == "domain_not_allowed"

    def test_fallback_from_client_app_url_preserves_port(self, settings):
        """Issue #125 / CodeRabbit follow-up — when the allow-list is unset,
        the dev fallback that derives ``configured_domains`` from
        ``CLIENT_APP_URL`` must keep the port so SIWE messages bind to the
        same authority the browser exposes (``localhost:5173``).
        """
        settings.WALLET_LOGIN_EXPECTED_DOMAINS = ()
        settings.BLOCK_AUTH_SETTINGS = {"CLIENT_APP_URL": "http://localhost:5173"}
        svc = WalletLoginService(default_chain_id=1)
        assert svc.expected_domains == ("localhost:5173",)
        challenge = svc.issue_challenge(address=_TEST_ADDRESS_LC)
        assert challenge.domain == "localhost:5173"

    def test_fallback_from_client_app_url_preserves_ipv6_brackets(self, settings):
        """Issue #125 / CodeRabbit follow-up — IPv6 ``CLIENT_APP_URL`` must
        keep the bracket form so ``_authority_host`` parses it (a bare
        ``::1`` would be malformed and the allow-list would end up empty).
        """
        settings.WALLET_LOGIN_EXPECTED_DOMAINS = ()
        settings.BLOCK_AUTH_SETTINGS = {"CLIENT_APP_URL": "http://[::1]:5173"}
        svc = WalletLoginService(default_chain_id=1)
        assert svc.expected_domains == ("[::1]:5173",)
        assert "::1" in svc._expected_hosts

    def test_emitted_domain_strips_default_port_for_https(self):
        """Issue #125 / CodeRabbit follow-up — ``window.location.host`` omits
        the port when it matches the scheme default (443 for HTTPS, 80 for
        HTTP) per WHATWG. The stored allow-list and the resolver must do
        the same so a SIWE message we emit matches the browser origin
        byte-for-byte and the wallet signs.
        """
        svc = WalletLoginService(
            expected_domains=("example.com:443",),
            default_chain_id=1,
        )
        assert svc.expected_domains == ("example.com",)
        challenge = svc.issue_challenge(
            address=_TEST_ADDRESS_LC,
            domain="example.com:443",
            uri="https://example.com",
        )
        assert challenge.domain == "example.com"

    def test_rejects_uri_with_invalid_port(self, svc):
        """Issue #125 / CodeRabbit follow-up — ``urlparse(uri).hostname`` does
        not validate the port, so ``https://example.com:notaport/`` would
        otherwise sneak past the URI-host equality check as long as the
        hostname matches. Force ``parsed_uri.port`` evaluation and reject
        on ``ValueError``.
        """
        issued = django_timezone.now()
        tampered = build_siwe_message(
            domain="example.com",
            address=_TEST_ADDRESS,
            uri="https://example.com:notaport/",
            chain_id=1,
            nonce="abcdef1234567890abcdef1234567890",
            issued_at=issued,
            expiration_time=issued + timedelta(minutes=5),
        )
        with pytest.raises(WalletLoginError) as exc_info:
            svc.verify_login(
                wallet_address=_TEST_ADDRESS_LC,
                message=tampered,
                signature=_sign(tampered),
            )
        assert exc_info.value.code == "uri_host_mismatch"

    def test_emitted_domain_is_lowercase_when_caller_uses_uppercase(self):
        """Issue #125 / CodeRabbit follow-up — ``window.location.host`` is
        serialized lowercase per the WHATWG URL spec, so a SIWE message we
        emitted with ``LOCALHOST:5173`` would mismatch the browser origin
        and the wallet would refuse to sign. Both the stored allow-list
        entry and the value returned to callers must canonicalize to
        lowercase.
        """
        svc = WalletLoginService(
            expected_domains=("LOCALHOST:5173",),
            default_chain_id=1,
        )
        assert svc.expected_domains == ("localhost:5173",)
        challenge = svc.issue_challenge(
            address=_TEST_ADDRESS_LC,
            domain="LOCALHOST:5173",
            uri="https://localhost:5173",
        )
        assert challenge.domain == "localhost:5173"

    def test_default_domain_skips_invalid_allowlist_entries(self):
        """Issue #125 / CodeRabbit follow-up — when the allow-list is
        ``(":5173", "example.com")``, the default domain selection must
        not pick the malformed entry verbatim. Drop invalid entries from
        ``expected_domains`` itself so ``self.expected_domains[0]`` can
        only ever return a clean authority.
        """
        svc = WalletLoginService(
            expected_domains=(":5173", "example.com"),
            default_chain_id=1,
        )
        challenge = svc.issue_challenge(address=_TEST_ADDRESS_LC)
        assert challenge.domain == "example.com"

    @pytest.mark.parametrize(
        "bad_domain",
        [
            "example.com/path",
            "example.com?x=1",
            "example.com#frag",
            "user@example.com",
            "localhost:notaport",
            "localhost:99999",
        ],
    )
    def test_rejects_non_authority_domain_inputs(self, svc, bad_domain):
        """Issue #125 / CodeRabbit follow-up — EIP-4361 §3.2 ``domain`` is a
        clean ``host[:port]``. Inputs carrying a path, query, fragment,
        userinfo, or invalid port must be rejected so they can't be smuggled
        into the SIWE plaintext that the wallet signs.
        """
        with pytest.raises(WalletLoginError) as exc_info:
            svc.issue_challenge(address=_TEST_ADDRESS_LC, domain=bad_domain)
        assert exc_info.value.code == "domain_not_allowed"

    def test_rejects_authority_port_mismatch_against_different_host(self):
        """Issue #125 — port normalization must not weaken host binding.

        A signed message with domain ``localhost:5173`` and a URI on a
        different host but the same port (``https://attacker.example:5173/``)
        must still be rejected as ``uri_host_mismatch``. Stripping the port
        only affects the port comparison; the host comparison stays strict.
        """
        svc = WalletLoginService(
            expected_domains=("localhost",),
            default_chain_id=1,
        )
        issued = django_timezone.now()
        tampered = build_siwe_message(
            domain="localhost:5173",
            address=_TEST_ADDRESS,
            uri="https://attacker.example:5173/",
            chain_id=1,
            nonce="abcdef1234567890abcdef1234567890",
            issued_at=issued,
            expiration_time=issued + timedelta(minutes=5),
        )
        with pytest.raises(WalletLoginError) as exc_info:
            svc.verify_login(
                wallet_address=_TEST_ADDRESS_LC,
                message=tampered,
                signature=_sign(tampered),
            )
        assert exc_info.value.code == "uri_host_mismatch"


# =============================================================================
# HTTP round-trip
# =============================================================================


@pytest.mark.django_db
class TestWalletLoginEndpoints:
    def test_challenge_returns_signable_message(self):
        client = APIClient()
        url = reverse("wallet-login-challenge")
        response = client.post(url, {"address": _TEST_ADDRESS_LC}, format="json")
        assert response.status_code == status.HTTP_200_OK, response.content
        body = response.json()
        assert body["domain"] == "example.com"
        assert body["chain_id"] == 1
        assert body["nonce"]
        assert body["message"].startswith("example.com wants you to sign in with your Ethereum account:")

    def test_full_login_then_replay_rejected(self):
        client = APIClient()
        challenge_resp = client.post(
            reverse("wallet-login-challenge"),
            {"address": _TEST_ADDRESS_LC},
            format="json",
        )
        assert challenge_resp.status_code == 200, challenge_resp.content
        message = challenge_resp.json()["message"]
        sig = _sign(message)

        login_resp = client.post(
            reverse("wallet-login"),
            {
                "wallet_address": _TEST_ADDRESS_LC,
                "message": message,
                "signature": sig,
            },
            format="json",
        )
        assert login_resp.status_code == 200, login_resp.content
        body = login_resp.json()
        assert "access" in body
        assert "refresh" in body
        # Issue #97: wallet login now returns user payload
        assert "user" in body
        user_payload = body["user"]
        assert "id" in user_payload
        assert "is_verified" in user_payload
        assert "wallet_address" in user_payload
        assert user_payload["wallet_address"] == _TEST_ADDRESS_LC
        # email may be null for wallet-first accounts
        assert "email" in user_payload

        # #537: wallets must be WalletItem[], not string[]. Bare address
        # strings cannot evolve to multi-wallet accounts without changing
        # the response shape.
        assert isinstance(user_payload["wallets"], list)
        assert len(user_payload["wallets"]) == 1
        wallet_item = user_payload["wallets"][0]
        assert wallet_item["address"] == _TEST_ADDRESS_LC
        assert wallet_item["chain_id"] == 1
        assert wallet_item["primary"] is True
        assert "linked_at" in wallet_item

        # #537: SIWE proves control of the private key — stronger than
        # email verification. Wallet-first accounts must be created as
        # is_verified=True so downstream gates don't bounce them.
        assert user_payload["is_verified"] is True

        replay = client.post(
            reverse("wallet-login"),
            {
                "wallet_address": _TEST_ADDRESS_LC,
                "message": message,
                "signature": sig,
            },
            format="json",
        )
        assert replay.status_code == status.HTTP_401_UNAUTHORIZED, replay.content
        assert replay.json()["error"]["code"] == "nonce_invalid"

    def test_login_user_payload_does_not_leak_credentials(self):
        """Issue #99: wallet-login's ``user`` payload must never contain
        password hash material or private Django attributes. Guards
        against a future refactor switching the response to a
        ``ModelSerializer(fields="__all__")``.
        """
        client = APIClient()
        login_resp = _perform_wallet_login(client, _TEST_ADDRESS_LC)
        assert login_resp.status_code == 200, login_resp.content
        assert_no_credential_leak(login_resp.json()["user"])

    def test_login_returns_null_email_for_wallet_first_user_autocreate(self):
        """Issue #99: wallet-first users have no email on first SIWE
        login. The auto-create path must expose ``user.email`` as
        ``None`` (a supported case) rather than coercing to an empty
        string or tripping the serializer's validation.

        Also asserts the DB row itself has ``email IS NULL`` -- the
        response could in principle correctly surface ``None`` while
        the backing user row stored ``""``, or vice versa, and both
        would be regressions. Checking both pins the contract
        end-to-end.
        """
        from tests.models import TestBlockUser

        client = APIClient()
        login_resp = _perform_wallet_login(client, _TEST_ADDRESS_LC)
        assert login_resp.status_code == status.HTTP_200_OK, login_resp.content
        user_payload = login_resp.json()["user"]
        assert user_payload["wallet_address"] == _TEST_ADDRESS_LC
        assert user_payload["email"] is None

        # DB-level sanity: the auto-create path must store ``None``, not
        # ``""``. A coerced empty string would satisfy the response
        # check (DRF would still serialize it as ``""``) so this is an
        # independent assertion, not a duplicate.
        created = TestBlockUser.objects.get(wallet_address=_TEST_ADDRESS_LC)
        assert created.email is None

    def test_login_returns_null_email_for_existing_wallet_first_user(self):
        """Issue #99: the response must also expose ``user.email`` as
        ``None`` for a *pre-existing* wallet-first user -- not just
        on the auto-create branch.

        The auto-create variant alone is too weak: if a future change
        coerced ``email`` to ``""`` only when looking up an existing
        row (say, a ``User.objects.get_or_create(defaults={"email":
        ""})`` regression), the auto-create test would still pass
        because it asserts the happy-path default, not the lookup
        branch.

        Seed an existing row with ``email=None`` via the ORM, then
        drive a login against it and assert both the response and the
        untouched DB row still hold ``None``.
        """
        from tests.models import TestBlockUser

        existing = TestBlockUser.objects.create(
            wallet_address=_TEST_ADDRESS_LC,
            email=None,
            is_verified=False,
        )
        client = APIClient()
        login_resp = _perform_wallet_login(client, _TEST_ADDRESS_LC)
        assert login_resp.status_code == status.HTTP_200_OK, login_resp.content
        user_payload = login_resp.json()["user"]
        assert user_payload["wallet_address"] == _TEST_ADDRESS_LC
        assert user_payload["email"] is None

        # Existing row must not have been mutated by the login path.
        existing.refresh_from_db()
        assert existing.email is None

    def test_login_rejects_forged_domain(self):
        client = APIClient()
        issued = django_timezone.now()
        rogue_msg = build_siwe_message(
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
                "message": rogue_msg,
                "signature": _sign(rogue_msg),
            },
            format="json",
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED, resp.content
        assert resp.json()["error"]["code"] == "domain_mismatch"

    def test_login_rejects_unknown_wallet_with_generic_401(self, settings):
        """Hardening #4 — the default no longer acts as a registration oracle."""
        settings.WALLET_LOGIN_AUTO_CREATE = False
        client = APIClient()
        challenge_resp = client.post(
            reverse("wallet-login-challenge"),
            {"address": _TEST_ADDRESS_LC},
            format="json",
        )
        message = challenge_resp.json()["message"]
        sig = _sign(message)
        resp = client.post(
            reverse("wallet-login"),
            {
                "wallet_address": _TEST_ADDRESS_LC,
                "message": message,
                "signature": sig,
            },
            format="json",
        )
        # Default hides registration status — 401 + generic code.
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED, resp.content
        assert resp.json()["error"]["code"] == "login_failed"

    def test_login_rejects_unknown_wallet_explicit_oracle_opt_in(self, settings):
        """Deployments that opt in still get the distinct 403."""
        settings.WALLET_LOGIN_AUTO_CREATE = False
        settings.WALLET_LOGIN_EXPOSE_REGISTRATION_STATUS = True
        client = APIClient()
        challenge_resp = client.post(
            reverse("wallet-login-challenge"),
            {"address": _TEST_ADDRESS_LC},
            format="json",
        )
        message = challenge_resp.json()["message"]
        sig = _sign(message)
        resp = client.post(
            reverse("wallet-login"),
            {
                "wallet_address": _TEST_ADDRESS_LC,
                "message": message,
                "signature": sig,
            },
            format="json",
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN, resp.content
        assert resp.json()["error"]["code"] == "auto_create_disabled"

    def test_login_existing_wallet_succeeds_with_autocreate_disabled(self, settings):
        """A pre-existing user still logs in when auto-create is off."""
        settings.WALLET_LOGIN_AUTO_CREATE = False
        from tests.models import TestBlockUser

        TestBlockUser.objects.create(wallet_address=_TEST_ADDRESS_LC, is_verified=False)
        client = APIClient()
        challenge_resp = client.post(
            reverse("wallet-login-challenge"),
            {"address": _TEST_ADDRESS_LC},
            format="json",
        )
        message = challenge_resp.json()["message"]
        sig = _sign(message)
        resp = client.post(
            reverse("wallet-login"),
            {
                "wallet_address": _TEST_ADDRESS_LC,
                "message": message,
                "signature": sig,
            },
            format="json",
        )
        assert resp.status_code == 200, resp.content
        body = resp.json()
        assert "access" in body
        # Issue #97: user payload present for existing wallet too
        assert "user" in body
        assert body["user"]["wallet_address"] == _TEST_ADDRESS_LC

    def test_login_rejects_oversized_message(self):
        """Hardening #9 — serializer caps message length."""
        from blockauth.utils.siwe import MAX_SIWE_MESSAGE_LENGTH

        client = APIClient()
        huge = "x" * (MAX_SIWE_MESSAGE_LENGTH + 16)
        resp = client.post(
            reverse("wallet-login"),
            {
                "wallet_address": _TEST_ADDRESS_LC,
                "message": huge,
                "signature": "0x" + "ab" * 65,
            },
            format="json",
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST


# =============================================================================
# Hardening #1 — auto-create race must not 500
# =============================================================================


@pytest.mark.django_db
class TestAutoCreateRace:
    """The linker must use get_or_create inside transaction.atomic."""

    def test_second_concurrent_first_login_returns_existing_user(self):
        """Simulate the losing side of the race by pre-creating the row.

        If the linker used filter().first() + create() it would raise
        IntegrityError (unique wallet_address). get_or_create returns the
        existing row instead.
        """
        from blockauth.services.wallet_user_linker import WalletUserLinker
        from tests.models import TestBlockUser

        existing = TestBlockUser.objects.create(wallet_address=_TEST_ADDRESS_LC, is_verified=False)

        linker = WalletUserLinker()
        linked = linker.link(wallet_address=_TEST_ADDRESS_LC)
        assert linked.user_id == str(existing.id)
        assert linked.created is False


# =============================================================================
# Hardening #2 — trigger fan-out is post-commit and exception-safe
# =============================================================================


@pytest.mark.django_db(transaction=True)
class TestTriggerFanOut:
    """Use transaction=True so ``transaction.on_commit`` actually fires.

    pytest-django's default ``django_db`` fixture wraps each test in a
    rollback, which suppresses ``on_commit`` callbacks. The linker's
    post-commit trigger dispatch needs a real commit to exercise.
    """

    def test_exception_in_post_signup_trigger_does_not_kill_response(self, settings):
        """A raising POST_SIGNUP_TRIGGER must not break the login path."""
        from blockauth.services.wallet_user_linker import WalletUserLinker

        calls = {"post_login": 0, "post_signup": 0}

        class RaisingSignup:
            def trigger(self, context):
                calls["post_signup"] += 1
                raise RuntimeError("signup webhook exploded")

        class CountingLogin:
            def trigger(self, context):
                calls["post_login"] += 1

        from blockauth.services import wallet_user_linker as linker_mod

        def _fake_get_config(key):
            if key == "POST_SIGNUP_TRIGGER":
                return RaisingSignup
            if key == "POST_LOGIN_TRIGGER":
                return CountingLogin
            raise AttributeError(key)

        with patch.object(linker_mod, "get_config", _fake_get_config):
            linker = WalletUserLinker()
            linked = linker.link(wallet_address=_TEST_ADDRESS_LC)

        assert linked.created is True
        # Signup trigger was invoked and raised — that must not roll back
        # the user row or break the login fan-out.
        assert calls["post_signup"] == 1
        # POST_LOGIN_TRIGGER must still have fired even though POST_SIGNUP
        # blew up -- the linker wraps each trigger in its own try/except.
        assert calls["post_login"] == 1


# =============================================================================
# LogRecord attribute-collision regression
# =============================================================================


@pytest.mark.django_db
class TestLinkerLoggingDoesNotCollide:
    """Regression: ``logger.info(extra={"created": ...})`` blows up because
    ``created`` is a reserved ``LogRecord`` attribute (the record's creation
    timestamp). Any handler that actually formats the record raises
    ``KeyError: "Attempt to overwrite 'created' in LogRecord"``. The fix
    renames the extra key to ``user_created``. This test wires a real
    ``StreamHandler`` + ``Formatter`` onto the linker's logger and asserts
    the successful-link path emits a record without raising.
    """

    def test_successful_link_emits_record_without_collision(self):
        import io
        import logging

        from blockauth.services import wallet_user_linker as linker_mod
        from blockauth.services.wallet_user_linker import WalletUserLinker

        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        # The default Formatter calls ``LogRecord.getMessage`` and touches
        # the reserved attribute names during ``%(created)s``-style interp
        # when something attempts to overwrite them in ``extra=``. Use a
        # format string that forces attribute access on ``created`` so we
        # get the KeyError on pre-fix code. ``makeRecord`` itself also
        # refuses to overwrite reserved attrs in ``extra`` on any modern
        # Python, so even the default formatter is enough to trip the bug
        # -- belt and braces.
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))

        linker_logger = linker_mod.logger
        prior_level = linker_logger.level
        linker_logger.addHandler(handler)
        linker_logger.setLevel(logging.INFO)
        try:
            linker = WalletUserLinker()
            linked = linker.link(wallet_address=_TEST_ADDRESS_LC)
            handler.flush()
        finally:
            linker_logger.removeHandler(handler)
            linker_logger.setLevel(prior_level)

        # Sanity: the happy path actually ran.
        assert linked.user_id
        # And the handler captured the line (non-empty ==> no raise during
        # emit). On pre-fix code ``makeRecord`` raises before anything
        # lands in the buffer.
        assert "Wallet login linked to user" in buf.getvalue()
