"""AppleIdTokenVerifier tests — bool coercion, conditional nonce, verify_raw.

Uses the session RSA keypair to generate Apple-shaped id_tokens. Patches the
JWKS HTTP fetch to return the test public key.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from django.test import override_settings

from blockauth.apple.exceptions import AppleIdTokenVerificationFailed, AppleNonceMismatch
from blockauth.apple.id_token_verifier import (
    AppleIdTokenClaims,
    AppleIdTokenVerifier,
    _reset_verifier_cache,
)


@pytest.fixture(autouse=True)
def _clear_verifier_cache():
    """Reset the module-level OIDCTokenVerifier cache between tests so
    `override_settings` changes (audiences, leeway) take effect."""
    _reset_verifier_cache()
    yield
    _reset_verifier_cache()


@pytest.fixture
def configured_settings():
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_SERVICES_ID": "com.example.services",
            "APPLE_BUNDLE_IDS": ("com.example.app",),
        }
    ):
        yield


@pytest.fixture
def jwks_response(jwks_payload_bytes):
    response = MagicMock(status_code=200, content=jwks_payload_bytes)
    response.json.return_value = json.loads(jwks_payload_bytes.decode())
    return response


def _apple_token(build_id_token, **overrides):
    claims = {
        "iss": "https://appleid.apple.com",
        "aud": "com.example.services",
        "sub": "001234.abcdef.1234",
        "email": "user@privaterelay.appleid.com",
        "email_verified": "true",
        "is_private_email": "true",
        "nonce_supported": True,
    }
    claims.update(overrides)
    return build_id_token(claims)


def test_string_bool_email_verified_coerced_to_true(configured_settings, build_id_token, jwks_response):
    token = _apple_token(build_id_token)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        claims = AppleIdTokenVerifier().verify(token, expected_nonce=None)
    assert isinstance(claims, AppleIdTokenClaims)
    assert claims.email_verified is True
    assert claims.is_private_email is True


def test_native_bundle_audience_accepted(configured_settings, build_id_token, jwks_response):
    token = _apple_token(build_id_token, aud="com.example.app")
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        claims = AppleIdTokenVerifier().verify(token, expected_nonce=None)
    assert claims.sub == "001234.abcdef.1234"


def test_nonce_required_when_nonce_supported_true(configured_settings, build_id_token, jwks_response):
    token = _apple_token(build_id_token, nonce="hashed-from-server", nonce_supported=True)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        AppleIdTokenVerifier().verify(token, expected_nonce="hashed-from-server")


def test_nonce_mismatch_raises_when_nonce_supported_true(configured_settings, build_id_token, jwks_response):
    token = _apple_token(build_id_token, nonce="aaaa", nonce_supported=True)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        with pytest.raises(AppleNonceMismatch):
            AppleIdTokenVerifier().verify(token, expected_nonce="bbbb")


def test_nonce_skipped_when_nonce_supported_false(configured_settings, build_id_token, jwks_response):
    token = _apple_token(build_id_token, nonce_supported=False)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        AppleIdTokenVerifier().verify(token, expected_nonce="anything")


def test_verify_raw_for_s2s_uses_services_id_audience(configured_settings, build_id_token, jwks_response):
    token = _apple_token(build_id_token, aud="com.example.services", events="event-payload-string")
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        claims = AppleIdTokenVerifier().verify_raw(token, audiences=("com.example.services",))
    assert claims["events"] == "event-payload-string"


def test_verify_raw_rejects_token_with_wrong_audience(configured_settings, build_id_token, jwks_response):
    """verify_raw must enforce the audience filter — a token aud'd to the
    bundle id is rejected when the caller passes only the services id."""
    token = _apple_token(build_id_token, aud="com.example.app", events="x")
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        with pytest.raises(AppleIdTokenVerificationFailed):
            AppleIdTokenVerifier().verify_raw(token, audiences=("com.example.services",))


def test_verify_raw_accepts_s2s_token_without_email(configured_settings, build_id_token, jwks_response):
    """Apple S2S notifications (consent-revoked, account-delete) do NOT carry
    an `email` claim. verify_raw must succeed even when email is absent.
    The bug this guards: OIDCVerifierConfig defaults require_email_claim=True,
    so without an explicit override RequiredClaimMissing would silently fail
    every S2S notification in production."""
    claims = {
        "iss": "https://appleid.apple.com",
        "aud": "com.example.services",
        "sub": "001234.abcdef.1234",
        # NOTE: no `email`, no `email_verified` — this is what Apple sends
        # for consent-revoked / account-delete events.
        "events": "consent-revoked-payload",
    }
    token = build_id_token(claims)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        decoded = AppleIdTokenVerifier().verify_raw(token, audiences=("com.example.services",))
    assert decoded["events"] == "consent-revoked-payload"
    assert "email" not in decoded


def test_nonce_skipped_when_nonce_supported_absent(configured_settings, build_id_token, jwks_response):
    """The docstring says 'False or absent — skip'. The fixture's default
    includes nonce_supported=True; this test omits it entirely so the
    'absent' branch is exercised (relies on _coerce_bool(None) returning
    False)."""
    claims = {
        "iss": "https://appleid.apple.com",
        "aud": "com.example.services",
        "sub": "001234.legacy.5678",
        "email": "user@privaterelay.appleid.com",
        # nonce_supported INTENTIONALLY OMITTED to test the absent path
    }
    token = build_id_token(claims)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        result = AppleIdTokenVerifier().verify(token, expected_nonce="anything")
    assert result.nonce_supported is False
