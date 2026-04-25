"""AppleIdTokenVerifier tests — bool coercion, conditional nonce, verify_raw.

Uses the session RSA keypair to generate Apple-shaped id_tokens. Patches the
JWKS HTTP fetch to return the test public key.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from django.test import override_settings

from blockauth.apple.exceptions import AppleNonceMismatch
from blockauth.apple.id_token_verifier import AppleIdTokenClaims, AppleIdTokenVerifier


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
