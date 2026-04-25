"""Tests for JWKSCache.

Strategy: stub `requests.get` to return real JWKS JSON bytes (from the session
`jwks_payload_bytes` fixture) and assert cache hit/miss behavior.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from blockauth.utils.jwt.exceptions import KidNotFound
from blockauth.utils.jwt.jwks_cache import JWKSCache


@pytest.fixture
def jwks_response(jwks_payload_bytes):
    response = MagicMock()
    response.status_code = 200
    response.content = jwks_payload_bytes
    response.json.return_value = json.loads(jwks_payload_bytes.decode())
    return response


def test_first_call_fetches_jwks(jwks_response, rsa_keypair):
    _, _, kid = rsa_keypair
    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response) as mock_get:
        key = cache.get_key_for_kid(kid)
    assert key["kid"] == kid
    assert mock_get.call_count == 1


def test_second_call_within_ttl_uses_cache(jwks_response, rsa_keypair):
    _, _, kid = rsa_keypair
    cache = JWKSCache("https://issuer.example/.well-known/jwks.json", cache_ttl_seconds=3600)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response) as mock_get:
        cache.get_key_for_kid(kid)
        cache.get_key_for_kid(kid)
    assert mock_get.call_count == 1


def test_unknown_kid_triggers_one_refetch(jwks_response, rsa_keypair):
    _, _, kid = rsa_keypair
    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response) as mock_get:
        cache.get_key_for_kid(kid)
        with pytest.raises(KidNotFound):
            cache.get_key_for_kid("rotated-kid-not-present")
    assert mock_get.call_count == 2


def test_unknown_kid_succeeds_when_refetch_returns_it(jwks_payload_bytes, rsa_keypair):
    _, _, kid = rsa_keypair
    rotated_jwks = json.loads(jwks_payload_bytes.decode())
    rotated_jwks["keys"][0]["kid"] = "rotated-kid-1"
    rotated_response = MagicMock()
    rotated_response.status_code = 200
    rotated_response.content = json.dumps(rotated_jwks).encode()
    rotated_response.json.return_value = rotated_jwks
    initial_response = MagicMock()
    initial_response.status_code = 200
    initial_response.json.return_value = {"keys": [{"kid": "old-kid", "kty": "RSA", "n": "x", "e": "AQAB"}]}

    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    with patch(
        "blockauth.utils.jwt.jwks_cache.requests.get",
        side_effect=[initial_response, rotated_response],
    ) as mock_get:
        cache.get_key_for_kid("old-kid")
        key = cache.get_key_for_kid("rotated-kid-1")
    assert key["kid"] == "rotated-kid-1"
    assert mock_get.call_count == 2


def test_jwks_fetch_failure_raises():
    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    failing_response = MagicMock(status_code=500)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=failing_response):
        with pytest.raises(KidNotFound):
            cache.get_key_for_kid("any-kid")
