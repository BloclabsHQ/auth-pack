"""Tests for JWKSCache.

Strategy: stub `requests.get` to return real JWKS JSON bytes (from the session
`jwks_payload_bytes` fixture) and assert cache hit/miss behavior.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from blockauth.utils.jwt.exceptions import JWKSUnreachable, KidNotFound
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
    """Non-200 from JWKS endpoint surfaces as JWKSUnreachable AND preserves (empty) cache state."""
    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    failing_response = MagicMock(status_code=500)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=failing_response):
        with pytest.raises(JWKSUnreachable):
            cache.get_key_for_kid("any-kid")
    # Cache state untouched — no spurious "fresh empty cache" pinning.
    assert cache._keys_by_kid == {}
    assert cache._fetched_at == 0.0


def test_transient_5xx_preserves_previously_cached_keys(jwks_payload_bytes, rsa_keypair):
    """A 5xx after a successful fetch must not wipe the cache or bump _fetched_at.

    Without this, a transient IdP outage would mark the empty cache as fresh and
    starve legitimate verifications for the entire TTL window.
    """
    _, _, kid = rsa_keypair
    initial_response = MagicMock()
    initial_response.status_code = 200
    initial_response.json.return_value = json.loads(jwks_payload_bytes.decode())
    failing_response = MagicMock(status_code=503)

    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    with patch(
        "blockauth.utils.jwt.jwks_cache.requests.get",
        side_effect=[initial_response, failing_response],
    ):
        cache.get_key_for_kid(kid)  # populates cache
        cached_fetched_at_before_503 = cache._fetched_at
        cache._fetched_at = 0.0  # force the cache to look stale so the next call attempts a fetch
        with pytest.raises((KidNotFound, JWKSUnreachable)):
            cache.get_key_for_kid("unknown-kid-rotation-attempt")

    # Original kid still recoverable; _keys_by_kid was not wiped.
    assert cache._keys_by_kid.get(kid) is not None
    # _fetched_at was not bumped by the failed fetch (still the value we forced).
    assert cache._fetched_at == 0.0


def test_network_error_does_not_propagate_raw(rsa_keypair):
    """RequestException from requests.get must surface as JWKSUnreachable, not raw exception."""
    import requests as _requests

    _, _, kid = rsa_keypair
    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    with patch(
        "blockauth.utils.jwt.jwks_cache.requests.get",
        side_effect=_requests.exceptions.ConnectionError("DNS failure"),
    ):
        with pytest.raises(JWKSUnreachable):
            cache.get_key_for_kid(kid)


def test_304_with_empty_cache_does_not_pin_empty_state():
    """304 against an empty cache must NOT mark _fetched_at fresh (would re-introduce wipe-and-bump)."""
    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    not_modified = MagicMock(status_code=304)
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=not_modified):
        with pytest.raises(JWKSUnreachable):
            cache.get_key_for_kid("any-kid")
    assert cache._keys_by_kid == {}
    assert cache._fetched_at == 0.0


def test_304_with_populated_cache_refreshes_freshness(jwks_payload_bytes, rsa_keypair):
    """304 against a populated cache refreshes _fetched_at without touching keys."""
    _, _, kid = rsa_keypair
    initial_response = MagicMock()
    initial_response.status_code = 200
    initial_response.json.return_value = json.loads(jwks_payload_bytes.decode())
    not_modified = MagicMock(status_code=304)

    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    with patch(
        "blockauth.utils.jwt.jwks_cache.requests.get",
        side_effect=[initial_response, not_modified],
    ):
        cache.get_key_for_kid(kid)  # populates cache
        cache._fetched_at = 0.0  # force stale so the next call refetches
        # Asking for a present kid after staling: stale-refresh fetch returns 304,
        # cache stays populated, _fetched_at refreshed, kid still present.
        key = cache.get_key_for_kid(kid)
    assert key["kid"] == kid
    assert cache._keys_by_kid.get(kid) is not None
    assert cache._fetched_at > 0.0


def test_malformed_json_response_does_not_propagate_raw(rsa_keypair):
    """A 200 with non-JSON body must surface as JWKSUnreachable, not raw ValueError."""
    _, _, kid = rsa_keypair
    bad_response = MagicMock(status_code=200)
    bad_response.json.side_effect = ValueError("Expecting value: line 1 column 1 (char 0)")
    cache = JWKSCache("https://issuer.example/.well-known/jwks.json")
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=bad_response):
        with pytest.raises(JWKSUnreachable):
            cache.get_key_for_kid(kid)
    assert cache._keys_by_kid == {}
    assert cache._fetched_at == 0.0
