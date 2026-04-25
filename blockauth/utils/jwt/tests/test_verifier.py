"""End-to-end tests for OIDCTokenVerifier.

Generates real RS256 tokens with the session RSA keypair, stubs JWKS HTTP, and
asserts each failure mode raises the corresponding subclass of
OIDCVerificationError.
"""

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from blockauth.utils.jwt.exceptions import (
    AlgorithmNotAllowed,
    AudienceMismatch,
    IssuerMismatch,
    NonceMismatch,
    SignatureInvalid,
    TokenExpired,
)
from blockauth.utils.jwt.verifier import OIDCTokenVerifier, OIDCVerifierConfig


@pytest.fixture
def google_config():
    return OIDCVerifierConfig(
        issuer="https://accounts.google.com",
        jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
        audiences=("123-web.apps.googleusercontent.com",),
        algorithms=("RS256",),
    )


@pytest.fixture
def patch_requests_get(jwks_payload_bytes):
    response = MagicMock(status_code=200, content=jwks_payload_bytes)
    response.json.return_value = json.loads(jwks_payload_bytes.decode())
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=response):
        yield


def test_verify_ok(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {"iss": "https://accounts.google.com", "aud": "123-web.apps.googleusercontent.com", "sub": "user-1", "email": "u@example.com"}
    )
    verifier = OIDCTokenVerifier(google_config)
    claims = verifier.verify(token, expected_nonce=None)
    assert claims["sub"] == "user-1"


def test_issuer_mismatch_raises(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {"iss": "https://evil.example", "aud": "123-web.apps.googleusercontent.com", "sub": "x"}
    )
    verifier = OIDCTokenVerifier(google_config)
    with pytest.raises(IssuerMismatch):
        verifier.verify(token, expected_nonce=None)


def test_audience_mismatch_raises(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {"iss": "https://accounts.google.com", "aud": "different.apps.googleusercontent.com", "sub": "x"}
    )
    verifier = OIDCTokenVerifier(google_config)
    with pytest.raises(AudienceMismatch):
        verifier.verify(token, expected_nonce=None)


def test_expired_raises(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {
            "iss": "https://accounts.google.com",
            "aud": "123-web.apps.googleusercontent.com",
            "sub": "x",
            "iat": int(time.time()) - 7200,
            "exp": int(time.time()) - 3600,
        }
    )
    verifier = OIDCTokenVerifier(google_config)
    with pytest.raises(TokenExpired):
        verifier.verify(token, expected_nonce=None)


def test_nonce_mismatch_raises(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {
            "iss": "https://accounts.google.com",
            "aud": "123-web.apps.googleusercontent.com",
            "sub": "x",
            "nonce": "AAAA",
        }
    )
    verifier = OIDCTokenVerifier(google_config)
    with pytest.raises(NonceMismatch):
        verifier.verify(token, expected_nonce="BBBB")


def test_algorithm_not_allowed_raises(google_config, patch_requests_get):
    import jwt as pyjwt

    token = pyjwt.encode({"iss": "https://accounts.google.com"}, "shared-secret", algorithm="HS256")
    verifier = OIDCTokenVerifier(google_config)
    with pytest.raises(AlgorithmNotAllowed):
        verifier.verify(token, expected_nonce=None)


def test_signature_invalid_raises(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {"iss": "https://accounts.google.com", "aud": "123-web.apps.googleusercontent.com", "sub": "x"}
    )
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    verifier = OIDCTokenVerifier(google_config)
    with pytest.raises(SignatureInvalid):
        verifier.verify(tampered, expected_nonce=None)


def test_aud_as_list_accepted(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {
            "iss": "https://accounts.google.com",
            "aud": ["123-web.apps.googleusercontent.com", "other"],
            "sub": "x",
        }
    )
    verifier = OIDCTokenVerifier(google_config)
    claims = verifier.verify(token, expected_nonce=None)
    assert "123-web.apps.googleusercontent.com" in (claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]])
