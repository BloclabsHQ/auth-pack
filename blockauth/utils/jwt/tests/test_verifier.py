"""End-to-end tests for OIDCTokenVerifier.

Generates real RS256 tokens with the session RSA keypair, stubs JWKS HTTP, and
asserts each failure mode raises the corresponding subclass of
OIDCVerificationError.
"""

import base64
import json
import secrets
import time
from unittest.mock import MagicMock, patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from blockauth.utils.jwt.exceptions import (
    AlgorithmNotAllowed,
    AudienceMismatch,
    IssuerMismatch,
    NonceMismatch,
    RequiredClaimMissing,
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
        {
            "iss": "https://accounts.google.com",
            "aud": "123-web.apps.googleusercontent.com",
            "sub": "user-1",
            "email": "u@example.com",
        }
    )
    verifier = OIDCTokenVerifier(google_config)
    claims = verifier.verify(token, expected_nonce=None)
    assert claims["sub"] == "user-1"


def test_issuer_mismatch_raises(google_config, build_id_token, patch_requests_get):
    token = build_id_token({"iss": "https://evil.example", "aud": "123-web.apps.googleusercontent.com", "sub": "x"})
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
    token = pyjwt.encode(
        {"iss": "https://accounts.google.com"},
        secrets.token_bytes(32),
        algorithm="HS256",
    )
    verifier = OIDCTokenVerifier(google_config)
    with pytest.raises(AlgorithmNotAllowed):
        verifier.verify(token, expected_nonce=None)


def test_signature_invalid_raises(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {"iss": "https://accounts.google.com", "aud": "123-web.apps.googleusercontent.com", "sub": "x"}
    )
    # Tamper the payload (middle segment): one byte flip changes the signing
    # input deterministically, so the signature can no longer match.
    header_b64, payload_b64, signature_b64 = token.split(".")
    tampered_payload = "A" + payload_b64[1:] if payload_b64[0] != "A" else "B" + payload_b64[1:]
    tampered = f"{header_b64}.{tampered_payload}.{signature_b64}"
    verifier = OIDCTokenVerifier(google_config)
    with pytest.raises(SignatureInvalid):
        verifier.verify(tampered, expected_nonce=None)


def test_aud_as_list_accepted(google_config, build_id_token, patch_requests_get):
    token = build_id_token(
        {
            "iss": "https://accounts.google.com",
            "aud": ["123-web.apps.googleusercontent.com", "other"],
            "sub": "x",
            "email": "u@example.com",
        }
    )
    verifier = OIDCTokenVerifier(google_config)
    claims = verifier.verify(token, expected_nonce=None)
    assert isinstance(claims["aud"], list)
    assert claims["aud"] == ["123-web.apps.googleusercontent.com", "other"]


# ---------------------------------------------------------------------------
# OIDCVerifierConfig validation (Mn-7)
# ---------------------------------------------------------------------------


def test_config_rejects_empty_audiences():
    with pytest.raises(ValueError):
        OIDCVerifierConfig(
            issuer="https://example.com",
            jwks_uri="https://example.com/jwks",
            audiences=(),
            algorithms=("RS256",),
        )


def test_config_rejects_empty_algorithms():
    with pytest.raises(ValueError):
        OIDCVerifierConfig(
            issuer="https://example.com",
            jwks_uri="https://example.com/jwks",
            audiences=("aud",),
            algorithms=(),
        )


def test_config_rejects_negative_leeway():
    with pytest.raises(ValueError):
        OIDCVerifierConfig(
            issuer="https://example.com",
            jwks_uri="https://example.com/jwks",
            audiences=("aud",),
            algorithms=("RS256",),
            leeway_seconds=-1,
        )


# ---------------------------------------------------------------------------
# require_email_claim enforcement (R-9)
# ---------------------------------------------------------------------------


def test_require_email_claim_missing_raises(google_config, build_id_token, patch_requests_get):
    """When require_email_claim=True, an id_token without `email` must be rejected."""
    token = build_id_token(
        {
            "iss": "https://accounts.google.com",
            "aud": "123-web.apps.googleusercontent.com",
            "sub": "user-2",
        }  # note: no "email"
    )
    verifier = OIDCTokenVerifier(google_config)
    with pytest.raises(RequiredClaimMissing):
        verifier.verify(token, expected_nonce=None)


# ---------------------------------------------------------------------------
# I-1: algorithm allowlist controls JWK dispatch (real ES256 keypair)
# ---------------------------------------------------------------------------


def test_verify_es256_token_with_ec_jwks_succeeds():
    """Algorithm allowlist controls key dispatch — ES256 path uses ECAlgorithm.from_jwk."""
    # Generate a real EC P-256 keypair
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    # Build the JWK manually per RFC 7518 §6.2 (EC keys: x, y, crv).
    public_numbers = private_key.public_key().public_numbers()
    # P-256 coordinates are 32 bytes, big-endian, unpadded base64url.
    x_bytes = public_numbers.x.to_bytes(32, "big")
    y_bytes = public_numbers.y.to_bytes(32, "big")
    kid = "ec-test-kid-" + secrets.token_hex(4)
    jwk = {
        "kty": "EC",
        "use": "sig",
        "alg": "ES256",
        "crv": "P-256",
        "kid": kid,
        "x": base64.urlsafe_b64encode(x_bytes).rstrip(b"=").decode(),
        "y": base64.urlsafe_b64encode(y_bytes).rstrip(b"=").decode(),
    }
    jwks_payload_bytes = json.dumps({"keys": [jwk]}).encode()

    config = OIDCVerifierConfig(
        issuer="https://example-ec.test",
        jwks_uri="https://example-ec.test/jwks",
        audiences=("ec-aud",),
        algorithms=("ES256",),
        require_email_claim=False,
    )

    token = pyjwt.encode(
        {
            "iss": "https://example-ec.test",
            "aud": "ec-aud",
            "sub": "ec-user",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
        },
        private_pem,
        algorithm="ES256",
        headers={"kid": kid},
    )

    response = MagicMock(status_code=200, content=jwks_payload_bytes)
    response.json.return_value = json.loads(jwks_payload_bytes.decode())
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=response):
        verifier = OIDCTokenVerifier(config)
        claims = verifier.verify(token, expected_nonce=None)

    assert claims["sub"] == "ec-user"
