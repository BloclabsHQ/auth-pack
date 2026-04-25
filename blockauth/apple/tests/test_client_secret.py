"""AppleClientSecretBuilder tests.

Strategy: generate a real ES256 keypair (P-256), point the builder at the PEM,
call build(), then verify the resulting JWT with the public key. We do not stub
PyJWT — the cryptography is exercised end-to-end.
"""

import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.test import override_settings

from blockauth.apple.client_secret import AppleClientSecretBuilder
from blockauth.apple.exceptions import AppleClientSecretConfigError


@pytest.fixture
def es256_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


@pytest.fixture
def configured_settings(es256_keypair):
    private_pem, _ = es256_keypair
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_TEAM_ID": "TEAMID1234",
            "APPLE_KEY_ID": "KEYID5678",
            "APPLE_PRIVATE_KEY_PEM": private_pem,
            "APPLE_SERVICES_ID": "com.example.services",
        }
    ):
        yield


def test_build_returns_es256_jwt_with_required_claims(configured_settings, es256_keypair):
    _, public_pem = es256_keypair
    builder = AppleClientSecretBuilder()
    secret = builder.build()

    header = pyjwt.get_unverified_header(secret)
    assert header["alg"] == "ES256"
    assert header["kid"] == "KEYID5678"

    claims = pyjwt.decode(secret, public_pem, algorithms=["ES256"], audience="https://appleid.apple.com")
    assert claims["iss"] == "TEAMID1234"
    assert claims["sub"] == "com.example.services"
    assert claims["aud"] == "https://appleid.apple.com"
    assert claims["exp"] - claims["iat"] <= 6 * 30 * 24 * 3600


def test_cached_secret_reused_within_window(configured_settings):
    builder = AppleClientSecretBuilder()
    a = builder.build()
    b = builder.build()
    assert a == b


def test_cache_rebuilt_when_near_expiry(configured_settings):
    builder = AppleClientSecretBuilder()
    a = builder.build()
    builder._cached_secret_expires_at = time.time() - 10  # type: ignore[attr-defined]
    b = builder.build()
    assert a != b


def test_missing_team_id_raises():
    with override_settings(BLOCK_AUTH_SETTINGS={"APPLE_TEAM_ID": None, "APPLE_KEY_ID": "k", "APPLE_PRIVATE_KEY_PEM": "x", "APPLE_SERVICES_ID": "s"}):
        with pytest.raises(AppleClientSecretConfigError):
            AppleClientSecretBuilder().build()
