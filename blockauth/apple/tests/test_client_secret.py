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

from blockauth.apple.client_secret import (
    CLIENT_SECRET_LIFETIME_SECONDS,
    AppleClientSecretBuilder,
    apple_client_secret_builder,
)
from blockauth.apple.exceptions import AppleClientSecretConfigError


@pytest.fixture
def es256_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
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
    # Tight assertion — must equal the configured 5-hour lifetime, not just be
    # under Apple's 6-month max. Catches accidental lifetime bumps.
    assert claims["exp"] - claims["iat"] == CLIENT_SECRET_LIFETIME_SECONDS


def test_build_can_use_explicit_client_id_for_native_app_ids(configured_settings, es256_keypair):
    _, public_pem = es256_keypair
    builder = AppleClientSecretBuilder()
    secret = builder.build(client_id="com.example.app")

    claims = pyjwt.decode(secret, public_pem, algorithms=["ES256"], audience="https://appleid.apple.com")
    assert claims["sub"] == "com.example.app"


def test_cached_secret_reused_within_window(configured_settings):
    builder = AppleClientSecretBuilder()
    a = builder.build()
    b = builder.build()
    assert a == b


def test_cache_rebuilds_for_different_client_id(configured_settings):
    builder = AppleClientSecretBuilder()
    service_secret = builder.build()
    app_secret = builder.build(client_id="com.example.app")
    assert service_secret != app_secret


def test_cache_rebuilt_when_near_expiry(configured_settings):
    builder = AppleClientSecretBuilder()
    a = builder.build()
    builder._cached_secret_expires_at = time.time() - 10  # type: ignore[attr-defined]
    b = builder.build()
    assert a != b


def test_missing_team_id_raises():
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_TEAM_ID": None,
            "APPLE_KEY_ID": "k",
            "APPLE_PRIVATE_KEY_PEM": "x",
            "APPLE_SERVICES_ID": "s",
        }
    ):
        with pytest.raises(AppleClientSecretConfigError):
            AppleClientSecretBuilder().build()


def test_private_key_path_branch_works(es256_keypair, tmp_path):
    """APPLE_PRIVATE_KEY_PATH must be read from disk when APPLE_PRIVATE_KEY_PEM is absent."""
    private_pem, public_pem = es256_keypair
    p8_path = tmp_path / "AuthKey_KEYID5678.p8"
    p8_path.write_text(private_pem, encoding="utf-8")

    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_TEAM_ID": "TEAMID1234",
            "APPLE_KEY_ID": "KEYID5678",
            "APPLE_PRIVATE_KEY_PATH": str(p8_path),
            "APPLE_SERVICES_ID": "com.example.services",
        }
    ):
        builder = AppleClientSecretBuilder()
        secret = builder.build()

    claims = pyjwt.decode(secret, public_pem, algorithms=["ES256"], audience="https://appleid.apple.com")
    assert claims["iss"] == "TEAMID1234"


def test_private_key_path_missing_raises_config_error(tmp_path):
    """A configured but non-existent APPLE_PRIVATE_KEY_PATH raises AppleClientSecretConfigError,
    not a raw FileNotFoundError that callers wouldn't know to catch."""
    nonexistent = tmp_path / "does_not_exist.p8"
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_TEAM_ID": "TEAMID1234",
            "APPLE_KEY_ID": "KEYID5678",
            "APPLE_PRIVATE_KEY_PATH": str(nonexistent),
            "APPLE_SERVICES_ID": "com.example.services",
        }
    ):
        with pytest.raises(AppleClientSecretConfigError):
            AppleClientSecretBuilder().build()


def test_module_singleton_is_an_instance():
    """The module-level singleton exposes the same API; views should import this
    instead of instantiating per-request so the in-process cache is meaningful."""
    assert isinstance(apple_client_secret_builder, AppleClientSecretBuilder)
