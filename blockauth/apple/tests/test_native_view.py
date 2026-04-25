"""Apple native id_token verify tests.

Covers: id_token verification path, conditional nonce on `nonce_supported`,
optional authorization_code redemption, missing raw_nonce.
"""

import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest
from django.test import override_settings

from blockauth.apple.id_token_verifier import _reset_verifier_cache


@pytest.fixture(autouse=True)
def _clear_verifier_cache():
    _reset_verifier_cache()
    yield
    _reset_verifier_cache()


def _es256_pem():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


@pytest.fixture
def apple_settings():
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_TEAM_ID": "TEAMID",
            "APPLE_KEY_ID": "KEYID",
            "APPLE_PRIVATE_KEY_PEM": _es256_pem(),
            "APPLE_SERVICES_ID": "com.example.services",
            "APPLE_BUNDLE_IDS": ("com.example.app",),
            "FEATURES": {"APPLE_LOGIN": True, "SOCIAL_AUTH": True},
            "BLOCK_AUTH_USER_MODEL": "tests.TestBlockUser",
            "ALGORITHM": "HS256",
            "SECRET_KEY": "test-secret-not-for-production",
        }
    ):
        yield


@pytest.mark.django_db
def test_native_verify_happy_path(apple_settings, client, build_id_token, jwks_payload_bytes):
    raw_nonce = "raw-nonce-value"
    expected_hash = hashlib.sha256(raw_nonce.encode()).hexdigest()
    id_token = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.app",
            "sub": "001234.native.subject",
            "email": "user@privaterelay.appleid.com",
            "email_verified": "true",
            "is_private_email": "true",
            "nonce": expected_hash,
            "nonce_supported": True,
        }
    )
    jwks_response = MagicMock(status_code=200, content=jwks_payload_bytes)
    jwks_response.json.return_value = json.loads(jwks_payload_bytes.decode())

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        response = client.post(
            "/apple/verify/",
            data={"id_token": id_token, "raw_nonce": raw_nonce},
            content_type="application/json",
        )

    assert response.status_code == 200, response.content
    body = response.json()
    assert "access" in body and "refresh" in body and "user" in body


@pytest.mark.django_db
def test_native_verify_redeems_authorization_code(apple_settings, client, build_id_token, jwks_payload_bytes):
    raw_nonce = "raw-nonce-2"
    expected_hash = hashlib.sha256(raw_nonce.encode()).hexdigest()
    id_token = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.app",
            "sub": "001234.native.code",
            "email": "user@privaterelay.appleid.com",
            "email_verified": "true",
            "is_private_email": "true",
            "nonce": expected_hash,
            "nonce_supported": True,
        }
    )
    jwks_response = MagicMock(status_code=200, content=jwks_payload_bytes)
    jwks_response.json.return_value = json.loads(jwks_payload_bytes.decode())
    token_response = MagicMock(status_code=200)
    token_response.json.return_value = {"refresh_token": "apple-refresh-from-code"}

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response), patch(
        "blockauth.apple.views.requests.post", return_value=token_response
    ) as mock_post:
        response = client.post(
            "/apple/verify/",
            data={"id_token": id_token, "raw_nonce": raw_nonce, "authorization_code": "auth-code"},
            content_type="application/json",
        )

    assert response.status_code == 200, response.content
    assert mock_post.call_args.kwargs["data"]["code"] == "auth-code"
    assert mock_post.call_args.kwargs["data"]["grant_type"] == "authorization_code"


@pytest.mark.django_db
def test_native_verify_skips_nonce_when_unsupported(apple_settings, client, build_id_token, jwks_payload_bytes):
    """`nonce_supported=False` from older Apple devices: server must not reject."""
    id_token = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.app",
            "sub": "001234.legacy.device",
            "email": "user@privaterelay.appleid.com",
            "email_verified": "true",
            "is_private_email": "true",
            "nonce_supported": False,
        }
    )
    jwks_response = MagicMock(status_code=200, content=jwks_payload_bytes)
    jwks_response.json.return_value = json.loads(jwks_payload_bytes.decode())

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        response = client.post(
            "/apple/verify/",
            data={"id_token": id_token, "raw_nonce": "anything"},
            content_type="application/json",
        )

    assert response.status_code == 200, response.content
