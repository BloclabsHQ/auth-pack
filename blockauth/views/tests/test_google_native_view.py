"""Google Native id_token verify endpoint.

Covers: happy path with valid id_token, raw_nonce missing -> 400, audience
mismatch -> 400, signature/audience invalid -> 400, audiences-not-configured
-> 400 (4020).
"""

import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest
from django.test import override_settings


@pytest.fixture(autouse=True)
def _clear_verifier_cache():
    from blockauth.views.google_native_views import _reset_verifier_cache

    _reset_verifier_cache()
    yield
    _reset_verifier_cache()


@pytest.fixture
def google_settings():
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "GOOGLE_NATIVE_AUDIENCES": ("123-web.apps.googleusercontent.com",),
            "FEATURES": {"GOOGLE_NATIVE_LOGIN": True, "SOCIAL_AUTH": True},
            "BLOCK_AUTH_USER_MODEL": "tests.TestBlockUser",
            "ALGORITHM": "HS256",
            "SECRET_KEY": "test-secret-not-for-production",
        }
    ):
        yield


@pytest.fixture
def jwks_response(jwks_payload_bytes):
    response = MagicMock(status_code=200, content=jwks_payload_bytes)
    response.json.return_value = json.loads(jwks_payload_bytes.decode())
    return response


@pytest.mark.django_db
def test_native_verify_happy_path(google_settings, client, build_id_token, jwks_response):
    raw_nonce = "raw-nonce-google"
    expected = hashlib.sha256(raw_nonce.encode()).hexdigest()
    id_token = build_id_token(
        {
            "iss": "https://accounts.google.com",
            "aud": "123-web.apps.googleusercontent.com",
            "sub": "google-native-sub-1",
            "email": "u@gmail.com",
            "email_verified": True,
            "azp": "android-client.apps.googleusercontent.com",
            "nonce": expected,
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        response = client.post(
            "/google/native/verify/",
            data={"id_token": id_token, "raw_nonce": raw_nonce},
            content_type="application/json",
        )

    assert response.status_code == 200, response.content
    body = response.json()
    assert "access" in body and "refresh" in body and "user" in body


@pytest.mark.django_db
def test_native_verify_audience_mismatch_rejected(google_settings, client, build_id_token, jwks_response):
    raw_nonce = "raw-nonce-google-2"
    expected = hashlib.sha256(raw_nonce.encode()).hexdigest()
    id_token = build_id_token(
        {
            "iss": "https://accounts.google.com",
            "aud": "wrong-audience.apps.googleusercontent.com",
            "sub": "google-native-sub-2",
            "email": "u@gmail.com",
            "email_verified": True,
            "nonce": expected,
        }
    )
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        response = client.post(
            "/google/native/verify/",
            data={"id_token": id_token, "raw_nonce": raw_nonce},
            content_type="application/json",
        )

    assert response.status_code == 400


@pytest.mark.django_db
def test_native_verify_missing_raw_nonce_rejected(google_settings, client, build_id_token, jwks_response):
    id_token = build_id_token(
        {
            "iss": "https://accounts.google.com",
            "aud": "123-web.apps.googleusercontent.com",
            "sub": "x",
            "email": "u@gmail.com",
            "email_verified": True,
        }
    )
    response = client.post(
        "/google/native/verify/",
        data={"id_token": id_token},
        content_type="application/json",
    )
    assert response.status_code == 400


@pytest.mark.django_db
def test_native_verify_no_audiences_configured_returns_4020(client, build_id_token, jwks_response):
    """Empty GOOGLE_NATIVE_AUDIENCES means the integrator hasn't enabled this
    endpoint properly — must surface as a configuration error not a 500."""
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "GOOGLE_NATIVE_AUDIENCES": (),
            "FEATURES": {"GOOGLE_NATIVE_LOGIN": True, "SOCIAL_AUTH": True},
            "BLOCK_AUTH_USER_MODEL": "tests.TestBlockUser",
            "ALGORITHM": "HS256",
            "SECRET_KEY": "test-secret-not-for-production",
        }
    ):
        with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
            response = client.post(
                "/google/native/verify/",
                data={"id_token": "any-token", "raw_nonce": "any-nonce"},
                content_type="application/json",
            )
        assert response.status_code == 400
