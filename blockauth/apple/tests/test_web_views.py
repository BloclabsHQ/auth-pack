"""Apple web flow tests — authorize redirect + form_post callback.

Stubs Apple's token endpoint (requests.post) and the JWKS fetch (requests.get)
to return values produced by the test RSA keypair. The id_token returned from
the stubbed token endpoint is built with `build_id_token` so signature
verification runs end-to-end against the test public key.
"""

import hashlib
import json
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from django.test import override_settings

from blockauth.apple.id_token_verifier import _reset_verifier_cache
from blockauth.apple.nonce import APPLE_NONCE_COOKIE_NAME
from blockauth.utils.oauth_state import OAUTH_PKCE_VERIFIER_COOKIE_NAME, OAUTH_STATE_COOKIE_NAME


@pytest.fixture(autouse=True)
def _clear_verifier_cache():
    _reset_verifier_cache()
    yield
    _reset_verifier_cache()


@pytest.fixture
def es256_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

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
def apple_settings(es256_keypair):
    private_pem, _ = es256_keypair
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_TEAM_ID": "TEAMID",
            "APPLE_KEY_ID": "KEYID",
            "APPLE_PRIVATE_KEY_PEM": private_pem,
            "APPLE_SERVICES_ID": "com.example.services",
            "APPLE_BUNDLE_IDS": ("com.example.app",),
            "APPLE_REDIRECT_URI": "https://callback.example.com/apple/callback/",
            "APPLE_CALLBACK_COOKIE_SAMESITE": "None",
            "FEATURES": {"APPLE_LOGIN": True, "SOCIAL_AUTH": True},
            "OAUTH_STATE_COOKIE_SECURE": True,
            "BLOCK_AUTH_USER_MODEL": "tests.TestBlockUser",
            "ALGORITHM": "HS256",
            "SECRET_KEY": "test-secret-not-for-production",
        }
    ):
        yield


@pytest.mark.django_db
def test_authorize_view_redirects_with_required_params(apple_settings, client):
    response = client.get("/apple/")
    assert response.status_code == 302
    parsed = urlparse(response["Location"])
    assert parsed.netloc == "appleid.apple.com"
    qs = parse_qs(parsed.query)
    assert qs["response_type"] == ["code"]
    assert qs["response_mode"] == ["form_post"]
    assert qs["scope"] == ["name email"]
    assert qs["client_id"] == ["com.example.services"]
    assert qs["redirect_uri"] == ["https://callback.example.com/apple/callback/"]
    assert qs["code_challenge_method"] == ["S256"]
    assert "state" in qs and "nonce" in qs and "code_challenge" in qs

    cookies = response.cookies
    assert OAUTH_STATE_COOKIE_NAME in cookies
    assert OAUTH_PKCE_VERIFIER_COOKIE_NAME in cookies
    assert APPLE_NONCE_COOKIE_NAME in cookies

    raw_nonce = cookies[APPLE_NONCE_COOKIE_NAME].value
    expected_nonce_hash = hashlib.sha256(raw_nonce.encode()).hexdigest()
    assert qs["nonce"] == [expected_nonce_hash]


@pytest.mark.django_db
def test_callback_full_flow(apple_settings, client, build_id_token, jwks_payload_bytes):
    init_response = client.get("/apple/")
    state_value = init_response.cookies[OAUTH_STATE_COOKIE_NAME].value
    raw_nonce = init_response.cookies[APPLE_NONCE_COOKIE_NAME].value
    pkce_verifier = init_response.cookies[OAUTH_PKCE_VERIFIER_COOKIE_NAME].value
    expected_nonce_hash = hashlib.sha256(raw_nonce.encode()).hexdigest()

    apple_id_token = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "001234.unique.subject",
            "email": "user@privaterelay.appleid.com",
            "email_verified": "true",
            "is_private_email": "true",
            "nonce": expected_nonce_hash,
            "nonce_supported": True,
        }
    )
    token_response = MagicMock(status_code=200)
    token_response.json.return_value = {
        "access_token": "apple-access",
        "refresh_token": "apple-refresh",
        "id_token": apple_id_token,
        "token_type": "Bearer",
        "expires_in": 3600,
    }
    jwks_response = MagicMock(status_code=200, content=jwks_payload_bytes)
    jwks_response.json.return_value = json.loads(jwks_payload_bytes.decode())

    with (
        patch("blockauth.apple.views.requests.post", return_value=token_response) as mock_post,
        patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response),
    ):
        callback = client.post(
            "/apple/callback/",
            data={"code": "real-auth-code", "state": state_value},
        )

    assert callback.status_code == 200
    body = callback.json()
    assert "access" in body and "refresh" in body and "user" in body
    assert mock_post.call_args.kwargs["data"]["code"] == "real-auth-code"
    assert mock_post.call_args.kwargs["data"]["code_verifier"] == pkce_verifier
    assert mock_post.call_args.kwargs["data"]["grant_type"] == "authorization_code"
    assert mock_post.call_args.kwargs["timeout"] == (3.05, 10)


@pytest.mark.django_db
def test_callback_state_mismatch_raises(apple_settings, client):
    """Cookie state and form-post state must match; mismatch is a 400."""
    client.get("/apple/")
    callback = client.post(
        "/apple/callback/",
        data={"code": "real-auth-code", "state": "wrong-state"},
    )
    assert callback.status_code == 400


@pytest.mark.django_db
def test_callback_pkce_cookie_missing_raises(apple_settings, client):
    """PKCE verifier cookie is required; absence is a 400 (code 4051)."""
    init = client.get("/apple/")
    state_value = init.cookies[OAUTH_STATE_COOKIE_NAME].value
    # Simulate a callback request that drops the PKCE cookie (e.g. cookie loss).
    client.cookies.pop(OAUTH_PKCE_VERIFIER_COOKIE_NAME, None)
    callback = client.post(
        "/apple/callback/",
        data={"code": "real-auth-code", "state": state_value},
    )
    assert callback.status_code == 400


@pytest.mark.django_db
def test_callback_token_exchange_4xx_returns_4053(apple_settings, client):
    """Apple /auth/token returning 4xx must map to ValidationError (HTTP 400),
    not escape as HTTP 500."""
    init = client.get("/apple/")
    state_value = init.cookies[OAUTH_STATE_COOKIE_NAME].value

    failing_response = MagicMock(status_code=400, text="bad code")
    failing_response.json.return_value = {"error": "invalid_grant"}
    with patch("blockauth.apple.views.requests.post", return_value=failing_response):
        callback = client.post(
            "/apple/callback/",
            data={"code": "real-auth-code", "state": state_value},
        )
    assert callback.status_code == 400  # ValidationError -> 400


@pytest.mark.django_db
def test_callback_token_endpoint_unreachable_returns_4053(apple_settings, client):
    """Network failures during token exchange must map to ValidationError,
    not bubble up as a raw RequestException → HTTP 500."""
    import requests as _requests

    init = client.get("/apple/")
    state_value = init.cookies[OAUTH_STATE_COOKIE_NAME].value

    with patch(
        "blockauth.apple.views.requests.post",
        side_effect=_requests.exceptions.ConnectionError("dns failure"),
    ):
        callback = client.post(
            "/apple/callback/",
            data={"code": "real-auth-code", "state": state_value},
        )
    assert callback.status_code == 400  # ValidationError -> 400


@pytest.mark.django_db
def test_callback_clears_cookies_on_error(apple_settings, client):
    """Failed callback must clear state/pkce/nonce cookies (not just on success)
    so a retry doesn't reuse stale values."""
    client.get("/apple/")

    callback = client.post(
        "/apple/callback/",
        data={"code": "real-auth-code", "state": "wrong-state"},  # mismatch -> 400
    )

    # All 3 cookies must be cleared on the error response.
    assert callback.status_code == 400
    assert callback.cookies[OAUTH_STATE_COOKIE_NAME]["max-age"] == 0
    assert callback.cookies[OAUTH_PKCE_VERIFIER_COOKIE_NAME]["max-age"] == 0
    assert callback.cookies[APPLE_NONCE_COOKIE_NAME]["max-age"] == 0


# ---------------------------------------------------------------------------
# build_success_response override hook
# ---------------------------------------------------------------------------
#
# Google, Facebook, LinkedIn, and Google-native already expose
# build_success_response(request, result) so integrators can swap the success
# response shape (e.g. BFF cookie redirect) without re-implementing the auth
# flow. These tests pin the contract for Apple's web callback so fabric-auth
# can plug in alongside the other providers.


class _StubBlockUser:
    """Minimal stand-in for the BlockUser-shaped object that
    `build_user_payload` reads. Keeps the hook unit tests off the DB.
    """

    def __init__(self, user_id: str, email: str):
        self.id = user_id
        self.email = email
        self.is_verified = True
        self.is_active = True
        self.wallet_address = None
        self.date_joined = None


def test_web_callback_view_default_build_success_response_returns_auth_state_json():
    """Default hook impl returns the existing AuthStateResponseSerializer JSON shape."""
    from blockauth.apple.views import AppleWebCallbackView
    from blockauth.utils.social import SocialLoginResult

    result = SocialLoginResult(
        user=_StubBlockUser("user-1", "apple-user@example.com"),
        access_token="access-token-jwt",
        refresh_token="refresh-token-jwt",
        created=False,
    )

    response = AppleWebCallbackView().build_success_response(request=None, result=result)

    assert response.status_code == 200
    assert response.data["access"] == "access-token-jwt"
    assert response.data["refresh"] == "refresh-token-jwt"
    assert response.data["user"]["id"] == "user-1"
    assert response.data["user"]["email"] == "apple-user@example.com"


def test_web_callback_view_subclass_can_override_build_success_response():
    """A subclass override is reached at the final response builder call site."""
    from rest_framework.response import Response
    from blockauth.apple.views import AppleWebCallbackView
    from blockauth.utils.social import SocialLoginResult

    class _SwapResponse(AppleWebCallbackView):
        def build_success_response(self, request, result):
            return Response(data={"swapped": True}, status=201)

    result = SocialLoginResult(
        user=_StubBlockUser("user-2", "apple-user-2@example.com"),
        access_token="a",
        refresh_token="r",
        created=True,
    )

    response = _SwapResponse().build_success_response(request=None, result=result)

    assert response.status_code == 201
    assert response.data == {"swapped": True}
