"""Google OAuth web flow.

Refactored from the previous email-based matching path to use:
  - PKCE (RFC 7636) on the authorization request and token exchange.
  - Nonce: random raw value stored in HttpOnly cookie at /google/, sha256 of
    raw value sent as the `nonce` parameter, and compared to the id_token's
    `nonce` claim on callback.
  - id_token verification via OIDCTokenVerifier with Google's JWKS — replaces
    the previous `userinfo` HTTP call.
  - SocialIdentity link via `(provider="google", subject=sub)`. Falls back to
    linking by Google-authoritative email (gmail.com or `hd` claim) per
    `AccountLinkingPolicy`.

Verifier instances are cached at module scope so the JWKSCache TTL is
meaningful across requests; tests reset via `_reset_verifier_cache()`.
"""

import hashlib
import logging
import secrets
import threading
import urllib.parse

import requests
from django.conf import settings
from django.shortcuts import redirect
from drf_spectacular.utils import extend_schema
from rest_framework import status as drf_status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.docs.social_auth_docs import google_auth_callback_schema, google_auth_login_schema
from blockauth.schemas.examples.social_auth import (
    social_authorization_code,
    social_invalid_auth_config,
)
from blockauth.serializers.user_account_serializers import AuthStateResponseSerializer
from blockauth.social.exceptions import SocialIdentityConflictError  # noqa: F401  intentional: documented as the propagating-409
from blockauth.social.service import SocialIdentityService
from blockauth.utils.auth_state import build_user_payload
from blockauth.utils.jwt import (
    JWKSCache,
    OIDCTokenVerifier,
    OIDCVerificationError,
    OIDCVerifierConfig,
)
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.oauth_state import (
    OAUTH_STATE_COOKIE_NAME,
    clear_pkce_verifier_cookie,
    clear_state_cookie,
    generate_state,
    read_pkce_verifier_cookie,
    set_pkce_verifier_cookie,
    set_state_cookie,
    verify_state,
)
from blockauth.utils.pkce import generate_pkce_pair
from blockauth.utils.social import social_login_data

logger = logging.getLogger(__name__)

GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_ISSUER = "https://accounts.google.com"
GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_NONCE_COOKIE_NAME = "blockauth_google_nonce"
GOOGLE_NONCE_BYTES = 32


def _block_setting(key, default=None):
    """Read BLOCK_AUTH_SETTINGS at runtime so override_settings propagates.

    `get_config` reads through DRF's APISettings, which caches keyed-attribute
    access; that cache is not invalidated by Django's `override_settings`.
    Reading `settings.BLOCK_AUTH_SETTINGS` directly here matches the pattern
    used by `blockauth.apple._settings.apple_setting` and
    `blockauth.views.google_native_views._block_setting` and keeps tests
    deterministic across `override_settings` blocks.
    """
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    return block_settings.get(key, default)


def _provider_setting(provider_key, key, default=None):
    """Read AUTH_PROVIDERS-nested or top-level GOOGLE_* settings.

    Newer integrations declare per-provider config under
    `BLOCK_AUTH_SETTINGS["AUTH_PROVIDERS"]["GOOGLE"]`; legacy integrations
    use flat top-level `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` /
    `GOOGLE_REDIRECT_URI`. Resolution order is nested first (the configured
    block beats the legacy alias when both are set), with top-level as the
    fallback so existing deployments keep working.
    """
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    providers = block_settings.get("AUTH_PROVIDERS", {}) or {}
    nested = providers.get(provider_key, {}) or {}
    if key in nested:
        return nested[key]
    return block_settings.get(f"GOOGLE_{key}", default)


def _google_client_id():
    return _provider_setting("GOOGLE", "CLIENT_ID") or _block_setting("GOOGLE_CLIENT_ID")


def _google_client_secret():
    return _provider_setting("GOOGLE", "CLIENT_SECRET") or _block_setting("GOOGLE_CLIENT_SECRET")


def _google_redirect_uri():
    return _provider_setting("GOOGLE", "REDIRECT_URI") or _block_setting("GOOGLE_REDIRECT_URI")


# Module-level verifier cache keyed by the audiences tuple. Survives across
# requests so the JWKSCache TTL is meaningful — without this, every web
# callback would re-fetch Google's JWKS endpoint. The double-checked locking
# pattern under `_verifier_cache_lock` ensures concurrent first requests
# don't race to instantiate duplicate verifiers. Mirrors the Phase 6
# hardening pattern used by `google_native_views._verifier_cache`.
_verifier_cache: dict[tuple[str, ...], OIDCTokenVerifier] = {}
_verifier_cache_lock = threading.Lock()


def _reset_verifier_cache() -> None:
    """Tests use this between override_settings blocks so a stale verifier
    from a prior config doesn't leak across cases."""
    with _verifier_cache_lock:
        _verifier_cache.clear()


def _build_verifier() -> OIDCTokenVerifier:
    client_id = _google_client_id()
    if not client_id:
        raise ValidationError(social_invalid_auth_config.value, 4020)
    audiences = (client_id,)

    cached = _verifier_cache.get(audiences)
    if cached is not None:
        return cached

    with _verifier_cache_lock:
        cached = _verifier_cache.get(audiences)
        if cached is not None:
            return cached
        cache_ttl = int(_block_setting("OIDC_JWKS_CACHE_TTL_SECONDS") or 3600)
        leeway = int(_block_setting("OIDC_VERIFIER_LEEWAY_SECONDS") or 60)
        config = OIDCVerifierConfig(
            issuer=GOOGLE_ISSUER,
            jwks_uri=GOOGLE_JWKS_URI,
            audiences=audiences,
            algorithms=("RS256",),
            leeway_seconds=leeway,
        )
        verifier = OIDCTokenVerifier(
            config,
            jwks_cache=JWKSCache(GOOGLE_JWKS_URI, cache_ttl_seconds=cache_ttl),
        )
        _verifier_cache[audiences] = verifier
        return verifier


class GoogleAuthLoginView(APIView):
    """Initiate Google OAuth — emit state, raw nonce, and PKCE pair."""

    permission_classes = (AllowAny,)
    authentication_classes = ()

    @extend_schema(**google_auth_login_schema)
    def get(self, request):
        client_id = _google_client_id()
        redirect_uri = _google_redirect_uri()
        if not client_id or not redirect_uri:
            raise ValidationError(social_invalid_auth_config.value, 4020)

        state = generate_state()
        raw_nonce = secrets.token_urlsafe(GOOGLE_NONCE_BYTES)
        hashed_nonce = hashlib.sha256(raw_nonce.encode("utf-8")).hexdigest()
        pair = generate_pkce_pair()

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "nonce": hashed_nonce,
            "code_challenge": pair.challenge,
            "code_challenge_method": "S256",
            "access_type": "online",
            "prompt": "select_account",
        }
        url = f"{GOOGLE_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

        blockauth_logger.info(
            "google.web.authorize_started",
            {"client_id_suffix": client_id[-6:]},
        )

        response = redirect(url)
        set_state_cookie(response, state)
        set_pkce_verifier_cookie(response, pair.verifier)
        # Raw nonce — kept HttpOnly so JS can't read it. Hashed value goes
        # to Google in the `nonce` query param; we re-hash on callback and
        # compare against the id_token's `nonce` claim.
        response.set_cookie(
            GOOGLE_NONCE_COOKIE_NAME,
            raw_nonce,
            max_age=600,
            httponly=True,
            secure=True,
            samesite="Lax",
        )
        return response


class GoogleAuthCallbackView(APIView):
    """Handle Google OAuth callback — verify state + PKCE + nonce + id_token.

    Subclass and override :meth:`build_success_response` to ship tokens via
    HttpOnly cookies + a 302 to the shell origin instead of the default JSON
    body (BFF pattern — fabric-auth#533).
    """

    permission_classes = (AllowAny,)
    authentication_classes = ()

    def build_success_response(self, request, result) -> Response:
        """Default: return the `{access, refresh, user}` JSON body.

        Integrator override (fabric-auth): set HttpOnly cookies carrying
        the JWTs and return a redirect to the shell origin, so tokens
        never reach JavaScript or the URL bar. The base implementation
        is kept for backwards compatibility and for deployments where
        the callback is consumed programmatically (e.g. mobile SDK).
        """
        serializer = AuthStateResponseSerializer(
            {
                "access": result.access_token,
                "refresh": result.refresh_token,
                "user": build_user_payload(result.user),
            }
        )
        return Response(data=serializer.data, status=drf_status.HTTP_200_OK)

    @extend_schema(**google_auth_callback_schema)
    def get(self, request):
        code = request.query_params.get("code")
        if not code:
            raise ValidationError(social_authorization_code.value, 4020)

        client_id = _google_client_id()
        client_secret = _google_client_secret()
        redirect_uri = _google_redirect_uri()
        if not all([client_id, client_secret, redirect_uri]):
            raise ValidationError(social_invalid_auth_config.value, 4020)

        # CSRF — must run BEFORE the token exchange so a probe cannot
        # consume a real authorization code.
        verify_state(request)

        pkce_verifier = read_pkce_verifier_cookie(request)
        if not pkce_verifier:
            raise ValidationError({"detail": "PKCE verifier missing"}, 4051)

        raw_nonce = request.COOKIES.get(GOOGLE_NONCE_COOKIE_NAME)
        if not raw_nonce:
            raise ValidationError({"detail": "OAuth nonce missing"}, 4061)
        expected_nonce = hashlib.sha256(raw_nonce.encode("utf-8")).hexdigest()

        try:
            token_response = requests.post(
                GOOGLE_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code",
                    "code_verifier": pkce_verifier,
                },
                timeout=10,
            )
        except requests.exceptions.RequestException as exc:
            blockauth_logger.warning(
                "google.web.token_endpoint_unreachable",
                {"error_class": exc.__class__.__name__},
            )
            raise ValidationError({"detail": "Google token endpoint unreachable"}, 4061) from exc

        if token_response.status_code != 200:
            blockauth_logger.error(
                "google.web.token_exchange_failed",
                {"status_code": token_response.status_code},
            )
            raise ValidationError({"detail": "Token exchange failed"}, 4061)

        token_payload = token_response.json()
        id_token = token_payload.get("id_token")
        if not id_token:
            raise ValidationError({"detail": "Google did not return id_token"}, 4061)

        try:
            claims = _build_verifier().verify(id_token, expected_nonce=expected_nonce)
        except OIDCVerificationError as exc:
            blockauth_logger.error(
                "google.web.id_token_verify_failed",
                {"error_class": exc.__class__.__name__},
            )
            raise ValidationError({"detail": str(exc)}, 4061)

        # SocialIdentityConflictError extends APIException with status_code=409;
        # let it propagate to the HTTP-semantic Conflict response rather than
        # demoting it to 400 by an extra ValidationError wrap. Phase 9
        # cross-flow consistency.
        user, _, _ = SocialIdentityService().upsert_and_link(
            provider="google",
            subject=str(claims["sub"]),
            email=claims.get("email"),
            email_verified=bool(claims.get("email_verified")),
            extra_claims={"hd": claims.get("hd")},
        )

        result = social_login_data(
            email=claims.get("email") or "",
            name=claims.get("name") or "",
            provider_data={
                "provider": "google",
                "user_info": claims,
                "preexisting_user": user,
            },
        )
        response = self.build_success_response(request, result)
        clear_state_cookie(response)
        clear_pkce_verifier_cookie(response)
        response.delete_cookie(GOOGLE_NONCE_COOKIE_NAME, samesite="Lax")
        return response
