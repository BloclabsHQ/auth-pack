"""LinkedIn OAuth web flow.

LinkedIn finished its OIDC migration in 2024. We use the standard OIDC
discovery values: issuer `https://www.linkedin.com`, JWKS at
`https://www.linkedin.com/oauth/openid/jwks`. Audience is the integrator's
LinkedIn client ID.

Like the Phase 13 Google refactor, this drops the userinfo HTTP call in favor
of the id_token's email / name / sub claims, and links by `(linkedin, sub)`.

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

from blockauth.docs.social_auth_docs import linkedin_auth_callback_schema, linkedin_auth_login_schema
from blockauth.schemas.examples.social_auth import social_authorization_code, social_invalid_auth_config
from blockauth.serializers.user_account_serializers import AuthStateResponseSerializer
from blockauth.social.exceptions import (  # noqa: F401  intentional: documented as the propagating-409
    SocialIdentityConflictError,
)
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

LINKEDIN_AUTHORIZE_URL = "https://www.linkedin.com/oauth/v2/authorization"
LINKEDIN_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
LINKEDIN_ISSUER = "https://www.linkedin.com"
LINKEDIN_JWKS_URI = "https://www.linkedin.com/oauth/openid/jwks"
LINKEDIN_NONCE_COOKIE_NAME = "blockauth_linkedin_nonce"
LINKEDIN_NONCE_BYTES = 32


def _block_setting(key, default=None):
    """Read BLOCK_AUTH_SETTINGS at runtime so override_settings propagates.

    `get_config` reads through DRF's APISettings, which caches keyed-attribute
    access; that cache is not invalidated by Django's `override_settings`.
    Reading `settings.BLOCK_AUTH_SETTINGS` directly here keeps tests
    deterministic across `override_settings` blocks (mirrors the
    `google_auth_views._block_setting` pattern).
    """
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    return block_settings.get(key, default)


def _provider_setting(key, default=None):
    """Read AUTH_PROVIDERS-nested or top-level LINKEDIN_* settings.

    Newer integrations declare per-provider config under
    `BLOCK_AUTH_SETTINGS["AUTH_PROVIDERS"]["LINKEDIN"]`; legacy integrations
    use flat top-level `LINKEDIN_CLIENT_ID` / `LINKEDIN_CLIENT_SECRET` /
    `LINKEDIN_REDIRECT_URI`. Resolution order is nested first (the configured
    block beats the legacy alias when both are set), with top-level as the
    fallback so existing deployments keep working.
    """
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    providers = block_settings.get("AUTH_PROVIDERS", {}) or {}
    nested = providers.get("LINKEDIN", {}) or {}
    if key in nested:
        return nested[key]
    return block_settings.get(f"LINKEDIN_{key}", default)


# Module-level verifier cache keyed by the audiences tuple. Survives across
# requests so the JWKSCache TTL is meaningful — without this, every web
# callback would re-fetch LinkedIn's JWKS endpoint. The double-checked locking
# pattern under `_verifier_cache_lock` ensures concurrent first requests
# don't race to instantiate duplicate verifiers. Mirrors the Phase 6/13
# hardening pattern.
_verifier_cache: dict[tuple[str, ...], OIDCTokenVerifier] = {}
_verifier_cache_lock = threading.Lock()


def _reset_verifier_cache() -> None:
    """Tests use this between override_settings blocks so a stale verifier
    from a prior config doesn't leak across cases."""
    with _verifier_cache_lock:
        _verifier_cache.clear()


def _build_verifier() -> OIDCTokenVerifier:
    client_id = _provider_setting("CLIENT_ID")
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
            issuer=LINKEDIN_ISSUER,
            jwks_uri=LINKEDIN_JWKS_URI,
            audiences=audiences,
            algorithms=("RS256",),
            leeway_seconds=leeway,
        )
        verifier = OIDCTokenVerifier(
            config,
            jwks_cache=JWKSCache(LINKEDIN_JWKS_URI, cache_ttl_seconds=cache_ttl),
        )
        _verifier_cache[audiences] = verifier
        return verifier


class LinkedInAuthLoginView(APIView):
    """Initiate LinkedIn OAuth — emit state, raw nonce, and PKCE pair."""

    permission_classes = (AllowAny,)
    authentication_classes = ()

    @extend_schema(**linkedin_auth_login_schema)
    def get(self, request):
        client_id = _provider_setting("CLIENT_ID")
        redirect_uri = _provider_setting("REDIRECT_URI")
        if not client_id or not redirect_uri:
            raise ValidationError(social_invalid_auth_config.value, 4020)

        state = generate_state()
        raw_nonce = secrets.token_urlsafe(LINKEDIN_NONCE_BYTES)
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
        }
        url = f"{LINKEDIN_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

        blockauth_logger.info(
            "linkedin.web.authorize_started",
            {"client_id_suffix": client_id[-6:]},
        )

        response = redirect(url)
        set_state_cookie(response, state)
        set_pkce_verifier_cookie(response, pair.verifier)
        # Raw nonce — kept HttpOnly so JS can't read it. Hashed value goes
        # to LinkedIn in the `nonce` query param; we re-hash on callback and
        # compare against the id_token's `nonce` claim.
        response.set_cookie(
            LINKEDIN_NONCE_COOKIE_NAME,
            raw_nonce,
            max_age=600,
            httponly=True,
            secure=True,
            samesite="Lax",
        )
        return response


class LinkedInAuthCallbackView(APIView):
    """Handle LinkedIn OAuth callback — verify state + PKCE + nonce + id_token.

    Subclass and override :meth:`build_success_response` to ship tokens via
    HttpOnly cookies + a 302 to the shell origin instead of the default JSON
    body (BFF pattern — fabric-auth#533).
    """

    permission_classes = (AllowAny,)
    authentication_classes = ()

    def build_success_response(self, request, result) -> Response:
        """Default: return the `{access, refresh, user}` JSON body.

        See :meth:`GoogleAuthCallbackView.build_success_response` for the
        integrator-override contract.
        """
        serializer = AuthStateResponseSerializer(
            {
                "access": result.access_token,
                "refresh": result.refresh_token,
                "user": build_user_payload(result.user),
            }
        )
        return Response(data=serializer.data, status=drf_status.HTTP_200_OK)

    @extend_schema(**linkedin_auth_callback_schema)
    def get(self, request):
        code = request.query_params.get("code")
        if not code:
            raise ValidationError(social_authorization_code.value)

        client_id = _provider_setting("CLIENT_ID")
        client_secret = _provider_setting("CLIENT_SECRET")
        redirect_uri = _provider_setting("REDIRECT_URI")
        if not all([client_id, client_secret, redirect_uri]):
            raise ValidationError(social_invalid_auth_config.value, 4020)

        # CSRF — must run BEFORE the token exchange so a probe cannot
        # consume a real authorization code.
        verify_state(request)

        pkce_verifier = read_pkce_verifier_cookie(request)
        if not pkce_verifier:
            raise ValidationError({"detail": "PKCE verifier missing"}, 4051)

        raw_nonce = request.COOKIES.get(LINKEDIN_NONCE_COOKIE_NAME)
        if not raw_nonce:
            raise ValidationError({"detail": "OAuth nonce missing"}, 4070)
        expected_nonce = hashlib.sha256(raw_nonce.encode("utf-8")).hexdigest()

        try:
            token_response = requests.post(
                LINKEDIN_TOKEN_URL,
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
                "linkedin.web.token_endpoint_unreachable",
                {"error_class": exc.__class__.__name__},
            )
            raise ValidationError({"detail": "LinkedIn token endpoint unreachable"}, 4070) from exc

        if token_response.status_code != 200:
            blockauth_logger.error(
                "linkedin.web.token_exchange_failed",
                {"status_code": token_response.status_code},
            )
            raise ValidationError({"detail": "Token exchange failed"}, 4070)

        token_payload = token_response.json()
        id_token = token_payload.get("id_token")
        if not id_token:
            raise ValidationError({"detail": "LinkedIn did not return id_token"}, 4070)

        try:
            claims = _build_verifier().verify(id_token, expected_nonce=expected_nonce)
        except OIDCVerificationError as exc:
            blockauth_logger.error(
                "linkedin.web.id_token_verify_failed",
                {"error_class": exc.__class__.__name__},
            )
            raise ValidationError({"detail": str(exc)}, 4070)

        # SocialIdentityConflictError extends APIException with status_code=409;
        # let it propagate to the HTTP-semantic Conflict response rather than
        # demoting it to 400 by an extra ValidationError wrap. Phase 9
        # cross-flow consistency.
        user, _, _ = SocialIdentityService().upsert_and_link(
            provider="linkedin",
            subject=str(claims["sub"]),
            email=claims.get("email"),
            email_verified=bool(claims.get("email_verified")),
            extra_claims={},
        )

        result = social_login_data(
            email=claims.get("email") or "",
            name=claims.get("name") or "",
            provider_data={
                "provider": "linkedin",
                "user_info": claims,
                "preexisting_user": user,
            },
        )
        response = self.build_success_response(request, result)
        clear_state_cookie(response)
        clear_pkce_verifier_cookie(response)
        response.delete_cookie(LINKEDIN_NONCE_COOKIE_NAME, samesite="Lax")
        return response
