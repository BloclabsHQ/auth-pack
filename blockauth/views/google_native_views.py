"""Google Native id_token verify endpoint.

Accepts a Google-issued id_token from Android Credential Manager, the iOS
Google Sign-In SDK, or Web One Tap, plus the raw_nonce the client passed when
requesting it. The audience allowlist contains the Web (server) OAuth client
IDs the integrator registered. The `azp` claim — which carries the platform
client ID — is captured but not enforced; integrators can validate it via a
post-login trigger if they wish.

Verifier instances are cached at module scope so the underlying JWKSCache
survives across requests; otherwise every Google native verification would
re-fetch https://www.googleapis.com/oauth2/v3/certs. Tests reset the cache
via `_reset_verifier_cache()`.
"""

import hashlib
import logging
import threading

from django.conf import settings
from drf_spectacular.utils import extend_schema
from rest_framework import status as drf_status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.serializers import CharField, Serializer
from rest_framework.views import APIView

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
from blockauth.utils.social import social_login_data

logger = logging.getLogger(__name__)


GOOGLE_ISSUER = "https://accounts.google.com"
GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs"


def _block_setting(key, default=None):
    """Read BLOCK_AUTH_SETTINGS at runtime so override_settings propagates.

    The package's `get_config` reads through DRF's APISettings, which caches
    keyed-attribute access; that cache is not invalidated by Django's
    `override_settings`. Reading `settings.BLOCK_AUTH_SETTINGS` directly here
    matches the pattern used by `blockauth.apple._settings.apple_setting` and
    keeps tests deterministic across `override_settings` blocks.
    """
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    return block_settings.get(key, default)


# Module-level verifier cache keyed by audiences tuple. Survives across
# requests so the JWKSCache TTL is meaningful — without this, every native
# verification would re-fetch Google's JWKS endpoint. The double-checked
# locking pattern under `_verifier_cache_lock` ensures concurrent first
# requests don't race to instantiate duplicate verifiers.
_verifier_cache: dict[tuple[str, ...], OIDCTokenVerifier] = {}
_verifier_cache_lock = threading.Lock()


def _reset_verifier_cache() -> None:
    """Tests use this between override_settings blocks so a stale verifier
    from a prior config doesn't leak across cases."""
    with _verifier_cache_lock:
        _verifier_cache.clear()


def _build_google_native_verifier() -> OIDCTokenVerifier:
    audiences = tuple(_block_setting("GOOGLE_NATIVE_AUDIENCES") or ())
    if not audiences:
        raise ValidationError(
            {"detail": "Google native audiences are not configured"}, 4020
        )

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


class GoogleNativeIdTokenVerifyRequestSerializer(Serializer):
    id_token = CharField()
    raw_nonce = CharField()


class GoogleNativeIdTokenVerifyView(APIView):
    """POST /google/native/verify/ — verify a Google-issued id_token.

    Body: {"id_token": <jwt>, "raw_nonce": <string>}
    The server hashes raw_nonce with SHA-256, compares the hex digest against
    the id_token's `nonce` claim (Google always emits one — no skip path).
    On success: upserts a SocialIdentity, mints blockauth JWTs, returns
    {"access", "refresh", "user"}.
    """

    permission_classes = (AllowAny,)
    authentication_classes = ()

    def build_success_response(self, request, result) -> Response:
        serializer = AuthStateResponseSerializer(
            {
                "access": result.access_token,
                "refresh": result.refresh_token,
                "user": build_user_payload(result.user),
            }
        )
        return Response(data=serializer.data, status=drf_status.HTTP_200_OK)

    @extend_schema(summary="Verify Google id_token from native client")
    def post(self, request):
        serializer = GoogleNativeIdTokenVerifyRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data

        expected_nonce = hashlib.sha256(
            validated["raw_nonce"].encode("utf-8")
        ).hexdigest()
        try:
            claims = _build_google_native_verifier().verify(
                validated["id_token"], expected_nonce=expected_nonce
            )
        except OIDCVerificationError as exc:
            blockauth_logger.error(
                "google.native.verify_failed",
                {"error_class": exc.__class__.__name__},
            )
            raise ValidationError({"detail": str(exc)}, 4061)

        # SocialIdentityConflictError extends APIException with status_code=409;
        # let it propagate to the HTTP-semantic Conflict response rather than
        # demoting it to 400 by an extra ValidationError wrap.
        user, _, _ = SocialIdentityService().upsert_and_link(
            provider="google",
            subject=str(claims["sub"]),
            email=claims.get("email"),
            email_verified=bool(claims.get("email_verified")),
            extra_claims={"hd": claims.get("hd"), "azp": claims.get("azp")},
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
        return self.build_success_response(request, result)
