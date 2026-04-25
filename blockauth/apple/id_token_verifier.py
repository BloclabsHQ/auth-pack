"""Apple id_token verifier.

Wraps the generic OIDCTokenVerifier with Apple-specific claim handling:
  - Apple sometimes serializes `email_verified` and `is_private_email` as the
    strings "true" / "false". We coerce those to bools.
  - Apple's `nonce_supported` claim signals whether the device participated in
    the nonce protocol. When True, we require nonce match. When False or
    absent, we skip nonce verification (older devices).
  - `verify_raw` is a thin convenience for the S2S notification path, which
    has a different audience expectation, no nonce, AND no email claim
    requirement (Apple's `consent-revoked` / `account-delete` events do not
    carry an `email` field).

Verifier instances are cached per (audiences, require_email_claim) tuple at
module scope so the underlying JWKSCache survives across requests; otherwise
every Apple verification would re-fetch https://appleid.apple.com/auth/keys.
Tests reset the cache via `_reset_verifier_cache()`.
"""

import hmac
import logging
import threading
from dataclasses import dataclass
from typing import Any

from django.conf import settings

from blockauth.apple.constants import AppleClaimKeys, AppleEndpoints
from blockauth.apple.exceptions import AppleIdTokenVerificationFailed, AppleNonceMismatch
from blockauth.utils.jwt import (
    JWKSCache,
    OIDCTokenVerifier,
    OIDCVerificationError,
    OIDCVerifierConfig,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AppleIdTokenClaims:
    sub: str
    email: str | None
    email_verified: bool
    is_private_email: bool
    nonce_supported: bool
    raw: dict[str, Any]


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return bool(value)


def _audiences() -> tuple[str, ...]:
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    services_id = block_settings.get("APPLE_SERVICES_ID")
    bundle_ids = tuple(block_settings.get("APPLE_BUNDLE_IDS") or ())
    # Order is informational only — OIDCVerifierConfig accepts any tuple
    # member as a valid `aud`. services_id first matches the typical web flow.
    audiences: list[str] = []
    if services_id:
        audiences.append(services_id)
    audiences.extend(bundle_ids)
    if not audiences:
        raise AppleIdTokenVerificationFailed("APPLE_SERVICES_ID and/or APPLE_BUNDLE_IDS must be configured")
    return tuple(audiences)


# Module-level verifier cache keyed by (audiences, require_email_claim).
# Survives across requests so the JWKSCache TTL is meaningful.
_verifier_cache: dict[tuple[tuple[str, ...], bool], OIDCTokenVerifier] = {}
_verifier_cache_lock = threading.Lock()


def _build_verifier(audiences: tuple[str, ...], *, require_email_claim: bool = True) -> OIDCTokenVerifier:
    """Return a cached OIDCTokenVerifier for the given audience tuple.

    `require_email_claim` defaults True for the standard sign-in flow (Apple
    always returns an email — relay or real). Set False for the S2S
    notification path: events like `consent-revoked` and `account-delete`
    do NOT carry an email claim.
    """
    cache_key = (audiences, require_email_claim)
    cached = _verifier_cache.get(cache_key)
    if cached is not None:
        return cached

    with _verifier_cache_lock:
        cached = _verifier_cache.get(cache_key)
        if cached is not None:
            return cached

        block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
        config = OIDCVerifierConfig(
            issuer="https://appleid.apple.com",
            jwks_uri=AppleEndpoints.JWKS,
            audiences=audiences,
            algorithms=("RS256",),
            leeway_seconds=int(block_settings.get("OIDC_VERIFIER_LEEWAY_SECONDS", 60)),
            require_email_claim=require_email_claim,
        )
        cache = JWKSCache(
            AppleEndpoints.JWKS,
            cache_ttl_seconds=int(block_settings.get("OIDC_JWKS_CACHE_TTL_SECONDS", 3600)),
        )
        verifier = OIDCTokenVerifier(config, jwks_cache=cache)
        _verifier_cache[cache_key] = verifier
        return verifier


def _reset_verifier_cache() -> None:
    """Clear the module-level verifier cache. Tests use this between
    `override_settings` blocks so a stale verifier from a prior config doesn't
    leak across test cases."""
    with _verifier_cache_lock:
        _verifier_cache.clear()


class AppleIdTokenVerifier:
    def verify(self, id_token: str, expected_nonce: str | None) -> AppleIdTokenClaims:
        verifier = _build_verifier(_audiences())
        try:
            claims = verifier.verify(id_token, expected_nonce=None)
        except OIDCVerificationError as exc:
            raise AppleIdTokenVerificationFailed(str(exc)) from exc

        nonce_supported = _coerce_bool(claims.get(AppleClaimKeys.NONCE_SUPPORTED))
        if expected_nonce is not None:
            if nonce_supported:
                actual = claims.get(AppleClaimKeys.NONCE)
                if not actual or not hmac.compare_digest(str(actual), str(expected_nonce)):
                    raise AppleNonceMismatch("Apple id_token nonce did not match expected value")
            else:
                logger.info(
                    "apple.idtoken.nonce_unsupported",
                    extra={
                        "sub_suffix": str(claims.get("sub", ""))[-4:],
                        # audience helps ops distinguish web (services_id)
                        # from native-old-device (bundle_id) traffic.
                        "audience": claims.get("aud"),
                    },
                )

        return AppleIdTokenClaims(
            sub=str(claims["sub"]),
            email=claims.get(AppleClaimKeys.EMAIL),
            email_verified=_coerce_bool(claims.get(AppleClaimKeys.EMAIL_VERIFIED)),
            is_private_email=_coerce_bool(claims.get(AppleClaimKeys.IS_PRIVATE_EMAIL)),
            nonce_supported=nonce_supported,
            raw=claims,
        )

    def verify_raw(self, id_token: str, audiences: tuple[str, ...]) -> dict[str, Any]:
        # require_email_claim=False because Apple S2S notification events
        # (consent-revoked, account-delete) do NOT carry an `email` field.
        verifier = _build_verifier(audiences, require_email_claim=False)
        try:
            return verifier.verify(id_token, expected_nonce=None)
        except OIDCVerificationError as exc:
            raise AppleIdTokenVerificationFailed(str(exc)) from exc
