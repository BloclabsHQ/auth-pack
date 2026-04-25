"""Apple id_token verifier.

Wraps the generic OIDCTokenVerifier with Apple-specific claim handling:
  - Apple sometimes serializes `email_verified` and `is_private_email` as the
    strings "true" / "false". We coerce those to bools.
  - Apple's `nonce_supported` claim signals whether the device participated in
    the nonce protocol. When True, we require nonce match. When False or
    absent, we skip nonce verification (older devices).
  - `verify_raw` is a thin convenience for the S2S notification path, which
    has a different audience expectation and no nonce.
"""

import hmac
import logging
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
    audiences: list[str] = []
    if services_id:
        audiences.append(services_id)
    audiences.extend(bundle_ids)
    if not audiences:
        raise AppleIdTokenVerificationFailed("APPLE_SERVICES_ID and/or APPLE_BUNDLE_IDS must be configured")
    return tuple(audiences)


def _build_verifier(audiences: tuple[str, ...]) -> OIDCTokenVerifier:
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    config = OIDCVerifierConfig(
        issuer="https://appleid.apple.com",
        jwks_uri=AppleEndpoints.JWKS,
        audiences=audiences,
        algorithms=("RS256",),
        leeway_seconds=int(block_settings.get("OIDC_VERIFIER_LEEWAY_SECONDS", 60)),
    )
    cache = JWKSCache(AppleEndpoints.JWKS, cache_ttl_seconds=int(block_settings.get("OIDC_JWKS_CACHE_TTL_SECONDS", 3600)))
    return OIDCTokenVerifier(config, jwks_cache=cache)


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
                logger.info("apple.idtoken.nonce_unsupported", extra={"sub_suffix": str(claims.get("sub", ""))[-4:]})

        return AppleIdTokenClaims(
            sub=str(claims["sub"]),
            email=claims.get(AppleClaimKeys.EMAIL),
            email_verified=_coerce_bool(claims.get(AppleClaimKeys.EMAIL_VERIFIED)),
            is_private_email=_coerce_bool(claims.get(AppleClaimKeys.IS_PRIVATE_EMAIL)),
            nonce_supported=nonce_supported,
            raw=claims,
        )

    def verify_raw(self, id_token: str, audiences: tuple[str, ...]) -> dict[str, Any]:
        verifier = _build_verifier(audiences)
        try:
            return verifier.verify(id_token, expected_nonce=None)
        except OIDCVerificationError as exc:
            raise AppleIdTokenVerificationFailed(str(exc)) from exc
