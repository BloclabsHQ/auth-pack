"""Generic OIDC id_token verifier.

Pins algorithms before signature work to defend against algorithm confusion.
Looks up signing keys via JWKSCache so every supported provider shares one
rotation-aware key cache. Returns decoded claims on success; raises a specific
OIDCVerificationError subclass on each distinct failure mode.

Example:
    config = OIDCVerifierConfig(
        issuer="https://accounts.google.com",
        jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
        audiences=("client-id.apps.googleusercontent.com",),
        algorithms=("RS256",),
    )
    verifier = OIDCTokenVerifier(config)
    try:
        claims = verifier.verify(id_token, expected_nonce=hashed_nonce)
    except OIDCVerificationError:
        # Auth fails closed — log and reject.
        raise
"""

import hmac
import logging
from dataclasses import dataclass

import jwt as pyjwt
from jwt.algorithms import get_default_algorithms

from blockauth.utils.jwt.exceptions import (
    AlgorithmNotAllowed,
    AudienceMismatch,
    IssuerMismatch,
    NonceMismatch,
    RequiredClaimMissing,
    SignatureInvalid,
    TokenExpired,
)
from blockauth.utils.jwt.jwks_cache import JWKSCache

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class OIDCVerifierConfig:
    issuer: str
    jwks_uri: str
    audiences: tuple[str, ...]
    algorithms: tuple[str, ...]
    leeway_seconds: int = 60
    require_email_claim: bool = True

    def __post_init__(self) -> None:
        if not self.issuer:
            raise ValueError("OIDCVerifierConfig.issuer must be non-empty")
        if not self.jwks_uri:
            raise ValueError("OIDCVerifierConfig.jwks_uri must be non-empty")
        if not self.audiences:
            raise ValueError(
                "OIDCVerifierConfig.audiences must contain at least one accepted audience"
            )
        if not self.algorithms:
            raise ValueError(
                "OIDCVerifierConfig.algorithms must contain at least one accepted alg"
            )
        if self.leeway_seconds < 0:
            raise ValueError("OIDCVerifierConfig.leeway_seconds must be >= 0")


class OIDCTokenVerifier:
    def __init__(self, config: OIDCVerifierConfig, jwks_cache: JWKSCache | None = None):
        self._config = config
        self._jwks_cache = jwks_cache or JWKSCache(config.jwks_uri)

    def verify(self, token: str, expected_nonce: str | None) -> dict:
        """Verify an OIDC id_token and return its decoded claims.

        On any verification failure, raises a subclass of `OIDCVerificationError`.
        Callers that want broad handling should catch `OIDCVerificationError`;
        callers that want targeted handling can catch any of:

          - `AlgorithmNotAllowed` — token's `alg` not in `config.algorithms`
          - `SignatureInvalid` — header undecodable / kid missing / signature mismatch
          - `JWKSUnreachable` — JWKS endpoint returned non-200 or transport error
          - `KidNotFound` — JWKS reachable but the token's kid is not present
          - `IssuerMismatch` — `iss` claim does not match `config.issuer`
          - `AudienceMismatch` — `aud` claim not in `config.audiences`
          - `TokenExpired` — `exp` is in the past (modulo leeway)
          - `NonceMismatch` — `expected_nonce` provided but missing/mismatched in claims
          - `RequiredClaimMissing` — `config.require_email_claim=True` but `email` absent

        `expected_nonce=None` skips nonce verification (used by Apple flows where
        `nonce_supported=false` on older clients, and by S2S notification verify).
        """
        try:
            unverified_header = pyjwt.get_unverified_header(token)
        except pyjwt.DecodeError as exc:
            raise SignatureInvalid("Token header could not be decoded") from exc

        alg = unverified_header.get("alg")
        if alg not in self._config.algorithms:
            raise AlgorithmNotAllowed(f"alg {alg!r} not in allowlist {self._config.algorithms}")

        kid = unverified_header.get("kid")
        if not kid:
            raise SignatureInvalid("Token header missing kid")

        jwk = self._jwks_cache.get_key_for_kid(kid)
        algorithm_impl = get_default_algorithms().get(alg)
        if algorithm_impl is None:
            raise AlgorithmNotAllowed(
                f"alg {alg!r} has no registered algorithm implementation"
            )
        public_key = algorithm_impl.from_jwk(jwk)

        try:
            claims = pyjwt.decode(
                token,
                public_key,
                algorithms=list(self._config.algorithms),
                audience=list(self._config.audiences),
                issuer=self._config.issuer,
                leeway=self._config.leeway_seconds,
                options={"require": ["iss", "aud", "exp", "iat"]},
            )
        except pyjwt.ExpiredSignatureError as exc:
            raise TokenExpired(str(exc)) from exc
        except pyjwt.InvalidIssuerError as exc:
            raise IssuerMismatch(str(exc)) from exc
        except pyjwt.InvalidAudienceError as exc:
            raise AudienceMismatch(str(exc)) from exc
        except pyjwt.InvalidSignatureError as exc:
            raise SignatureInvalid(str(exc)) from exc
        except pyjwt.PyJWTError as exc:
            raise SignatureInvalid(str(exc)) from exc

        logger.info(
            "oidc.verify.succeeded",
            extra={
                "issuer": self._config.issuer,
                "audiences": list(self._config.audiences),
            },
        )

        if expected_nonce is not None:
            actual = claims.get("nonce")
            if not actual or not hmac.compare_digest(str(actual), str(expected_nonce)):
                raise NonceMismatch("nonce claim missing or did not match")

        if self._config.require_email_claim and "email" not in claims:
            raise RequiredClaimMissing("Required `email` claim missing from id_token")

        return claims
