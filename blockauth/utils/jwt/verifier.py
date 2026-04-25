"""Generic OIDC id_token verifier.

Pins algorithms before signature work to defend against algorithm confusion.
Looks up signing keys via JWKSCache so every supported provider shares one
rotation-aware key cache. Returns decoded claims on success; raises a specific
OIDCVerificationError subclass on each distinct failure mode.
"""

import hmac
import logging
from dataclasses import dataclass

import jwt as pyjwt
from jwt.algorithms import RSAAlgorithm

from blockauth.utils.jwt.exceptions import (
    AlgorithmNotAllowed,
    AudienceMismatch,
    IssuerMismatch,
    NonceMismatch,
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


class OIDCTokenVerifier:
    def __init__(self, config: OIDCVerifierConfig, jwks_cache: JWKSCache | None = None):
        self._config = config
        self._jwks_cache = jwks_cache or JWKSCache(config.jwks_uri)

    def verify(self, token: str, expected_nonce: str | None) -> dict:
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
        public_key = RSAAlgorithm.from_jwk(jwk)

        logger.info(
            "oidc.verify.started",
            extra={"issuer": self._config.issuer, "audience": ",".join(self._config.audiences)},
        )

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

        if expected_nonce is not None:
            actual = claims.get("nonce")
            if not actual or not hmac.compare_digest(str(actual), str(expected_nonce)):
                raise NonceMismatch("nonce claim missing or did not match")

        return claims
