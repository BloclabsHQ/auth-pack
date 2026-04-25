"""OIDC verification errors.

Each subclass corresponds to one specific failure mode so callers can branch on
class without inspecting message strings.
"""


class OIDCVerificationError(Exception):
    """Base class for every failure inside `OIDCTokenVerifier.verify`."""


class IssuerMismatch(OIDCVerificationError):
    """Token's iss claim does not match OIDCVerifierConfig.issuer."""


class AudienceMismatch(OIDCVerificationError):
    """Token's aud claim is not in OIDCVerifierConfig.audiences."""


class SignatureInvalid(OIDCVerificationError):
    """Token signature did not verify against the JWKS public key."""


class KidNotFound(OIDCVerificationError):
    """JWKS endpoint was reachable but the token's kid is absent from the response."""


class JWKSUnreachable(OIDCVerificationError):
    """Transport-level failure fetching the JWKS endpoint (network error or non-200)."""


class TokenExpired(OIDCVerificationError):
    """Token's exp claim is in the past (beyond configured leeway)."""


class NonceMismatch(OIDCVerificationError):
    """Token's nonce claim is missing or does not match the expected nonce."""


class AlgorithmNotAllowed(OIDCVerificationError):
    """Token header alg is not in OIDCVerifierConfig.algorithms allowlist."""


class RequiredClaimMissing(OIDCVerificationError):
    """A claim required by the verifier configuration is absent from the decoded token."""
