"""OIDC verification errors.

Each subclass corresponds to one specific failure mode so callers can branch on
class without inspecting message strings.
"""


class OIDCVerificationError(Exception):
    """Base class for every failure inside `OIDCTokenVerifier.verify`."""


class IssuerMismatch(OIDCVerificationError):
    pass


class AudienceMismatch(OIDCVerificationError):
    pass


class SignatureInvalid(OIDCVerificationError):
    pass


class KidNotFound(OIDCVerificationError):
    pass


class TokenExpired(OIDCVerificationError):
    pass


class NonceMismatch(OIDCVerificationError):
    pass


class AlgorithmNotAllowed(OIDCVerificationError):
    pass
