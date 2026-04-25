"""Smoke test: lock the public surface of `blockauth.utils.jwt`.

Catches accidental removals or renames of exported symbols by re-importing
the documented public API in one shot. Failure here means a downstream
consumer (Apple, Google native, LinkedIn, etc.) would also break — fix the
export before fixing this test.
"""

from blockauth.utils.jwt import (  # noqa: F401
    AlgorithmNotAllowed,
    AudienceMismatch,
    IssuerMismatch,
    JWKSCache,
    JWKSUnreachable,
    KidNotFound,
    NonceMismatch,
    OIDCTokenVerifier,
    OIDCVerificationError,
    OIDCVerifierConfig,
    SignatureInvalid,
    TokenExpired,
)


def test_public_surface_exports_match_all():
    """`__all__` must list exactly the public surface — nothing missing, nothing extra."""
    import blockauth.utils.jwt as pkg

    expected = {
        "AlgorithmNotAllowed",
        "AudienceMismatch",
        "IssuerMismatch",
        "JWKSCache",
        "JWKSUnreachable",
        "KidNotFound",
        "NonceMismatch",
        "OIDCTokenVerifier",
        "OIDCVerificationError",
        "OIDCVerifierConfig",
        "SignatureInvalid",
        "TokenExpired",
    }
    assert set(pkg.__all__) == expected


def test_oidc_subclasses_share_base():
    """All OIDC failure subclasses inherit from OIDCVerificationError so callers
    can catch broadly with `except OIDCVerificationError`."""
    from blockauth.utils.jwt import (
        AlgorithmNotAllowed,
        AudienceMismatch,
        IssuerMismatch,
        JWKSUnreachable,
        KidNotFound,
        NonceMismatch,
        OIDCVerificationError,
        SignatureInvalid,
        TokenExpired,
    )

    for sub in (
        AlgorithmNotAllowed,
        AudienceMismatch,
        IssuerMismatch,
        JWKSUnreachable,
        KidNotFound,
        NonceMismatch,
        SignatureInvalid,
        TokenExpired,
    ):
        assert issubclass(sub, OIDCVerificationError), f"{sub.__name__} does not subclass OIDCVerificationError"
