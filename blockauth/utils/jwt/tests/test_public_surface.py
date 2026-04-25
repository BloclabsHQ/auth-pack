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
    RequiredClaimMissing,
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
        "RequiredClaimMissing",
        "SignatureInvalid",
        "TokenExpired",
    }
    assert set(pkg.__all__) == expected


def test_oidc_subclasses_share_base():
    """All OIDC failure subclasses inherit from OIDCVerificationError so callers
    can catch broadly with `except OIDCVerificationError`.

    Uses __subclasses__() so adding a new subclass without updating __all__
    will fail this test. (And vice versa.)
    """
    import blockauth.utils.jwt as pkg
    from blockauth.utils.jwt import OIDCVerificationError

    subclasses = OIDCVerificationError.__subclasses__()
    # Must be at least the 9 currently-known failure modes.
    assert len(subclasses) >= 9

    for sub in subclasses:
        assert issubclass(sub, OIDCVerificationError), (
            f"{sub.__name__} does not subclass OIDCVerificationError"
        )
        # Each declared subclass must also be exported.
        assert sub.__name__ in pkg.__all__, f"{sub.__name__} missing from __all__"
