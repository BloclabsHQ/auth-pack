"""RFC 7636 PKCE helper.

`generate_pkce_pair` returns a `PkcePair(verifier, challenge)` where the
verifier is a high-entropy URL-safe random string and the challenge is the
S256 derivation Apple, Google, LinkedIn, and Facebook all accept.

The named-tuple return shape (rather than a positional `(verifier, challenge)`
tuple) defends against silent position-swap bugs at the four downstream
OAuth call sites: a typo wiring the verifier into the authorization URL as
the challenge would otherwise be a PKCE bypass that no test would catch.
"""

import base64
import hashlib
import secrets
from typing import NamedTuple

VERIFIER_BYTES = 32  # 32 random bytes → 43 url-safe chars, lower bound of RFC 7636


class PkcePair(NamedTuple):
    """RFC 7636 PKCE pair. Tuple-compatible: `verifier, challenge = pair` still works."""

    verifier: str
    challenge: str


def compute_pkce_challenge(verifier: str) -> str:
    """Derive the S256 challenge from a verifier per RFC 7636 §4.2.

    Exposed separately from `generate_pkce_pair` so the derivation can be
    tested against the RFC 7636 Appendix B known-answer vector without going
    through the random generator.
    """
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def generate_pkce_pair() -> PkcePair:
    verifier = secrets.token_urlsafe(VERIFIER_BYTES)
    challenge = compute_pkce_challenge(verifier)
    return PkcePair(verifier, challenge)
