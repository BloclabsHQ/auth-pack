"""RFC 7636 PKCE helper.

`generate_pkce_pair` returns `(code_verifier, code_challenge)` where the
verifier is a high-entropy URL-safe random string and the challenge is the
S256 derivation Apple, Google, LinkedIn, and Facebook all accept.
"""

import base64
import hashlib
import secrets

VERIFIER_BYTES = 32  # 32 random bytes → 43 url-safe chars, lower bound of RFC 7636


def generate_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(VERIFIER_BYTES)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge
