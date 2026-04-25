"""Package-level pytest fixtures.

Exposes real RSA keypairs and a token-builder helper so any sub-package's tests
can produce signed JWTs without re-implementing the boilerplate.

Living at the package root means the fixtures are auto-discovered by
`blockauth/utils/jwt/tests/`, `blockauth/social/tests/`, `blockauth/apple/tests/`,
and `blockauth/views/tests/` without per-directory duplication.
"""

import base64
import json
import secrets
import time
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture(scope="session")
def rsa_keypair():
    """Return (private_pem_str, public_pem_str, kid)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    kid = "test-kid-" + secrets.token_hex(4)
    return private_pem, public_pem, kid


@pytest.fixture(scope="session")
def jwks_payload_bytes(rsa_keypair):
    """Return JWKS JSON bytes for the test public key, suitable as an HTTP body."""
    _, public_pem, kid = rsa_keypair
    public_key = serialization.load_pem_public_key(public_pem.encode())
    numbers = public_key.public_numbers()
    n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    # RFC 7518 §6.3.1: RSA JWK `n` and `e` are unpadded base64url integers.
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode(),
        "e": base64.urlsafe_b64encode(e_bytes).rstrip(b"=").decode(),
    }
    return json.dumps({"keys": [jwk]}).encode()


@pytest.fixture
def build_id_token(rsa_keypair):
    """Factory: build an RS256-signed JWT with arbitrary claims and the test kid."""
    private_pem, _, kid = rsa_keypair

    def _build(claims: dict[str, Any], kid_override: str | None = None) -> str:
        defaults = {"iat": int(time.time()), "exp": int(time.time()) + 600}
        merged = {**defaults, **claims}
        return pyjwt.encode(
            merged,
            private_pem,
            algorithm="RS256",
            headers={"kid": kid_override or kid},
        )

    return _build


@pytest.fixture
def aes_key():
    """32-byte AES-GCM key for SocialIdentity encryption tests."""
    return secrets.token_bytes(32)
