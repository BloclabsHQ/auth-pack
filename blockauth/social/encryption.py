"""AES-GCM-256 encryptor for refresh-token-at-rest.

Each ciphertext blob is `nonce(12 bytes) || ciphertext || tag(16 bytes)` — a
single bytes value that fits a `BinaryField` on the SocialIdentity model.
Associated data binds the ciphertext to a specific (provider, subject) so a
ciphertext from one identity row cannot be replayed onto another.

Nonce-collision bound: random 96-bit nonces have ~2**-32 collision probability
near 2**32 messages encrypted with the same key (birthday bound). For the
SocialIdentity use case (one ciphertext per linked identity per rotation, per
deployment) this is comfortably below the limit. If this class is reused for
high-volume encryption (e.g. millions of messages per key per day), switch to
deterministic/counter-based nonces or rotate keys.
"""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings

NONCE_BYTES = 12
KEY_BYTES = 32
GCM_TAG_BYTES = 16


class AESGCMEncryptor:
    def __init__(self, key: bytes):
        if len(key) != KEY_BYTES:
            raise ValueError(f"AES-GCM key must be {KEY_BYTES} bytes, got {len(key)}")
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: str, associated_data: bytes) -> bytes:
        nonce = os.urandom(NONCE_BYTES)
        ciphertext_with_tag = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data)
        return nonce + ciphertext_with_tag

    def decrypt(self, blob: bytes, associated_data: bytes) -> str:
        if len(blob) < NONCE_BYTES + GCM_TAG_BYTES:
            raise ValueError(
                f"AES-GCM blob too short: got {len(blob)} bytes, " f"need at least {NONCE_BYTES + GCM_TAG_BYTES}"
            )
        nonce = blob[:NONCE_BYTES]
        ciphertext_with_tag = blob[NONCE_BYTES:]
        plaintext_bytes = self._aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        return plaintext_bytes.decode("utf-8")


def load_encryptor() -> "AESGCMEncryptor | None":
    """Load the configured AESGCMEncryptor from BLOCK_AUTH_SETTINGS.

    Returns None when no encryption key is configured. Callers should treat
    None as "do not store refresh tokens at rest" rather than crashing.
    """
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    key_b64 = block_settings.get("SOCIAL_IDENTITY_ENCRYPTION_KEY")
    if not key_b64:
        return None
    return AESGCMEncryptor(base64.b64decode(key_b64))


def aad_for(provider: str, subject: str) -> bytes:
    """AAD format binding a refresh-token blob to a specific identity row."""
    return f"social_identity:{provider}:{subject}".encode("utf-8")
