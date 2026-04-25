"""AES-GCM-256 encryptor for refresh-token-at-rest.

Each ciphertext blob is `nonce(12 bytes) || ciphertext || tag(16 bytes)` — a
single bytes value that fits a `BinaryField` on the SocialIdentity model.
Associated data binds the ciphertext to a specific (provider, subject) so a
ciphertext from one identity row cannot be replayed onto another.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12
KEY_BYTES = 32


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
        nonce = blob[:NONCE_BYTES]
        ciphertext_with_tag = blob[NONCE_BYTES:]
        plaintext_bytes = self._aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        return plaintext_bytes.decode("utf-8")
