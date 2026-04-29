"""AES-GCM round-trip and AAD-binding tests."""

import pytest
from cryptography.exceptions import InvalidTag

from blockauth.social.encryption import AESGCMEncryptor


def test_round_trip(aes_key):
    enc = AESGCMEncryptor(aes_key)
    aad = b"social_identity:apple:sub_1"
    blob = enc.encrypt("refresh-token-xyz", aad)
    assert enc.decrypt(blob, aad) == "refresh-token-xyz"


def test_blob_is_random_per_call(aes_key):
    enc = AESGCMEncryptor(aes_key)
    aad = b"social_identity:apple:sub_1"
    a = enc.encrypt("same-plaintext", aad)
    b = enc.encrypt("same-plaintext", aad)
    assert a != b


def test_decrypt_with_wrong_aad_fails(aes_key):
    """Wrong AAD must raise InvalidTag specifically, not a generic exception.

    Pinning the exception class prevents a future regression where a slicing
    bug raises TypeError but the test still passes.
    """
    enc = AESGCMEncryptor(aes_key)
    blob = enc.encrypt("refresh", b"social_identity:apple:sub_1")
    with pytest.raises(InvalidTag):
        enc.decrypt(blob, b"social_identity:apple:sub_2")


def test_decrypt_with_wrong_key_fails():
    """Wrong key must raise InvalidTag (the GCM auth-tag check)."""
    enc1 = AESGCMEncryptor(b"\x00" * 32)
    enc2 = AESGCMEncryptor(b"\x11" * 32)
    blob = enc1.encrypt("refresh", b"aad")
    with pytest.raises(InvalidTag):
        enc2.decrypt(blob, b"aad")


def test_key_must_be_32_bytes():
    with pytest.raises(ValueError):
        AESGCMEncryptor(b"\x00" * 16)


def test_truncated_blob_raises_value_error(aes_key):
    """Blob shorter than nonce+tag (12+16 = 28 bytes) is structurally invalid.

    Without an explicit length check, the call would either decrypt garbage
    against a tag-only fragment or raise a confusing low-level error. A
    ValueError at the boundary is the right contract.
    """
    enc = AESGCMEncryptor(aes_key)
    with pytest.raises(ValueError):
        enc.decrypt(b"\x00" * 5, b"aad")


def test_empty_plaintext_round_trip(aes_key):
    """Empty plaintext is a valid AES-GCM input (encrypts to tag-only 16 bytes)."""
    enc = AESGCMEncryptor(aes_key)
    aad = b"social_identity:apple:sub_1"
    blob = enc.encrypt("", aad)
    assert enc.decrypt(blob, aad) == ""
