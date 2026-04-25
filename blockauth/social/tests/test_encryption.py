"""AES-GCM round-trip and AAD-binding tests."""

import pytest

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
    enc = AESGCMEncryptor(aes_key)
    blob = enc.encrypt("refresh", b"social_identity:apple:sub_1")
    with pytest.raises(Exception):  # cryptography raises InvalidTag
        enc.decrypt(blob, b"social_identity:apple:sub_2")


def test_decrypt_with_wrong_key_fails():
    enc1 = AESGCMEncryptor(b"\x00" * 32)
    enc2 = AESGCMEncryptor(b"\x11" * 32)
    blob = enc1.encrypt("refresh", b"aad")
    with pytest.raises(Exception):
        enc2.decrypt(blob, b"aad")


def test_key_must_be_32_bytes():
    with pytest.raises(ValueError):
        AESGCMEncryptor(b"\x00" * 16)
