"""RFC 7636 PKCE pair generation tests."""

import base64
import hashlib

import pytest

from blockauth.utils.pkce import generate_pkce_pair


def test_pair_lengths_match_rfc_7636():
    verifier, challenge = generate_pkce_pair()
    assert 43 <= len(verifier) <= 128
    assert len(challenge) == 43  # base64url(sha256) without padding is always 43


def test_challenge_is_sha256_of_verifier():
    verifier, challenge = generate_pkce_pair()
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    assert challenge == expected


def test_two_calls_produce_distinct_pairs():
    a = generate_pkce_pair()
    b = generate_pkce_pair()
    assert a != b


def test_verifier_charset_is_url_safe():
    verifier, _ = generate_pkce_pair()
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    assert set(verifier).issubset(allowed)
