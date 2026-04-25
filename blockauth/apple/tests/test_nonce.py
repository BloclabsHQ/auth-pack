"""Apple nonce helper tests."""

import hashlib

import pytest
from django.http import HttpResponse

from blockauth.apple.nonce import (
    APPLE_NONCE_COOKIE_NAME,
    clear_nonce_cookie,
    generate_raw_nonce,
    hash_raw_nonce,
    read_nonce_cookie,
    set_nonce_cookie,
)


def test_raw_nonce_is_url_safe_random():
    a = generate_raw_nonce()
    b = generate_raw_nonce()
    assert a != b
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    assert set(a).issubset(allowed)


def test_hash_is_sha256_hex_of_raw_value():
    raw = "abc"
    expected = hashlib.sha256(b"abc").hexdigest()
    assert hash_raw_nonce(raw) == expected


def test_cookie_set_clear_round_trip(rf):
    response = HttpResponse()
    set_nonce_cookie(response, "raw-nonce-value")
    assert response.cookies[APPLE_NONCE_COOKIE_NAME].value == "raw-nonce-value"

    request = rf.get("/")
    request.COOKIES[APPLE_NONCE_COOKIE_NAME] = "raw-nonce-value"
    assert read_nonce_cookie(request) == "raw-nonce-value"

    cleared = HttpResponse()
    clear_nonce_cookie(cleared)
    assert cleared.cookies[APPLE_NONCE_COOKIE_NAME]["max-age"] == 0
