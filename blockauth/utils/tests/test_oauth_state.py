"""Tests for oauth_state extensions: verify_state_values, samesite override,
PKCE verifier cookie helpers."""

import pytest
from django.http import HttpResponse
from rest_framework.exceptions import ValidationError

from blockauth.utils.oauth_state import (
    clear_pkce_verifier_cookie,
    oauth_pkce_verifier_cookie_name,
    oauth_state_cookie_name,
    read_pkce_verifier_cookie,
    set_pkce_verifier_cookie,
    set_state_cookie,
    verify_state_values,
)


def test_verify_state_values_matching():
    verify_state_values("abc", "abc")


def test_verify_state_values_missing_cookie_raises():
    with pytest.raises(ValidationError):
        verify_state_values(None, "abc")


def test_verify_state_values_missing_provided_raises():
    with pytest.raises(ValidationError):
        verify_state_values("abc", None)


def test_verify_state_values_mismatch_raises():
    with pytest.raises(ValidationError):
        verify_state_values("abc", "xyz")


def test_state_cookie_name_is_provider_suffixed():
    assert oauth_state_cookie_name("google") == "blockauth_oauth_state_google"
    assert oauth_state_cookie_name("facebook") == "blockauth_oauth_state_facebook"
    assert oauth_state_cookie_name("linkedin") == "blockauth_oauth_state_linkedin"
    assert oauth_state_cookie_name("apple") == "blockauth_oauth_state_apple"


def test_pkce_verifier_cookie_name_is_provider_suffixed():
    assert oauth_pkce_verifier_cookie_name("google") == "blockauth_oauth_pkce_google"
    assert oauth_pkce_verifier_cookie_name("apple") == "blockauth_oauth_pkce_apple"


def test_state_cookie_samesite_override():
    response = HttpResponse()
    set_state_cookie(response, "stateval", provider="apple", samesite="None")
    assert response.cookies[oauth_state_cookie_name("apple")]["samesite"] == "None"


def test_pkce_verifier_cookie_round_trip(rf):
    response = HttpResponse()
    set_pkce_verifier_cookie(response, "verifier-xyz", provider="google")
    assert response.cookies[oauth_pkce_verifier_cookie_name("google")].value == "verifier-xyz"

    request = rf.get("/")
    request.COOKIES[oauth_pkce_verifier_cookie_name("google")] = "verifier-xyz"
    assert read_pkce_verifier_cookie(request, provider="google") == "verifier-xyz"

    cleared = HttpResponse()
    clear_pkce_verifier_cookie(cleared, provider="google")
    assert cleared.cookies[oauth_pkce_verifier_cookie_name("google")]["max-age"] == 0


def test_pkce_verifier_round_trip_isolated_per_provider(rf):
    """Two concurrent OAuth flows do not stomp each other's PKCE verifier."""
    request = rf.get("/")
    request.COOKIES[oauth_pkce_verifier_cookie_name("google")] = "g-verifier"
    request.COOKIES[oauth_pkce_verifier_cookie_name("apple")] = "a-verifier"
    assert read_pkce_verifier_cookie(request, provider="google") == "g-verifier"
    assert read_pkce_verifier_cookie(request, provider="apple") == "a-verifier"
