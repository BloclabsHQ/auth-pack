"""Tests for oauth_state extensions: verify_state_values, samesite override,
PKCE verifier cookie helpers."""

import pytest
from django.http import HttpResponse
from rest_framework.exceptions import ValidationError

from blockauth.utils.oauth_state import (
    OAUTH_PKCE_VERIFIER_COOKIE_NAME,
    OAUTH_STATE_COOKIE_NAME,
    clear_pkce_verifier_cookie,
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


def test_state_cookie_samesite_override():
    response = HttpResponse()
    set_state_cookie(response, "stateval", samesite="None")
    assert response.cookies[OAUTH_STATE_COOKIE_NAME]["samesite"] == "None"


def test_pkce_verifier_cookie_round_trip(rf):
    response = HttpResponse()
    set_pkce_verifier_cookie(response, "verifier-xyz")
    assert response.cookies[OAUTH_PKCE_VERIFIER_COOKIE_NAME].value == "verifier-xyz"

    request = rf.get("/")
    request.COOKIES[OAUTH_PKCE_VERIFIER_COOKIE_NAME] = "verifier-xyz"
    assert read_pkce_verifier_cookie(request) == "verifier-xyz"

    cleared = HttpResponse()
    clear_pkce_verifier_cookie(cleared)
    assert cleared.cookies[OAUTH_PKCE_VERIFIER_COOKIE_NAME]["max-age"] == 0
