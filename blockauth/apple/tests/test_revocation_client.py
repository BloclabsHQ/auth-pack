"""AppleRevocationClient tests.

Behavior contract: POST to /auth/revoke with token + token_type_hint and the
ES256 client_secret. Treats HTTP 200 as success. On non-200 OR network error,
logs and returns without raising — Apple deletion must continue regardless of
network state.
"""

from unittest.mock import MagicMock, patch

import pytest
from django.test import override_settings

from blockauth.apple.revocation_client import AppleRevocationClient


@pytest.fixture
def es256_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


@pytest.fixture
def configured(es256_keypair):
    private_pem, _ = es256_keypair
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_TEAM_ID": "TEAMID",
            "APPLE_KEY_ID": "KEYID",
            "APPLE_PRIVATE_KEY_PEM": private_pem,
            "APPLE_SERVICES_ID": "com.example.services",
        }
    ):
        yield


def test_revoke_posts_to_apple(configured):
    success_response = MagicMock(status_code=200, text="")
    with patch("blockauth.apple.revocation_client.requests.post", return_value=success_response) as mock_post:
        AppleRevocationClient().revoke("apple-refresh-token")

    assert mock_post.call_count == 1
    call = mock_post.call_args
    assert call.args[0] == "https://appleid.apple.com/auth/revoke"
    assert call.kwargs["data"]["token"] == "apple-refresh-token"
    assert call.kwargs["data"]["token_type_hint"] == "refresh_token"
    assert call.kwargs["data"]["client_id"] == "com.example.services"


def test_revoke_swallows_non_200(configured):
    failing_response = MagicMock(status_code=500, text="server error")
    with patch("blockauth.apple.revocation_client.requests.post", return_value=failing_response):
        # Must not raise.
        AppleRevocationClient().revoke("apple-refresh-token")


def test_revoke_swallows_network_error(configured):
    import requests as real_requests

    with patch(
        "blockauth.apple.revocation_client.requests.post",
        side_effect=real_requests.exceptions.ConnectionError("no network"),
    ):
        # Must not raise.
        AppleRevocationClient().revoke("apple-refresh-token")
