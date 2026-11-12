"""SEC-05: wallet link uses a server-issued challenge."""

import json
import time

import pytest
from django.urls import reverse
from eth_account import Account
from eth_account.messages import encode_defunct
from rest_framework.test import APIClient

from blockauth.utils.config import get_block_auth_user_model

_KEY = "0x" + "3" * 64
_ACCOUNT = Account.from_key(_KEY)


def _user(email):
    User = get_block_auth_user_model()
    user = User(email=email, is_verified=True)
    user.set_password("TestP@ss123!")
    user.save()
    return user


def _sign(message, account=_ACCOUNT):
    signature = account.sign_message(encode_defunct(text=message)).signature.hex()
    return signature if signature.startswith("0x") else "0x" + signature


def _client_json_payload():
    message = json.dumps(
        {
            "body": "Link wallet",
            "nonce": "client-chosen-nonce-1",
            "timestamp": int(time.time()),
        }
    )
    return {
        "wallet_address": _ACCOUNT.address,
        "message": message,
        "signature": _sign(message),
    }


@pytest.mark.django_db
def test_client_built_json_blob_does_not_link():
    """SEC-05: a client-built message with a client-chosen nonce is rejected."""
    user = _user("link-json@example.com")
    client = APIClient()
    client.force_authenticate(user=user)
    response = client.post(reverse("wallet-link"), _client_json_payload(), format="json")
    user.refresh_from_db()
    assert response.status_code != 200
    assert user.wallet_address is None
    assert response.data["error"]["code"] == "malformed_message"


@pytest.mark.django_db
def test_server_challenge_links_once():
    """SEC-05: a server challenge links, and the same signature is rejected again."""
    user = _user("link-ok@example.com")
    client = APIClient()
    client.force_authenticate(user=user)
    issued = client.post(
        reverse("wallet-link-challenge"),
        {"address": _ACCOUNT.address},
        format="json",
    )
    assert issued.status_code == 200
    message = issued.data["message"]
    payload = {
        "wallet_address": _ACCOUNT.address,
        "message": message,
        "signature": _sign(message),
    }
    first = client.post(reverse("wallet-link"), payload, format="json")
    assert first.status_code == 200
    user.refresh_from_db()
    assert user.wallet_address == _ACCOUNT.address.lower()
    replay = client.post(reverse("wallet-link"), payload, format="json")
    assert replay.status_code != 200


@pytest.mark.django_db
def test_link_challenge_is_bound_to_the_authenticated_account():
    """SEC-05: a challenge issued for one account does not link another."""
    owner = _user("link-owner@example.com")
    other = _user("link-other@example.com")
    owner_client = APIClient()
    owner_client.force_authenticate(user=owner)
    issued = owner_client.post(
        reverse("wallet-link-challenge"),
        {"address": _ACCOUNT.address},
        format="json",
    )
    assert issued.status_code == 200
    other_client = APIClient()
    other_client.force_authenticate(user=other)
    response = other_client.post(
        reverse("wallet-link"),
        {
            "wallet_address": _ACCOUNT.address,
            "message": issued.data["message"],
            "signature": _sign(issued.data["message"]),
        },
        format="json",
    )
    other.refresh_from_db()
    assert response.status_code != 200
    assert other.wallet_address is None
