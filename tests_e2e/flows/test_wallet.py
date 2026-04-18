"""Flows: wallet-login (SIWE), wallet-link, wallet-email-add."""

from __future__ import annotations

import uuid

from scripts.sign_siwe import sign_for_login, sign_link_message

PASSWORD = "Str0ng-Passw0rd!42"


def test_wallet_login_creates_user_and_issues_tokens(client):
    address, message, signature = sign_for_login(client.base_url)

    resp = client.post(
        "/auth/login/wallet/",
        json_body={"wallet_address": address, "message": message, "signature": signature},
        expect=200,
    )
    body = resp.json()
    assert body["access"] and body["refresh"]
    assert body["user"]["wallet_address"].lower() == address.lower()


def _signup_and_confirm(client, email):
    client.post(
        "/auth/signup/",
        json_body={"identifier": email, "password": PASSWORD, "method": "email"},
        expect=200,
    )
    code = client.latest_otp(email)
    return client.post(
        "/auth/signup/confirm/",
        json_body={"identifier": email, "code": code},
        expect=200,
    ).json()


def test_wallet_link_flow(client, unique_email):
    """Email-first user links a wallet via the legacy JSON-message signer."""
    # 1. Create an email-first account and log in.
    client.post(
        "/auth/signup/",
        json_body={"identifier": unique_email, "password": PASSWORD, "method": "email"},
        expect=200,
    )
    code = client.latest_otp(unique_email)
    auth = client.post(
        "/auth/signup/confirm/",
        json_body={"identifier": unique_email, "code": code},
        expect=200,
    ).json()
    access = auth["access"]
    assert auth["user"]["wallet_address"] is None

    # 2. Sign the JSON link message with the dev private key.
    address, message, signature = sign_link_message()

    # 3. Link the wallet.
    resp = client.post(
        "/auth/wallet/link/",
        json_body={"wallet_address": address, "message": message, "signature": signature},
        token=access,
        expect=200,
    ).json()
    assert resp["wallet_address"].lower() == address.lower()
    assert resp["user"]["wallet_address"].lower() == address.lower()
    assert resp["user"]["email"] == unique_email
    # Fresh tokens issued so custom claims pick up the newly-linked wallet.
    assert resp["access"] and resp["refresh"]


def test_wallet_link_rejects_nonce_replay(client, unique_email):
    """The same signed message can't be replayed — nonce is single-use."""
    client.post(
        "/auth/signup/",
        json_body={"identifier": unique_email, "password": PASSWORD, "method": "email"},
        expect=200,
    )
    code = client.latest_otp(unique_email)
    auth = client.post(
        "/auth/signup/confirm/",
        json_body={"identifier": unique_email, "code": code},
        expect=200,
    ).json()
    access = auth["access"]

    address, message, signature = sign_link_message()
    client.post(
        "/auth/wallet/link/",
        json_body={"wallet_address": address, "message": message, "signature": signature},
        token=access,
        expect=200,
    )

    # Second attempt reuses the same nonce -> rejected.
    replay = client.post(
        "/auth/wallet/link/",
        json_body={"wallet_address": address, "message": message, "signature": signature},
        token=access,
    )
    assert replay.status_code == 400
    assert "nonce" in replay.text.lower() or "linked" in replay.text.lower()


def test_wallet_email_add_sends_verification(client):
    # Create a wallet-first account via SIWE, then bolt an email onto it.
    address, message, signature = sign_for_login(client.base_url)
    login = client.post(
        "/auth/login/wallet/",
        json_body={"wallet_address": address, "message": message, "signature": signature},
        expect=200,
    ).json()
    access = login["access"]

    email = f"wallet-{uuid.uuid4().hex[:8]}@e2e.test"
    resp = client.post(
        "/auth/wallet/email/add/",
        json_body={"email": email, "verification_type": "otp"},
        token=access,
        expect=200,
    )
    body = resp.json()
    assert body["user"]["email"] == email
    # Verification OTP should have been written.
    assert client.latest_otp(email)
