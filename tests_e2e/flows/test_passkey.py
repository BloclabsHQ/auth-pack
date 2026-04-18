"""Flow: passkey / WebAuthn register + authenticate.

Skipped unless ``soft-webauthn`` is installed — the dependency is
optional because it is only used for the E2E scenario. Install with::

    uv add --dev soft-webauthn
"""

from __future__ import annotations

import pytest

pytest.importorskip(
    "soft_webauthn",
    reason="Install soft-webauthn (uv add --dev soft-webauthn) to run the passkey flow.",
)

from scripts.webauthn_client import (  # noqa: E402
    authentication_response,
    make_device,
    registration_response,
)

PASSWORD = "Str0ng-Passw0rd!42"


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


def test_passkey_register_and_authenticate(client, unique_email):
    auth = _signup_and_confirm(client, unique_email)
    access = auth["access"]

    device = make_device(client.base_url)

    # Registration
    options = client.post(
        "/auth/passkey/register/options/",
        json_body={"display_name": "E2E Device"},
        token=access,
        expect=200,
    ).json()
    reg_response = registration_response(device, options)
    client.post(
        "/auth/passkey/register/verify/",
        json_body=reg_response,
        token=access,
        expect=201,
    )

    # Authentication
    auth_options = client.post(
        "/auth/passkey/auth/options/",
        json_body={"username": unique_email},
        expect=200,
    ).json()
    auth_resp = authentication_response(device, auth_options)
    body = client.post(
        "/auth/passkey/auth/verify/",
        json_body=auth_resp,
        expect=200,
    ).json()
    assert body["access"] and body["refresh"]
    assert body["user"]["email"] == unique_email

    # Credential list + delete
    listing = client.get("/auth/passkey/credentials/", token=access, expect=200).json()
    assert listing["count"] >= 1
    cred_id = listing["credentials"][0]["id"]
    client.request(
        "DELETE",
        f"/auth/passkey/credentials/{cred_id}/",
        token=access,
        expect=204,
    )
