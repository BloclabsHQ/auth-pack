"""Flow: TOTP setup -> confirm -> verify -> status -> disable."""

from __future__ import annotations

import re

import pytest

pyotp = pytest.importorskip(
    "pyotp",
    reason="Install pyotp (uv add --dev pyotp) to run the TOTP flow.",
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


def _extract_secret(provisioning_uri: str) -> str:
    # otpauth://totp/Issuer:Label?secret=BASE32&issuer=Issuer&...
    match = re.search(r"secret=([A-Z2-7]+)", provisioning_uri)
    assert match, provisioning_uri
    return match.group(1)


def test_totp_setup_confirm_verify_disable(client, unique_email):
    auth = _signup_and_confirm(client, unique_email)
    access = auth["access"]

    # Setup
    setup = client.post(
        "/auth/totp/setup/",
        json_body={},
        token=access,
        expect=201,
    ).json()
    secret = setup["secret"] or _extract_secret(setup["provisioning_uri"])
    assert setup["backup_codes"] and len(setup["backup_codes"]) > 0

    # Generate a current code from the secret
    totp = pyotp.TOTP(secret)

    # Confirm
    client.post(
        "/auth/totp/confirm/",
        json_body={"code": totp.now()},
        token=access,
        expect=200,
    )

    # Status
    status = client.get("/auth/totp/status/", token=access, expect=200).json()
    assert status["enabled"] is True

    # Verify
    verify = client.post(
        "/auth/totp/verify/",
        json_body={"code": totp.now()},
        token=access,
        expect=200,
    ).json()
    assert verify["success"] is True

    # Disable (via password — simpler than timing another TOTP code)
    client.post(
        "/auth/totp/disable/",
        json_body={"password": PASSWORD},
        token=access,
        expect=200,
    )
    status2 = client.get("/auth/totp/status/", token=access, expect=200).json()
    assert status2["enabled"] is False
