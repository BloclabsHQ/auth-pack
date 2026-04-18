"""Flows: password reset (OTP + confirm) and password change (authenticated)."""

from __future__ import annotations

PASSWORD = "Str0ng-Passw0rd!42"
NEW_PASSWORD = "An0ther-Strong!55"


def _signup_and_confirm(client, email):
    client.post(
        "/auth/signup/",
        json_body={"identifier": email, "password": PASSWORD, "method": "email"},
        expect=200,
    )
    code = client.latest_otp(email)
    resp = client.post(
        "/auth/signup/confirm/",
        json_body={"identifier": email, "code": code},
        expect=200,
    )
    return resp.json()


def test_password_reset_with_new_password_logs_in(client, unique_email):
    _signup_and_confirm(client, unique_email)

    # Request reset OTP
    client.post(
        "/auth/password/reset/",
        json_body={"identifier": unique_email, "method": "email"},
        expect=200,
    )
    code = client.latest_otp(unique_email)

    # Confirm reset
    confirm = client.post(
        "/auth/password/reset/confirm/",
        json_body={
            "identifier": unique_email,
            "code": code,
            "new_password": NEW_PASSWORD,
            "confirm_password": NEW_PASSWORD,
        },
        expect=200,
    )
    body = confirm.json()
    assert body["access"] and body["refresh"]

    # Old password must no longer work
    fail = client.post(
        "/auth/login/basic/",
        json_body={"identifier": unique_email, "password": PASSWORD},
    )
    assert fail.status_code == 400

    # New password must log in
    client.post(
        "/auth/login/basic/",
        json_body={"identifier": unique_email, "password": NEW_PASSWORD},
        expect=200,
    )


def test_password_change_returns_fresh_tokens(client, unique_email):
    auth = _signup_and_confirm(client, unique_email)
    access = auth["access"]

    resp = client.post(
        "/auth/password/change/",
        json_body={
            "old_password": PASSWORD,
            "new_password": NEW_PASSWORD,
            "confirm_password": NEW_PASSWORD,
        },
        token=access,
        expect=200,
    )
    body = resp.json()
    assert body["access"] and body["refresh"]
    assert body["user"]["email"] == unique_email

    # New password works, old one doesn't
    client.post(
        "/auth/login/basic/",
        json_body={"identifier": unique_email, "password": NEW_PASSWORD},
        expect=200,
    )
    fail = client.post(
        "/auth/login/basic/",
        json_body={"identifier": unique_email, "password": PASSWORD},
    )
    assert fail.status_code == 400
