"""Flow: passwordless login (request OTP -> confirm)."""

from __future__ import annotations


def test_passwordless_new_user_created_and_logged_in(client, unique_email):
    client.post(
        "/auth/login/passwordless/",
        json_body={"identifier": unique_email, "method": "email"},
        expect=200,
    )
    code = client.latest_otp(unique_email)
    confirm = client.post(
        "/auth/login/passwordless/confirm/",
        json_body={"identifier": unique_email, "code": code},
        expect=200,
    )
    body = confirm.json()
    assert body["access"] and body["refresh"]
    assert body["user"]["email"] == unique_email
    assert body["user"]["is_verified"] is True


def test_passwordless_rejects_wrong_code(client, unique_email):
    client.post(
        "/auth/login/passwordless/",
        json_body={"identifier": unique_email, "method": "email"},
        expect=200,
    )
    resp = client.post(
        "/auth/login/passwordless/confirm/",
        json_body={"identifier": unique_email, "code": "000000"},
    )
    assert resp.status_code == 400
