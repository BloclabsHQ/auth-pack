"""Flows: signup -> confirm -> basic login -> refresh."""

from __future__ import annotations


PASSWORD = "Str0ng-Passw0rd!42"


def test_signup_confirm_login_refresh(client, unique_email):
    # 1. Signup (sends OTP)
    resp = client.post(
        "/auth/signup/",
        json_body={"identifier": unique_email, "password": PASSWORD, "method": "email"},
        expect=200,
    )
    assert "sent" in resp.json()["message"].lower()

    # 2. Retrieve OTP from dev-only endpoint and confirm
    code = client.latest_otp(unique_email)
    confirm = client.post(
        "/auth/signup/confirm/",
        json_body={"identifier": unique_email, "code": code},
        expect=200,
    )
    body = confirm.json()
    assert body["access"] and body["refresh"]
    assert body["user"]["email"] == unique_email
    assert body["user"]["is_verified"] is True

    # 3. Basic login using the password set at signup
    login = client.post(
        "/auth/login/basic/",
        json_body={"identifier": unique_email, "password": PASSWORD},
        expect=200,
    )
    login_body = login.json()
    assert login_body["user"]["email"] == unique_email
    refresh_token = login_body["refresh"]

    # 4. Refresh the tokens
    refreshed = client.post(
        "/auth/token/refresh/",
        json_body={"refresh_token": refresh_token},
        expect=200,
    )
    rb = refreshed.json()
    assert rb["access"] and rb["refresh"]
    assert rb["user"]["email"] == unique_email
    # Rotation: new refresh token must differ
    assert rb["refresh"] != refresh_token


def test_signup_resend_otp_same_account(client, unique_email):
    client.post(
        "/auth/signup/",
        json_body={"identifier": unique_email, "password": PASSWORD, "method": "email"},
        expect=200,
    )
    resend = client.post(
        "/auth/signup/otp/resend/",
        json_body={"identifier": unique_email, "method": "email"},
        expect=200,
    )
    # Response is intentionally opaque to prevent enumeration.
    assert "verification" in resend.json()["message"].lower() or "sent" in resend.json()["message"].lower()


def test_basic_login_rejects_bad_password(client, unique_email):
    client.post(
        "/auth/signup/",
        json_body={"identifier": unique_email, "password": PASSWORD, "method": "email"},
        expect=200,
    )
    code = client.latest_otp(unique_email)
    client.post(
        "/auth/signup/confirm/",
        json_body={"identifier": unique_email, "code": code},
        expect=200,
    )
    resp = client.post(
        "/auth/login/basic/",
        json_body={"identifier": unique_email, "password": "wrong-password-xx"},
    )
    assert resp.status_code == 400
