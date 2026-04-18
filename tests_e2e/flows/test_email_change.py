"""Flow: authenticated email change (request OTP -> confirm)."""

from __future__ import annotations

import uuid

PASSWORD = "Str0ng-Passw0rd!42"


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


def test_email_change_updates_user_and_issues_fresh_tokens(client, unique_email):
    auth = _signup_and_confirm(client, unique_email)
    access = auth["access"]

    new_email = f"rotated-{uuid.uuid4().hex[:10]}@e2e.test"
    client.post(
        "/auth/email/change/",
        json_body={
            "new_email": new_email,
            "current_password": PASSWORD,
            "verification_type": "otp",
        },
        token=access,
        expect=200,
    )

    code = client.latest_otp(new_email)
    confirm = client.post(
        "/auth/email/change/confirm/",
        json_body={"identifier": new_email, "code": code},
        token=access,
        expect=200,
    )
    body = confirm.json()
    assert body["user"]["email"] == new_email
    assert body["access"] and body["refresh"]

    # Login with new email works, old email does not.
    client.post(
        "/auth/login/basic/",
        json_body={"identifier": new_email, "password": PASSWORD},
        expect=200,
    )
    fail = client.post(
        "/auth/login/basic/",
        json_body={"identifier": unique_email, "password": PASSWORD},
    )
    assert fail.status_code == 400
