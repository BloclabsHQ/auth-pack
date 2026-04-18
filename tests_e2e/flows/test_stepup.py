"""Flow: step-up receipt issue + validate (RFC 9470 shape)."""

from __future__ import annotations


def test_stepup_receipt_roundtrip(client):
    issue = client.post(
        "/auth/_test/stepup/issue/",
        json_body={"subject": "user-42"},
        expect=200,
    ).json()
    receipt = issue["receipt"]

    ok = client.post(
        "/auth/_test/stepup/validate/",
        json_body={"receipt": receipt, "expected_subject": "user-42"},
        expect=200,
    ).json()
    assert ok["valid"] is True
    assert ok["subject"] == "user-42"
    assert ok["audience"] == "e2e-wallet"
    assert ok["scope"] == "mpc"


def test_stepup_rejects_wrong_subject(client):
    issue = client.post(
        "/auth/_test/stepup/issue/",
        json_body={"subject": "user-42"},
        expect=200,
    ).json()
    resp = client.post(
        "/auth/_test/stepup/validate/",
        json_body={"receipt": issue["receipt"], "expected_subject": "someone-else"},
    )
    assert resp.status_code == 401
    assert resp.json()["code"] == "receipt_subject_mismatch"
