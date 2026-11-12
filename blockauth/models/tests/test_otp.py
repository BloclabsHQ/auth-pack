"""SEC-09: stored OTP codes differ from the code that is delivered."""

import pytest
from rest_framework.exceptions import ValidationError

from blockauth.models.otp import OTP, OTPSubject
from blockauth.notification import send_otp


@pytest.mark.django_db
def test_stored_otp_differs_from_delivered_code(monkeypatch):
    """SEC-09: the stored code is not the delivered code, and the delivered code still validates."""
    delivered = {}

    def notify(self, method, event, context):
        delivered["code"] = context["code"]

    monkeypatch.setattr("blockauth.notification.DummyNotification.notify", notify)
    send_otp(
        {"identifier": "otp@test.com", "method": "email", "verification_type": "otp"},
        OTPSubject.LOGIN,
    )
    stored = OTP.objects.get(identifier="otp@test.com").code
    assert stored != delivered["code"]
    with pytest.raises(ValidationError):
        OTP.validate_otp("otp@test.com", OTPSubject.LOGIN, "wrong-code")
    assert OTP.validate_otp("otp@test.com", OTPSubject.LOGIN, delivered["code"]) is None
