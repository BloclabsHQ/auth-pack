"""Regression tests for log-context sanitization of password fields.

Guards against re-introducing the plaintext-credential leak where the password
change / reset-confirm success paths logged raw ``request.data`` and the
sanitizer did not know about the ``*_password`` field names.
"""

from blockauth.constants import REDACTION_STRING, SENSITIVE_FIELDS
from blockauth.utils.generics import sanitize_log_context

# The exact request-body keys used by the password change / reset / email-change
# serializers. Every one carries a secret and must never reach a log sink.
PASSWORD_FIELDS = [
    "password",
    "old_password",
    "new_password",
    "confirm_password",
    "current_password",
    "hashed_password",
]


def test_password_fields_are_in_sensitive_fields():
    for field in PASSWORD_FIELDS:
        assert field in SENSITIVE_FIELDS, f"{field} must be redacted in logs"


def test_change_password_payload_is_fully_redacted():
    payload = {
        "old_password": "currentSecret123!",
        "new_password": "brandNewSecret456!",
        "confirm_password": "brandNewSecret456!",
    }

    sanitized = sanitize_log_context(payload, {"user": "user-1"})

    assert sanitized["user"] == "user-1"
    for field in ("old_password", "new_password", "confirm_password"):
        assert sanitized[field] == REDACTION_STRING
    # No raw secret value survives anywhere in the emitted context.
    assert "currentSecret123!" not in sanitized.values()
    assert "brandNewSecret456!" not in sanitized.values()


def test_reset_confirm_payload_redacts_new_password_and_token():
    payload = {
        "new_password": "freshSecret789!",
        "confirm_password": "freshSecret789!",
        "token": "reset-token-abc",
    }

    sanitized = sanitize_log_context(payload, {"user": "user-2"})

    assert sanitized["new_password"] == REDACTION_STRING
    assert sanitized["confirm_password"] == REDACTION_STRING
    assert sanitized["token"] == REDACTION_STRING
    assert "freshSecret789!" not in sanitized.values()


def test_non_sensitive_fields_pass_through_unredacted():
    sanitized = sanitize_log_context({"email": "creator@example.test", "remember": True})

    assert sanitized["email"] == "creator@example.test"
    assert sanitized["remember"] is True


def test_sensitive_key_in_additional_context_is_redacted():
    # Regression: additional_context used to be merged AFTER sanitizing data,
    # so a sensitive key passed there (e.g. a decoded JWT under "payload")
    # leaked through unredacted.
    sanitized = sanitize_log_context(
        {"refresh_token": "raw-refresh"},
        {"payload": {"type": "access", "sub": "user-1"}, "user": "user-1"},
    )

    assert sanitized["payload"] == REDACTION_STRING
    assert sanitized["refresh_token"] == REDACTION_STRING
    assert sanitized["user"] == "user-1"


def test_additional_context_still_overrides_data_keys():
    # Preserve prior behaviour: additional_context wins on key conflicts.
    sanitized = sanitize_log_context({"user": "from-data"}, {"user": "from-context"})

    assert sanitized["user"] == "from-context"
