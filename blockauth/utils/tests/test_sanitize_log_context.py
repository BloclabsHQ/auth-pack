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


# ---------------------------------------------------------------------------
# Recursive redaction — secrets nested under non-sensitive keys must not leak.
# ---------------------------------------------------------------------------


def _flatten_values(obj):
    """Yield every scalar value in a nested dict/list for leak assertions."""
    out = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_flatten_values(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(_flatten_values(v))
    else:
        out.append(obj)
    return out


def test_nested_sensitive_key_under_innocuous_key_is_redacted():
    # Regression: a sensitive key one level down (here under "profile") used to
    # survive because redaction only looked at top-level keys.
    sanitized = sanitize_log_context({"profile": {"email": "creator@example.test", "password": "topSecret123!"}})

    assert sanitized["profile"]["email"] == "creator@example.test"
    assert sanitized["profile"]["password"] == REDACTION_STRING
    assert "topSecret123!" not in _flatten_values(sanitized)


def test_deeply_nested_sensitive_value_is_redacted():
    sanitized = sanitize_log_context({"a": {"b": {"c": {"new_password": "deepSecret!"}}}})

    assert sanitized["a"]["b"]["c"]["new_password"] == REDACTION_STRING
    assert "deepSecret!" not in _flatten_values(sanitized)


def test_sensitive_key_redacts_whole_subtree_not_just_leaves():
    # A sensitive key blanks its entire value — we never expose the structure or
    # length of a secret payload by walking into it.
    sanitized = sanitize_log_context({"payload": {"sub": "user-1", "scope": "admin"}})

    assert sanitized["payload"] == REDACTION_STRING


def test_secrets_inside_lists_of_dicts_are_redacted():
    sanitized = sanitize_log_context({"sessions": [{"id": 1, "token": "raw-a"}, {"id": 2, "token": "raw-b"}]})

    assert sanitized["sessions"][0]["id"] == 1
    assert sanitized["sessions"][0]["token"] == REDACTION_STRING
    assert sanitized["sessions"][1]["token"] == REDACTION_STRING
    assert "raw-a" not in _flatten_values(sanitized)
    assert "raw-b" not in _flatten_values(sanitized)


def test_pattern_matched_keys_are_redacted():
    # Keys not enumerated in SENSITIVE_FIELDS but caught by SENSITIVE_PATTERNS
    # (defence-in-depth for unknown nested data).
    sanitized = sanitize_log_context({"user_password": "p1", "x_api_token": "t1", "wallet_secret": "s1"})

    assert sanitized["user_password"] == REDACTION_STRING
    assert sanitized["x_api_token"] == REDACTION_STRING
    assert sanitized["wallet_secret"] == REDACTION_STRING
    for raw in ("p1", "t1", "s1"):
        assert raw not in _flatten_values(sanitized)


def test_runaway_depth_fails_safe_to_redaction():
    # Build a structure deeper than the recursion ceiling; the over-deep tail
    # must collapse to the redaction string rather than recurse unbounded.
    root = inner = {}
    for _ in range(20):
        child = {}
        inner["next"] = child
        inner = child
    inner["leaf"] = "buried"

    sanitized = sanitize_log_context(root)

    assert "buried" not in _flatten_values(sanitized)


def test_scalars_and_clean_nesting_pass_through():
    sanitized = sanitize_log_context({"count": 3, "meta": {"ok": True, "items": ["a", "b"]}})

    assert sanitized["count"] == 3
    assert sanitized["meta"] == {"ok": True, "items": ["a", "b"]}
