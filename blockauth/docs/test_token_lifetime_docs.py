"""SEC-20: docs state the access-token lifetime default."""

from datetime import timedelta
from pathlib import Path

from blockauth.conf import DEFAULTS

_ROOT = Path(__file__).resolve().parents[2]


def _read(relative: str) -> str:
    return (_ROOT / relative).read_text(encoding="utf-8")


def _setting_comment(source: str, key: str) -> str:
    lines = source.splitlines()
    needle = f'"{key}"'
    for index, line in enumerate(lines):
        if needle not in line:
            continue
        comments = []
        cursor = index - 1
        while cursor >= 0 and lines[cursor].strip().startswith("#"):
            comments.append(lines[cursor].strip().lstrip("#").strip())
            cursor -= 1
        return "\n".join(reversed(comments))
    raise AssertionError(f"{key} default not found")


def test_access_token_lifetime_default_is_3600_seconds():
    assert DEFAULTS["ACCESS_TOKEN_LIFETIME"] == timedelta(seconds=3600)


def test_conf_comment_states_lifetime_guidance():
    source = _read("blockauth/conf.py")
    comment = _setting_comment(source, "ACCESS_TOKEN_LIFETIME").lower()
    assert "3600" in comment
    assert "15 minutes" in comment


def test_security_standards_state_default_and_recommendation():
    text = _read("docs/security/security-standards.md").lower()
    assert "3600" in text
    assert "15 minutes" in text


def test_token_usage_guide_states_default_and_recommendation():
    text = _read("docs/TOKEN_USAGE_GUIDE.md").lower()
    assert "3600" in text
    assert "15 minutes" in text
