"""Per-provider account linking rules.

Truth table:
| provider | email_verified | gmail or hd | result |
| google   | True           | gmail       | True   |
| google   | True           | hd present  | True   |
| google   | True           | other       | False  |
| google   | False          | any         | False  |
| linkedin | True           | any         | True   |
| linkedin | False          | any         | False  |
| apple    | True           | any         | False  (Apple email never authoritative)
| apple    | False          | any         | False
| facebook | True           | any         | True (email present implies verified)
| facebook | False          | any         | False
"""

import pytest

from blockauth.social.linking_policy import AccountLinkingPolicy


@pytest.mark.parametrize(
    "provider,email,verified,extra,expected",
    [
        ("google", "u@gmail.com", True, {}, True),
        ("google", "u@workspace.com", True, {"hd": "workspace.com"}, True),
        ("google", "u@workspace.com", True, {}, False),
        ("google", "u@gmail.com", False, {}, False),
        ("linkedin", "u@example.com", True, {}, True),
        ("linkedin", "u@example.com", False, {}, False),
        ("apple", "u@example.com", True, {}, False),
        ("apple", "u@privaterelay.appleid.com", True, {}, False),
        ("facebook", "u@example.com", True, {}, True),
        ("facebook", "u@example.com", False, {}, False),
        ("facebook", None, False, {}, False),
    ],
)
def test_can_link_truth_table(provider, email, verified, extra, expected):
    assert (
        AccountLinkingPolicy.can_link_to_existing_user(
            provider=provider, email=email, email_verified=verified, extra_claims=extra
        )
        is expected
    )


def test_unknown_provider_rejects():
    assert (
        AccountLinkingPolicy.can_link_to_existing_user(
            provider="unsupported", email="u@example.com", email_verified=True, extra_claims={}
        )
        is False
    )
