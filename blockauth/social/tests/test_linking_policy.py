"""Per-provider account linking rules.

Truth table (matches blockauth/social/linking_policy.py):
| provider | email_verified | gmail or hd-match | result                                      |
| google   | True           | gmail.com         | True                                        |
| google   | True           | googlemail.com    | True                                        |
| google   | True           | hd matches email  | True                                        |
| google   | True           | hd MISMATCH email | False (defense-in-depth)                    |
| google   | True           | other (no hd)     | False                                       |
| google   | False          | any               | False                                       |
| linkedin | True           | any               | True                                        |
| linkedin | False          | any               | False                                       |
| apple    | True           | any               | False (Apple email never authoritative)     |
| apple    | False          | any               | False                                       |
| facebook | True           | any               | True (caller maps email-present -> verified)|
| facebook | False          | any               | False                                       |
| any      | any            | email empty/None  | False                                       |
| GOOGLE   | True           | gmail.com         | True (provider name normalized)             |
"""

import pytest

from blockauth.social.linking_policy import AccountLinkingPolicy


@pytest.mark.parametrize(
    "provider,email,verified,extra,expected",
    [
        # Google authoritative domains
        ("google", "u@gmail.com", True, {}, True),
        ("google", "u@googlemail.com", True, {}, True),
        ("google", "USER@GMAIL.COM", True, {}, True),  # case-insensitive email
        # Google Workspace via hd claim — must cross-validate
        ("google", "u@workspace.com", True, {"hd": "workspace.com"}, True),
        ("google", "u@workspace.com", True, {"hd": "WORKSPACE.COM"}, True),  # hd case-insensitive
        # Google Workspace hd MISMATCH — defense-in-depth: must reject
        ("google", "admin@evil.com", True, {"hd": "trusted-corp.com"}, False),
        # Google rejection paths
        ("google", "u@workspace.com", True, {}, False),
        ("google", "u@gmail.com", False, {}, False),
        # LinkedIn
        ("linkedin", "u@example.com", True, {}, True),
        ("linkedin", "u@example.com", False, {}, False),
        # Apple — never authoritative
        ("apple", "u@example.com", True, {}, False),
        ("apple", "u@privaterelay.appleid.com", True, {}, False),
        # Facebook
        ("facebook", "u@example.com", True, {}, True),
        ("facebook", "u@example.com", False, {}, False),
        # Empty / None email — universal reject
        ("facebook", None, False, {}, False),
        ("google", "", True, {}, False),
        ("linkedin", None, True, {}, False),
        # Provider name capitalization — must normalize
        ("GOOGLE", "u@gmail.com", True, {}, True),
        ("Google", "u@gmail.com", True, {}, True),
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
