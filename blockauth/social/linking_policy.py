"""Per-provider rules for auto-linking a new social identity to an existing
User row by email.

Default posture is "do not link" — only providers that are demonstrably
authoritative for the claimed email opt in. The dispatcher keeps the rule for
each provider isolated so future additions (Microsoft, GitHub) get their own
explicit case rather than inheriting a default.
"""

from typing import Any, Literal

# Provider literals supported by this policy. Adding a new provider also
# requires adding an explicit branch in `can_link_to_existing_user`.
SupportedProvider = Literal["google", "linkedin", "facebook", "apple"]

GOOGLE_AUTHORITATIVE_DOMAINS = ("@gmail.com", "@googlemail.com")


class AccountLinkingPolicy:
    @staticmethod
    def can_link_to_existing_user(
        *,
        provider: str,
        email: str | None,
        email_verified: bool,
        extra_claims: dict[str, Any],
    ) -> bool:
        if not email:
            return False

        # Normalize provider name once. Upstream callers should pass
        # lowercase, but defending here guards against a Provider /
        # PROVIDER / Google capitalization slip silently falling through
        # to the unknown-provider deny path.
        provider = provider.lower()
        email_lower = email.lower()
        email_domain = email_lower.rsplit("@", 1)[-1] if "@" in email_lower else ""

        if provider == "google":
            if not email_verified:
                return False
            if email_lower.endswith(GOOGLE_AUTHORITATIVE_DOMAINS):
                return True
            hd = extra_claims.get("hd")
            if hd:
                # Cross-validate hd against the email domain. A provider
                # response with `email=admin@evil.com, hd=trusted-corp.com`
                # must NOT pass — Google issues hd as the user's actual
                # Workspace domain, which always matches the email domain.
                if email_domain == str(hd).lower():
                    return True
            return False

        if provider == "linkedin":
            return bool(email_verified)

        if provider == "facebook":
            return bool(email_verified)

        if provider == "apple":
            return False

        return False
