"""Per-provider rules for auto-linking a new social identity to an existing
User row by email.

Default posture is "do not link" — only providers that are demonstrably
authoritative for the claimed email opt in. The dispatcher keeps the rule for
each provider isolated so future additions (Microsoft, GitHub) get their own
explicit case rather than inheriting a default.
"""

from typing import Any


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

        if provider == "google":
            if not email_verified:
                return False
            if email.lower().endswith("@gmail.com"):
                return True
            if extra_claims.get("hd"):
                return True
            return False

        if provider == "linkedin":
            return bool(email_verified)

        if provider == "facebook":
            return bool(email_verified)

        if provider == "apple":
            return False

        return False
