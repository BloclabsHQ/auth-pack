"""SocialIdentityService.

Single entrypoint `upsert_and_link` consolidates the four cases an OAuth/OIDC
sign-in can produce:
  1. Existing (provider, subject) — return the linked user.
  2. New (provider, subject), email matches existing User, policy permits — link.
  3. New (provider, subject), email matches existing User, policy rejects — raise.
  4. No email match — create a new User.

Refresh tokens are encrypted with `AESGCMEncryptor` and stored as the
`encrypted_refresh_token` blob; the AAD binds each ciphertext to the
(provider, subject) pair so a stolen blob from one identity cannot be
replayed onto another row.

Plan deviations:
  - User model is resolved via `django.contrib.auth.get_user_model()` rather
    than `blockauth.utils.config.get_block_auth_user_model()`. The
    `SocialIdentity.user` FK targets `settings.AUTH_USER_MODEL`; the
    service must query the same model the FK points at. Same fix used
    in Task 2.3.
  - New-user creation goes through `User.objects.create_user(username=...,
    email=..., password=None)` rather than the plan's
    `User.objects.create(email=..., is_verified=...)`. The latter fails
    against `auth.User` (no `is_verified` field, required `username`).
    `create_user(password=None)` produces an unusable password (Django
    default), so the integrator's password-reset flow still works.
"""

import base64
import logging
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction

from blockauth.social.encryption import AESGCMEncryptor
from blockauth.social.exceptions import SocialIdentityConflictError
from blockauth.social.linking_policy import AccountLinkingPolicy
from blockauth.social.models import SocialIdentity

logger = logging.getLogger(__name__)


def _load_encryptor() -> AESGCMEncryptor | None:
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    key_b64 = block_settings.get("SOCIAL_IDENTITY_ENCRYPTION_KEY")
    if not key_b64:
        return None
    return AESGCMEncryptor(base64.b64decode(key_b64))


def _aad_for(provider: str, subject: str) -> bytes:
    return f"social_identity:{provider}:{subject}".encode("utf-8")


class SocialIdentityService:
    def __init__(self, encryptor: AESGCMEncryptor | None = None):
        self._encryptor = encryptor or _load_encryptor()

    @transaction.atomic
    def upsert_and_link(
        self,
        *,
        provider: str,
        subject: str,
        email: str | None,
        email_verified: bool,
        extra_claims: dict[str, Any],
        refresh_token: str | None = None,
    ) -> tuple[Any, SocialIdentity, bool]:
        User = get_user_model()

        existing_identity = (
            SocialIdentity.objects.select_related("user")
            .filter(provider=provider, subject=subject)
            .first()
        )
        if existing_identity is not None:
            self._maybe_store_refresh(existing_identity, refresh_token, provider, subject)
            existing_identity.save(update_fields=["last_used_at", "encrypted_refresh_token"])
            logger.info(
                "social_identity.matched_existing_subject",
                extra={"provider": provider, "user_id": str(existing_identity.user.id)},
            )
            return existing_identity.user, existing_identity, False

        existing_user = User.objects.filter(email=email).first() if email else None
        if existing_user is not None:
            if not AccountLinkingPolicy.can_link_to_existing_user(
                provider=provider,
                email=email,
                email_verified=email_verified,
                extra_claims=extra_claims,
            ):
                logger.warning(
                    "social_identity.linking_rejected_unverified_email",
                    extra={
                        "provider": provider,
                        "email_domain_only": (email or "").split("@")[-1],
                    },
                )
                raise SocialIdentityConflictError(
                    provider=provider, existing_user_id=str(existing_user.id)
                )

            identity = SocialIdentity(
                provider=provider,
                subject=subject,
                user=existing_user,
                email_at_link=email,
                email_verified_at_link=email_verified,
            )
            self._maybe_store_refresh(identity, refresh_token, provider, subject)
            identity.save()
            logger.info(
                "social_identity.linked_to_existing_user",
                extra={
                    "provider": provider,
                    "user_id": str(existing_user.id),
                    "linking_reason": self._linking_reason(provider, email, extra_claims),
                },
            )
            return existing_user, identity, False

        # New-user creation. See module docstring for the rationale behind
        # `create_user` (model-agnostic) vs. the plan's `objects.create(...)`.
        # `username` is required by `auth.User`; we derive it from email or
        # synthesize one from (provider, subject) to guarantee uniqueness
        # for users without an email (e.g., Apple "hide my email" without
        # a relay address, edge case). Truncated to Django's 150-char limit.
        username = email if email else f"social_{provider}_{subject}"
        username = username[:150]
        new_user = User.objects.create_user(
            username=username,
            email=email or "",
            password=None,
        )
        identity = SocialIdentity(
            provider=provider,
            subject=subject,
            user=new_user,
            email_at_link=email,
            email_verified_at_link=email_verified,
        )
        self._maybe_store_refresh(identity, refresh_token, provider, subject)
        identity.save()
        logger.info(
            "social_identity.created_new_user",
            extra={"provider": provider, "user_id": str(new_user.id)},
        )
        return new_user, identity, True

    def decrypt_refresh_token(self, identity: SocialIdentity) -> str | None:
        if identity.encrypted_refresh_token is None or self._encryptor is None:
            return None
        return self._encryptor.decrypt(
            bytes(identity.encrypted_refresh_token),
            _aad_for(identity.provider, identity.subject),
        )

    def _maybe_store_refresh(
        self,
        identity: SocialIdentity,
        refresh_token: str | None,
        provider: str,
        subject: str,
    ) -> None:
        if refresh_token is None:
            return
        if self._encryptor is None:
            logger.warning(
                "social_identity.refresh_token_dropped_no_key",
                extra={"provider": provider},
            )
            return
        identity.encrypted_refresh_token = self._encryptor.encrypt(
            refresh_token, _aad_for(provider, subject)
        )

    @staticmethod
    def _linking_reason(provider: str, email: str | None, extra: dict[str, Any]) -> str:
        if provider == "google" and email and email.lower().endswith("@gmail.com"):
            return "google_authoritative_domain"
        if provider == "google" and extra.get("hd"):
            return "google_workspace_domain"
        if provider == "linkedin":
            return "linkedin_email_verified"
        if provider == "facebook":
            return "facebook_email_present"
        return "unknown"
