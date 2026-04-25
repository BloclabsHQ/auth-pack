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

import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction

from blockauth.social.encryption import AESGCMEncryptor, aad_for, load_encryptor
from blockauth.social.exceptions import SocialIdentityConflictError
from blockauth.social.linking_policy import AccountLinkingPolicy
from blockauth.social.models import SocialIdentity

logger = logging.getLogger(__name__)


class SocialIdentityService:
    def __init__(self, encryptor: AESGCMEncryptor | None = None):
        self._encryptor = encryptor or load_encryptor()

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
            SocialIdentity.objects.select_related("user").filter(provider=provider, subject=subject).first()
        )
        if existing_identity is not None:
            refresh_changed = self._maybe_store_refresh(existing_identity, refresh_token, provider, subject)
            update_fields = ["last_used_at"]
            if refresh_changed:
                update_fields.append("encrypted_refresh_token")
            existing_identity.save(update_fields=update_fields)
            logger.info(
                "social_identity.matched_existing_subject",
                extra={"provider": provider, "user_id": str(existing_identity.user.id)},
            )
            return existing_identity.user, existing_identity, False

        # Case-insensitive email match: a stored "CaseUser@Gmail.com" must still
        # match an IdP-returned "caseuser@gmail.com" (RFC 5321 §2.4 — local-part
        # is technically case-sensitive, but virtually all real mail providers
        # treat it case-insensitively, and downstream views normalize on
        # ingress). Using __iexact prevents a duplicate User row on
        # already-existing accounts whose email differs only in case.
        # `.order_by("id")` makes the choice deterministic across replicas if
        # legacy data has two users sharing the same email modulo case. Without
        # it, .first() ordering is unspecified.
        existing_user = User.objects.filter(email__iexact=email).order_by("id").first() if email else None
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
                raise SocialIdentityConflictError(provider=provider, existing_user_id=str(existing_user.id))

            identity = SocialIdentity(
                provider=provider,
                subject=subject,
                user=existing_user,
                email_at_link=email,
                email_verified_at_link=email_verified,
            )
            self._maybe_store_refresh(identity, refresh_token, provider, subject)
            try:
                identity.save()
            except IntegrityError:
                # Concurrency race: another sign-in for the same (provider,
                # subject) won the unique-constraint coin flip. Re-fetch the
                # winner and return that. The @transaction.atomic decorator
                # rolls back any half-applied state from this call. (See
                # `_recover_from_race` for details.)
                return self._recover_from_race(provider, subject, refresh_token)
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
        try:
            identity.save()
        except IntegrityError:
            # Lost the race against a concurrent sign-in. The @transaction.atomic
            # decorator on this method ensures the just-created `new_user`
            # row is rolled back along with everything else, so we won't leak
            # an orphan User. Re-fetch the winning identity and return it.
            return self._recover_from_race(provider, subject, refresh_token)
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
            aad_for(identity.provider, identity.subject),
        )

    def _maybe_store_refresh(
        self,
        identity: SocialIdentity,
        refresh_token: str | None,
        provider: str,
        subject: str,
    ) -> bool:
        """Encrypt and stage `refresh_token` on `identity` if conditions allow.

        Returns True iff `identity.encrypted_refresh_token` was actually
        mutated. Callers use the bool to decide whether to include the field
        in `save(update_fields=...)`, so logins that don't carry a fresh
        refresh token avoid a needless write.
        """
        if refresh_token is None:
            return False
        if self._encryptor is None:
            logger.warning(
                "social_identity.refresh_token_dropped_no_key",
                extra={"provider": provider},
            )
            return False
        identity.encrypted_refresh_token = self._encryptor.encrypt(refresh_token, aad_for(provider, subject))
        return True

    def _recover_from_race(
        self,
        provider: str,
        subject: str,
        refresh_token: str | None,
    ) -> tuple[Any, SocialIdentity, bool]:
        """Re-fetch the (provider, subject) winner after a lost-race IntegrityError.

        Called from the IntegrityError handlers in upsert_and_link. The outer
        @transaction.atomic has already rolled back any partial state from
        this call (including a freshly-created User in Branch 4). We bump
        last_used_at on the winner so the caller still sees a "saw this
        identity recently" signal.
        """
        winner = SocialIdentity.objects.select_related("user").get(provider=provider, subject=subject)
        # Don't re-store the refresh token here — the winning insert already
        # wrote the AAD-bound ciphertext (or decided not to). Updating it on
        # the loser's behalf would write a different ciphertext under an AAD
        # that's already valid, with no benefit.
        winner.save(update_fields=["last_used_at"])
        logger.info(
            "social_identity.race_recovered",
            extra={"provider": provider, "user_id": str(winner.user.id)},
        )
        return winner.user, winner, False

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
