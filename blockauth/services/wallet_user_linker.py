"""
Link a verified wallet address to a user and mint the auth tokens.

This is the last mile after :class:`WalletLoginService.verify_login` returns.
Kept separate from the signature-verification service so that file has one
responsibility (nonce + SIWE) and this file has one responsibility (user
lookup / creation + JWT issuance + trigger fan-out).

Hardening applied here (issue #90):

* #1 Auto-create race -> no 500. ``get_or_create`` inside
  ``transaction.atomic()`` so the losing side of a concurrent first-login
  for an unseen address returns the existing row instead of tripping the
  unique constraint.
* #2 Trigger fan-out must not block or lose events. Triggers fire via
  ``transaction.on_commit`` so the user-facing response is never held up on
  the event bus, and a raising trigger is caught + logged rather than
  silently dropping the signup broadcast (the user row was already saved,
  so a naive exception would permanently skip the "post-signup" fan-out).
* #4 Registration oracle. When ``WALLET_LOGIN_AUTO_CREATE=False``, unknown
  addresses used to return 403 ``auto_create_disabled`` while known addresses
  returned 200 -- a registration scanner for anyone with a wallet. The
  service now surfaces a ``login_failed`` code that the view maps to 401.
  Deployments that want the explicit 403 can opt in via
  ``WALLET_LOGIN_EXPOSE_REGISTRATION_STATUS=True``.
* #6 Silent ImportError fallback in token issuance. We keep the
  ``generate_auth_token_with_custom_claims`` fast path, but if it isn't
  available we emit a ``logger.warning`` rather than silently dropping
  custom claims. On a real blockauth downgrade that's the tail that gives
  the operator the ring-pull.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Tuple

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from blockauth.enums import AuthenticationType
from blockauth.utils.config import get_block_auth_user_model, get_config
from blockauth.utils.generics import model_to_json
from blockauth.utils.token import AUTH_TOKEN_CLASS, generate_auth_token

logger = logging.getLogger(__name__)


class WalletUserLinkError(Exception):
    """Raised when we refuse to create or fetch a user for a verified wallet."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class LinkedUser:
    """Output of :meth:`WalletUserLinker.link`.

    ``user`` carries the Django model instance so the caller can serialise
    a user payload into the HTTP response without an extra DB round-trip.
    The field is typed ``Any`` to avoid importing the concrete user model
    at class-definition time (it varies per deployment).
    """

    user_id: str
    email: str
    access_token: str
    refresh_token: str
    created: bool
    user: Any = None


class WalletUserLinker:
    """Look up or (optionally) create the user backing a verified wallet."""

    def link(self, *, wallet_address: str) -> LinkedUser:
        """Find the user by wallet address, or create one if allowed.

        Returns a :class:`LinkedUser` with JWT pair. Raises
        :class:`WalletUserLinkError` on auto-create refusals.
        """
        normalized = wallet_address.lower()
        user_model = get_block_auth_user_model()
        auto_create = self._auto_create_enabled()

        # #1: do the lookup-or-create inside a transaction. The
        # ``wallet_address`` column is unique on ``BlockUser``; without the
        # atomic get-or-create, two concurrent first-logins race and the
        # losing side gets a 500 IntegrityError. ``get_or_create`` is
        # documented to handle that race by retrying the lookup on
        # IntegrityError.
        if auto_create:
            with transaction.atomic():
                # #537: SIWE proves cryptographic control of the private
                # key behind this address — that's a stronger ownership
                # guarantee than email click-through verification. Create
                # wallet-first accounts as ``is_verified=True`` so
                # downstream gates on the flag don't bounce the user.
                user, created = user_model.objects.get_or_create(
                    wallet_address=normalized,
                    defaults={"is_verified": True},
                )
                # Existing wallet-first accounts created before this
                # change have ``is_verified=False`` stuck on their row;
                # promote on any subsequent SIWE login so the legacy
                # rows heal without a data migration.
                if not created and not user.is_verified:
                    user.is_verified = True
                    user.save(update_fields=["is_verified"])
        else:
            existing = user_model.objects.filter(wallet_address=normalized).first()
            if existing is None:
                # #4: don't tell the caller whether the wallet is registered.
                # Default to a generic ``login_failed`` code; the view maps
                # it to 401 so the response is indistinguishable from a bad
                # signature. Deployments that need the explicit 403 for
                # UX reasons can opt in.
                if _expose_registration_status():
                    raise WalletUserLinkError(
                        "auto_create_disabled",
                        "No account exists for this wallet address and auto-create is disabled",
                    )
                raise WalletUserLinkError(
                    "login_failed",
                    "Authentication failed",
                )
            user = existing
            created = False

        # Last-login update + authentication type tag always run, regardless
        # of whether we created the row.
        user.last_login = timezone.now()
        user.add_authentication_type(AuthenticationType.WALLET)
        user.save()

        access_token, refresh_token = self._issue_tokens(user_id=str(user.id))

        # #2: fire triggers AFTER the outer transaction commits, so a
        # trigger exception can't roll back the user row. Wrapping each
        # trigger in try/except inside the on_commit callback also means
        # the post-signup fan-out (user.registered event, project
        # creation) is preserved across trigger bugs instead of silently
        # dying with ``created=False`` on the next retry.
        user_data = model_to_json(user, remove_fields=("password",))
        provider_data = {
            "provider": "wallet",
            "wallet_address": user.wallet_address,
        }
        self._schedule_triggers(
            user_data=user_data,
            provider_data=provider_data,
            created=created,
        )

        # NOTE: ``created`` is a reserved ``logging.LogRecord`` attribute (the
        # record's creation timestamp). Passing it via ``extra`` raises
        # ``KeyError: "Attempt to overwrite 'created' in LogRecord"`` on any
        # handler that actually formats the record, so the key is renamed to
        # ``user_created`` here. Other reserved LogRecord attrs to avoid:
        # msg/args/levelname/levelno/pathname/filename/module/exc_info/
        # exc_text/stack_info/lineno/funcName/msecs/relativeCreated/thread/
        # threadName/processName/process/message/asctime.
        logger.info(
            "Wallet login linked to user",
            extra={
                "user_id": str(user.id),
                "wallet_address": normalized,
                "user_created": created,
            },
        )

        return LinkedUser(
            user_id=str(user.id),
            email=user.email or "",
            access_token=access_token,
            refresh_token=refresh_token,
            created=created,
            user=user,
        )

    # =========================================================================
    # Helpers
    # =========================================================================

    @staticmethod
    def _auto_create_enabled() -> bool:
        """Return ``True`` unless the deployment explicitly disabled auto-create.

        Defaults ``True`` to preserve the existing behavior. A deploy that
        wants to gate wallet login on pre-existing accounts sets
        ``WALLET_LOGIN_AUTO_CREATE = False``.
        """
        return bool(getattr(settings, "WALLET_LOGIN_AUTO_CREATE", True))

    @staticmethod
    def _issue_tokens(*, user_id: str) -> Tuple[str, str]:
        """Generate the access/refresh JWT pair for the wallet user.

        Mirrors blockauth's own logic so the resulting claims are identical
        to what the other login paths issue.

        #6: if ``generate_auth_token_with_custom_claims`` is unavailable for
        any reason, fall back to the basic issuer BUT emit a warning. A
        silent fallback would drop every custom claim a consumer has
        registered and the operator would only notice when downstream
        services start rejecting tokens.
        """
        try:
            from blockauth.utils.token import generate_auth_token_with_custom_claims
        except ImportError:
            logger.warning(
                "generate_auth_token_with_custom_claims unavailable; falling back "
                "to generate_auth_token. Custom JWT claims will be omitted."
            )
            return generate_auth_token(token_class=AUTH_TOKEN_CLASS(), user_id=user_id)

        return generate_auth_token_with_custom_claims(token_class=AUTH_TOKEN_CLASS(), user_id=user_id)

    @staticmethod
    def _schedule_triggers(
        *,
        user_data: dict,
        provider_data: dict,
        created: bool,
    ) -> None:
        """Schedule post-signup/post-login triggers for after-commit dispatch.

        We deliberately use ``transaction.on_commit`` so the HTTP response is
        not blocked on the trigger (which often calls an event bus or sync
        service) and so a trigger exception cannot roll back the user row
        that's already been saved. Each trigger is wrapped in try/except +
        ``logger.exception`` so one trigger dying doesn't stop the others.
        """

        def _fire() -> None:
            if created:
                try:
                    post_signup_trigger = get_config("POST_SIGNUP_TRIGGER")()
                    post_signup_trigger.trigger(context={"user": user_data, "provider_data": provider_data})
                except Exception:
                    logger.exception("POST_SIGNUP_TRIGGER raised; continuing with login flow")

            try:
                post_login_trigger = get_config("POST_LOGIN_TRIGGER")()
                post_login_trigger.trigger(context={"user": user_data, "provider_data": provider_data})
            except Exception:
                logger.exception("POST_LOGIN_TRIGGER raised; continuing with login flow")

        # ``on_commit`` requires an active transaction. If the caller is not
        # wrapping us in one (e.g. a synchronous management command) we run
        # the triggers immediately -- same semantics as Django's own
        # ``on_commit`` behavior outside of atomic blocks.
        transaction.on_commit(_fire)


def _expose_registration_status() -> bool:
    """Return True when deployments explicitly opted into the oracle.

    The default is False so #4 is closed by default for every consumer.
    """
    return bool(getattr(settings, "WALLET_LOGIN_EXPOSE_REGISTRATION_STATUS", False))


wallet_user_linker = WalletUserLinker()
