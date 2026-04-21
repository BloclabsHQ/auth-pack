"""Shared helpers for building the post-auth-state-change response tuple.

Centralizes the ``{access, refresh, user}`` shape that every first-party
login, signup-confirm, refresh, password-mutation, OAuth-callback, and
identity-mutation endpoint now returns. Keeping this in one place means
adding a field to the user payload (e.g. ``display_name``) is a one-line
change and every endpoint picks it up automatically.
"""

from typing import Tuple

from blockauth.utils.token import AUTH_TOKEN_CLASS, generate_auth_token


def build_user_payload(user) -> dict:
    """Shape the ``user`` block used by every post-auth-state response.

    Matches the ``@bloclabshq/auth`` shell ``AuthUser`` schema:
    ``is_active`` and ``date_joined`` (ISO-8601) are always present;
    ``wallets`` is an array (empty when unlinked) so the model can grow
    to many-wallet-per-user without another payload change;
    ``wallet_address`` stays alongside ``wallets`` for transitional
    compatibility. ``first_name`` / ``last_name`` are omitted when
    unset (the shell models these as ``z.optional``, which rejects
    ``null``) and use ``getattr`` so downstream user models that never
    added those fields stay compatible.

    ``is_active`` and ``date_joined`` are also read via ``getattr`` —
    ``BlockUser`` extends ``AbstractBaseUser``, which exposes
    ``is_active`` only as a class-attribute default and does not define
    ``date_joined`` at all. Defensive reads keep the helper safe across
    downstream user models that don't define these fields.
    """
    date_joined = getattr(user, "date_joined", None)
    payload = {
        "id": user.id,
        "email": user.email,
        "is_verified": user.is_verified,
        "is_active": getattr(user, "is_active", True),
        "date_joined": date_joined.isoformat() if date_joined else None,
        "wallet_address": user.wallet_address,
        "wallets": [user.wallet_address] if user.wallet_address else [],
    }
    first_name = getattr(user, "first_name", None)
    if first_name:
        payload["first_name"] = first_name
    last_name = getattr(user, "last_name", None)
    if last_name:
        payload["last_name"] = last_name
    return payload


def issue_auth_tokens(user) -> Tuple[str, str]:
    """Issue a fresh ``(access, refresh)`` pair via the custom-claims-aware
    path when available, falling back to the legacy generator if the
    enhanced module is missing.

    Custom claims are computed against a DB-fresh read of the user (see
    ``blockauth.jwt.token_manager.JWTTokenManager.generate_token``), so
    callers only need to ensure ``user.save()`` has committed before
    invoking this helper.
    """
    try:
        from blockauth.utils.token import generate_auth_token_with_custom_claims

        return generate_auth_token_with_custom_claims(token_class=AUTH_TOKEN_CLASS(), user_id=str(user.id))
    except ImportError:
        return generate_auth_token(token_class=AUTH_TOKEN_CLASS(), user_id=str(user.id))
