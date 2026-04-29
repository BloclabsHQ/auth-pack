"""Shared helpers for building the post-auth-state-change response tuple.

Centralizes the ``{access, refresh, user}`` shape that every first-party
login, signup-confirm, refresh, password-mutation, OAuth-callback, and
identity-mutation endpoint now returns. Keeping this in one place means
adding a field to the user payload (e.g. ``display_name``) is a one-line
change and every endpoint picks it up automatically.
"""

from typing import Tuple

from blockauth.utils.token import AUTH_TOKEN_CLASS, generate_auth_token

DEFAULT_WALLET_CHAIN_ID = 1


def _build_wallet_items(user, date_joined) -> list[dict]:
    """Shape wallet rows as ``WalletItem`` objects, not bare address strings.

    Clients receive ``{address, chain_id, linked_at, label, primary}``
    objects so the model can grow to many-wallet-per-user without changing
    the wire shape. Today the ``BlockUser`` abstract has a single
    ``wallet_address`` column plus ``authentication_types`` list, so we
    project the single linked address into a one-element array with
    ``primary=True``. Default chain id is mainnet (1) until downstream
    user models add a ``wallet_chain_id`` column; ``linked_at`` falls
    back to ``date_joined`` because no per-wallet link timestamp exists
    on the abstract user yet. ``label`` is always ``None`` at this
    layer — dashboards attach labels client-side.
    """
    if not getattr(user, "wallet_address", None):
        return []
    linked_at = getattr(user, "wallet_linked_at", None) or date_joined
    return [
        {
            "address": user.wallet_address,
            "chain_id": getattr(user, "wallet_chain_id", None) or DEFAULT_WALLET_CHAIN_ID,
            "linked_at": linked_at.isoformat() if linked_at else None,
            "label": getattr(user, "wallet_label", None),
            "primary": True,
        }
    ]


def build_user_payload(user) -> dict:
    """Shape the ``user`` block used by every post-auth-state response.

    ``is_active`` and ``date_joined`` (ISO-8601) are always present;
    ``wallets`` is an array (empty when unlinked) so the model can grow to
    many-wallet-per-user without another payload change; ``wallet_address``
    stays alongside ``wallets`` for transitional compatibility.
    ``first_name`` / ``last_name`` are omitted when unset and use ``getattr``
    so downstream user models that never added those fields stay compatible.

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
        "wallets": _build_wallet_items(user, date_joined),
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
