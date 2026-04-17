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

    ``first_name`` / ``last_name`` use ``getattr`` so downstream user
    models that never added those fields stay compatible. The field set
    matches ``blockauth.serializers.user_account_serializers.LoginUserSerializer``.
    """
    return {
        "id": user.id,
        "email": user.email,
        "is_verified": user.is_verified,
        "wallet_address": user.wallet_address,
        "first_name": getattr(user, "first_name", None),
        "last_name": getattr(user, "last_name", None),
    }


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
