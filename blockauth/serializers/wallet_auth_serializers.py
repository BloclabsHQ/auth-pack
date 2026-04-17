"""DRF serializers for the SIWE-backed wallet login flow (issue #90).

These serializers are specific to the new ``/login/wallet/challenge/`` and
the overridden ``/login/wallet/`` endpoints. The legacy JSON-message
``WalletLoginSerializer`` in ``blockauth.serializers.wallet_serializers``
remains in place for backwards compatibility but is no longer wired into the
default URLconf.
"""

from rest_framework import serializers

from blockauth.serializers.user_account_serializers import LoginUserSerializer
from blockauth.utils.siwe import MAX_SIWE_MESSAGE_LENGTH


class WalletChallengeRequestSerializer(serializers.Serializer):
    """Request body for ``POST /login/wallet/challenge/``."""

    address = serializers.CharField(
        max_length=42,
        help_text="Ethereum wallet address (0x-prefixed, 42 chars)",
    )
    chain_id = serializers.IntegerField(
        required=False,
        min_value=1,
        help_text=(
            "Optional EIP-155 chain ID to bind the challenge to. Defaults to "
            "WALLET_LOGIN_DEFAULT_CHAIN_ID when omitted."
        ),
    )
    domain = serializers.CharField(
        required=False,
        max_length=253,
        help_text=(
            "Optional domain requesting the login. Must be in the server's "
            "allow-list. Defaults to the first allow-listed domain."
        ),
    )
    uri = serializers.URLField(
        required=False,
        max_length=2048,
        help_text=(
            "Optional SIWE URI field. Defaults to https://<domain>. The "
            "client should set this to the exact URL initiating the login so "
            "wallets can display it."
        ),
    )


class WalletChallengeResponseSerializer(serializers.Serializer):
    """Response body for ``POST /login/wallet/challenge/``."""

    message = serializers.CharField(help_text="SIWE plaintext to be signed")
    nonce = serializers.CharField(help_text="Server-issued single-use nonce")
    domain = serializers.CharField(help_text="Domain the challenge is bound to")
    chain_id = serializers.IntegerField(help_text="EIP-155 chain ID")
    uri = serializers.CharField(help_text="URI included in the SIWE plaintext")
    issued_at = serializers.DateTimeField(help_text="When the nonce was minted")
    expires_at = serializers.DateTimeField(help_text="Nonce is rejected after this time (UTC)")


class WalletLoginRequestSerializer(serializers.Serializer):
    """Request body for the overridden ``POST /login/wallet/``.

    Hardening #9: ``message`` is length-capped at parse time to match the
    parser's own ``MAX_SIWE_MESSAGE_LENGTH``. Without this the DRF field
    would accept any string up to Django's 2.5 MB upload cap and we'd have
    to walk every byte in the parser before rejecting.
    """

    wallet_address = serializers.CharField(max_length=42, help_text="Ethereum wallet address (0x-prefixed)")
    message = serializers.CharField(
        max_length=MAX_SIWE_MESSAGE_LENGTH,
        help_text=(
            "EIP-4361 SIWE plaintext issued by the challenge endpoint, "
            "verbatim -- the client must not modify any bytes."
        ),
    )
    signature = serializers.CharField(
        max_length=132,
        help_text="Ethereum signature, 0x-prefixed 130-hex-char string",
    )


# Backwards-compat alias. The wallet-login response used to embed a
# ``WalletLoginUserSerializer`` declared here. Issue #97 generalised the
# payload to basic-login and passwordless-login, at which point the
# serializer was promoted to the shared ``LoginUserSerializer`` in
# ``user_account_serializers``. Keeping the alias avoids breaking any
# external consumer that imported the old name before the rename was
# released; remove in a future major bump.
WalletLoginUserSerializer = LoginUserSerializer


class WalletLoginResponseSerializer(serializers.Serializer):
    """Response body for ``POST /login/wallet/`` (issue #97).

    Shares the :class:`LoginUserSerializer` payload with basic-login and
    passwordless-login so the three endpoints return the same shape and
    clients can share a single generated type.
    """

    access = serializers.CharField(help_text="JWT access token")
    refresh = serializers.CharField(help_text="JWT refresh token")
    user = LoginUserSerializer(help_text="Authenticated user profile")
