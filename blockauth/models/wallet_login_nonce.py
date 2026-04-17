"""
Server-issued nonce for EIP-4361 (Sign-In With Ethereum) wallet login.

Background
----------
Before this model, ``POST /login/wallet/`` accepted any client-supplied
message and had no replay protection. A captured
``{wallet_address, message, signature}`` payload authenticated indefinitely.
That defect is tracked as issue #90 (upstream) / fabric-auth #401.

The fix is a two-round-trip flow:

1. ``POST /login/wallet/challenge/`` — server mints a random nonce, binds it
   to a lowercased wallet address with a TTL (default 5 minutes), and returns
   a SIWE plaintext for the client to sign.
2. ``POST /login/wallet/`` — client submits the signed SIWE message; server
   parses it, re-checks the embedded nonce against an unconsumed row in this
   table, marks it consumed atomically, then verifies the signature.

Nonces are single-use: ``consumed_at`` is set inside
``SELECT ... FOR UPDATE`` so two concurrent login attempts with the same
nonce can't both succeed.
"""

from django.db import models
from django.utils import timezone


class WalletLoginNonce(models.Model):
    """One row per issued SIWE challenge."""

    # 32 characters = 16 bytes hex-encoded, well above EIP-4361's 8-char
    # minimum. Keeping the column narrow.
    NONCE_MAX_LENGTH = 64

    address = models.CharField(
        max_length=42,
        db_index=True,
        help_text="Lowercased Ethereum wallet address the challenge is bound to",
    )
    nonce = models.CharField(
        max_length=NONCE_MAX_LENGTH,
        unique=True,
        help_text="Server-generated random nonce embedded in the SIWE message",
    )
    domain = models.CharField(
        max_length=253,
        help_text=(
            "Domain the challenge was minted for. The signed SIWE message's "
            "domain field must match this value exactly at login time."
        ),
    )
    uri = models.CharField(
        max_length=2048,
        help_text="SIWE URI field echoed into the plaintext",
    )
    chain_id = models.PositiveIntegerField(
        help_text="EIP-155 chain ID the challenge is scoped to",
    )
    statement = models.CharField(
        max_length=512,
        blank=True,
        default="",
        help_text="Optional human-readable statement included in the plaintext",
    )
    issued_at = models.DateTimeField(
        help_text="Wall-clock time the nonce was issued (UTC)",
    )
    expires_at = models.DateTimeField(
        db_index=True,
        help_text="Nonce becomes invalid at this time (UTC)",
    )
    consumed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=(
            "Set the first time this nonce is redeemed. A non-null value "
            "means the nonce is burned and must never be accepted again."
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "blockauth"
        managed = True
        db_table = "wallet_login_nonce"
        ordering = ["-created_at"]
        indexes = [
            # The hot lookup is ``(address, nonce, consumed_at IS NULL)`` at
            # login time. The unique index on nonce handles that; the compound
            # index here keeps the reaper's ``expires_at < now`` sweep cheap.
            models.Index(
                fields=["address", "expires_at"],
                name="wallet_nonce_lookup_idx",
            ),
        ]
        verbose_name = "Wallet Login Nonce"
        verbose_name_plural = "Wallet Login Nonces"

    def __str__(self) -> str:
        return f"WalletLoginNonce(address={self.address}, nonce={self.nonce[:8]}...)"

    @property
    def is_consumed(self) -> bool:
        return self.consumed_at is not None

    @property
    def is_expired(self) -> bool:
        return self.expires_at <= timezone.now()
