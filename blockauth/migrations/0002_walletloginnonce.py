"""
Add ``WalletLoginNonce`` — server-issued nonces for SIWE (EIP-4361) wallet
login.

Fixes #90. Before this change, ``POST /login/wallet/`` accepted any
client-supplied message with no replay protection. A captured payload
authenticated indefinitely. This model backs the new
``POST /login/wallet/challenge/`` endpoint and the single-use, TTL-bounded
nonce enforcement added alongside it.

See ``blockauth/models/wallet_login_nonce.py`` and
``blockauth/services/wallet_login_service.py`` for the runtime contract.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("blockauth", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="WalletLoginNonce",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "address",
                    models.CharField(
                        db_index=True,
                        help_text=("Lowercased Ethereum wallet address the challenge " "is bound to"),
                        max_length=42,
                    ),
                ),
                (
                    "nonce",
                    models.CharField(
                        help_text=("Server-generated random nonce embedded in the " "SIWE message"),
                        max_length=64,
                        unique=True,
                    ),
                ),
                (
                    "domain",
                    models.CharField(
                        help_text=(
                            "Domain the challenge was minted for. The signed "
                            "SIWE message's domain field must match this "
                            "value exactly at login time."
                        ),
                        max_length=253,
                    ),
                ),
                (
                    "uri",
                    models.CharField(
                        help_text="SIWE URI field echoed into the plaintext",
                        max_length=2048,
                    ),
                ),
                (
                    "chain_id",
                    models.PositiveIntegerField(
                        help_text="EIP-155 chain ID the challenge is scoped to",
                    ),
                ),
                (
                    "statement",
                    models.CharField(
                        blank=True,
                        default="",
                        help_text=("Optional human-readable statement included in " "the plaintext"),
                        max_length=512,
                    ),
                ),
                (
                    "issued_at",
                    models.DateTimeField(
                        help_text="Wall-clock time the nonce was issued (UTC)",
                    ),
                ),
                (
                    "expires_at",
                    models.DateTimeField(
                        db_index=True,
                        help_text="Nonce becomes invalid at this time (UTC)",
                    ),
                ),
                (
                    "consumed_at",
                    models.DateTimeField(
                        blank=True,
                        help_text=(
                            "Set the first time this nonce is redeemed. A "
                            "non-null value means the nonce is burned and "
                            "must never be accepted again."
                        ),
                        null=True,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Wallet Login Nonce",
                "verbose_name_plural": "Wallet Login Nonces",
                "db_table": "wallet_login_nonce",
                "ordering": ["-created_at"],
                "managed": True,
            },
        ),
        migrations.AddIndex(
            model_name="walletloginnonce",
            index=models.Index(
                fields=["address", "expires_at"],
                name="wallet_nonce_lookup_idx",
            ),
        ),
    ]
