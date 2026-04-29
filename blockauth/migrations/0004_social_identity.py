"""Add SocialIdentity table to the umbrella `blockauth` app.

Backs the OIDC `(provider, subject)` to User link used by Google native
verification and Apple Sign-In. The model lives under the umbrella
`blockauth` app so consumers keep one `INSTALLED_APPS` entry and one
`MIGRATION_MODULES` override for the whole package.
"""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("blockauth", "0003_otp_add_payload"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="SocialIdentity",
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
                ("provider", models.CharField(max_length=20)),
                ("subject", models.CharField(max_length=255)),
                ("email_at_link", models.EmailField(blank=True, max_length=254, null=True)),
                ("email_verified_at_link", models.BooleanField()),
                ("encrypted_refresh_token", models.BinaryField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("last_used_at", models.DateTimeField(auto_now=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="social_identities",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "social_identity",
                "indexes": [
                    models.Index(fields=["user", "provider"], name="social_iden_user_id_bc8105_idx"),
                ],
                "unique_together": {("provider", "subject")},
            },
        ),
    ]
