import uuid6
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="E2EUser",
            fields=[
                ("password", models.CharField(max_length=128, verbose_name="password")),
                ("last_login", models.DateTimeField(blank=True, null=True, verbose_name="last login")),
                (
                    "id",
                    models.UUIDField(default=uuid6.uuid7, editable=False, primary_key=True, serialize=False),
                ),
                ("email", models.EmailField(blank=True, max_length=254, null=True, unique=True)),
                ("phone_number", models.CharField(blank=True, max_length=20, null=True, unique=True)),
                ("wallet_address", models.CharField(blank=True, max_length=42, null=True, unique=True)),
                ("is_verified", models.BooleanField(default=False)),
                ("authentication_types", models.JSONField(blank=True, default=list)),
                ("first_name", models.CharField(blank=True, max_length=150, null=True)),
                ("last_name", models.CharField(blank=True, max_length=150, null=True)),
            ],
            options={
                "db_table": "e2e_user",
                "managed": True,
            },
        ),
    ]
