"""Widen OTP.code so a 64-character digest fits."""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("blockauth", "0005_scope_social_identity_table"),
    ]

    operations = [
        migrations.AlterField(
            model_name="otp",
            name="code",
            field=models.CharField(max_length=64),
        ),
    ]
