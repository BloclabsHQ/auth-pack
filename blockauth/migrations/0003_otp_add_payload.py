"""Add OTP.payload JSONField for the ghost-free signup flow.

When signup OTP send fails the user row must not be left behind. The fix
defers user-row creation to SignUpConfirmView and carries the hashed
password + auth types via this field so the confirm step can reconstruct
the full user without a round-trip.

Field is nullable so existing OTP rows (and other subjects) are unaffected.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("blockauth", "0002_walletloginnonce"),
    ]

    operations = [
        migrations.AddField(
            model_name="otp",
            name="payload",
            field=models.JSONField(
                blank=True,
                default=None,
                null=True,
                help_text="Arbitrary data carried through to OTP confirmation (e.g. hashed password for signup).",
            ),
        ),
    ]
