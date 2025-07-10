# Generated manually for BlockAuth

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blockauth', '0003_alter_otp_subject'),
    ]

    operations = [
        migrations.AddField(
            model_name='blockuser',
            name='authentication_types',
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="List of authentication methods used by this user (e.g., ['EMAIL', 'WALLET'])"
            ),
        ),
    ] 