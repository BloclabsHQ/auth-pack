# Generated manually for BlockAuth

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blockauth', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='blockuser',
            name='wallet_address',
            field=models.CharField(
                blank=True,
                null=True,
                max_length=42,
                unique=True,
                help_text="Ethereum wallet address"
            ),
        ),
    ] 