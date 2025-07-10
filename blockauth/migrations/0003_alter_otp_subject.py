# Generated manually for BlockAuth

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blockauth', '0002_add_wallet_address'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otp',
            name='subject',
            field=models.CharField(choices=[('login', 'Login'), ('sign_up', 'Signup'), ('password_reset', 'Password Reset'), ('email_change', 'Email Change'), ('wallet_email_verification', 'Wallet Email Verification')], max_length=30),
        ),
    ]
