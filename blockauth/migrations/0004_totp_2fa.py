"""
Migration for TOTP 2FA models.

Creates the following tables:
- totp_2fa: Stores TOTP configuration per user
- totp_verification_log: Audit log for verification attempts
"""
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('blockauth', '0003_passkey_validators'),
    ]

    operations = [
        # TOTP 2FA Configuration table
        migrations.CreateModel(
            name='TOTP2FA',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('encrypted_secret', models.TextField(help_text='Encrypted TOTP secret (Base32-encoded internally)')),
                ('status', models.CharField(
                    choices=[
                        ('disabled', 'Disabled'),
                        ('pending_confirmation', 'Pending Confirmation'),
                        ('enabled', 'Enabled'),
                    ],
                    default='disabled',
                    help_text='Current TOTP status',
                    max_length=30,
                )),
                ('algorithm', models.CharField(default='sha1', help_text='Hash algorithm (sha1, sha256, sha512)', max_length=10)),
                ('digits', models.PositiveSmallIntegerField(default=6, help_text='Number of digits in TOTP code (6 or 8)')),
                ('time_step', models.PositiveSmallIntegerField(default=30, help_text='Time step in seconds')),
                ('backup_codes_hash', models.JSONField(blank=True, default=list, help_text='List of hashed backup codes (SHA-256)')),
                ('backup_codes_remaining', models.PositiveSmallIntegerField(default=0, help_text='Number of unused backup codes remaining')),
                ('failed_attempts', models.PositiveSmallIntegerField(default=0, help_text='Number of consecutive failed verification attempts')),
                ('locked_until', models.DateTimeField(blank=True, help_text='Account is locked until this time due to failed attempts', null=True)),
                ('last_failed_at', models.DateTimeField(blank=True, help_text='Timestamp of last failed verification', null=True)),
                ('last_used_counter', models.BigIntegerField(blank=True, help_text='Time counter of last successfully used code (prevents replay)', null=True)),
                ('last_verified_at', models.DateTimeField(blank=True, help_text='When TOTP was last successfully verified', null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, help_text='When TOTP was initially set up')),
                ('enabled_at', models.DateTimeField(blank=True, help_text='When TOTP was confirmed and enabled', null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, help_text='Last update timestamp')),
                ('recovery_email_sent_at', models.DateTimeField(blank=True, help_text='When recovery instructions were last sent', null=True)),
                ('user', models.OneToOneField(
                    help_text='User who owns this TOTP configuration',
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='totp_2fa',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'verbose_name': 'TOTP 2FA Configuration',
                'verbose_name_plural': 'TOTP 2FA Configurations',
                'db_table': 'totp_2fa',
            },
        ),

        # TOTP Verification Log table
        migrations.CreateModel(
            name='TOTPVerificationLog',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('success', models.BooleanField(help_text='Whether verification was successful')),
                ('verification_type', models.CharField(
                    choices=[('totp', 'TOTP Code'), ('backup', 'Backup Code')],
                    help_text='Type of code verified',
                    max_length=20,
                )),
                ('ip_address', models.GenericIPAddressField(blank=True, help_text='IP address of the request', null=True)),
                ('user_agent', models.TextField(blank=True, default='', help_text='User agent of the request')),
                ('failure_reason', models.CharField(blank=True, default='', help_text='Reason for failure if applicable', max_length=50)),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True, help_text='When the verification attempt occurred')),
                ('user', models.ForeignKey(
                    help_text='User who attempted verification',
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='totp_verification_logs',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'verbose_name': 'TOTP Verification Log',
                'verbose_name_plural': 'TOTP Verification Logs',
                'db_table': 'totp_verification_log',
                'ordering': ['-created_at'],
            },
        ),

        # Indexes for TOTP2FA
        migrations.AddIndex(
            model_name='totp2fa',
            index=models.Index(fields=['user'], name='totp_user_idx'),
        ),
        migrations.AddIndex(
            model_name='totp2fa',
            index=models.Index(fields=['status'], name='totp_status_idx'),
        ),
        migrations.AddIndex(
            model_name='totp2fa',
            index=models.Index(fields=['locked_until'], name='totp_locked_idx'),
        ),

        # Indexes for TOTPVerificationLog
        migrations.AddIndex(
            model_name='totpverificationlog',
            index=models.Index(fields=['user', 'created_at'], name='totp_log_user_time_idx'),
        ),
        migrations.AddIndex(
            model_name='totpverificationlog',
            index=models.Index(fields=['success', 'created_at'], name='totp_log_success_idx'),
        ),
        migrations.AddIndex(
            model_name='totpverificationlog',
            index=models.Index(fields=['ip_address', 'created_at'], name='totp_log_ip_idx'),
        ),
    ]
