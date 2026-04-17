"""
Management command to clean up expired authentication records.

Removes:
- Expired or used OTP records
- Expired or used passkey challenges
- Old TOTP verification logs

Safe for cron execution: idempotent, no locks required.
"""

import logging
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from blockauth.utils.config import get_config

logger = logging.getLogger("blockauth")


def _get_retention(key, default):
    """Fetch a cleanup retention setting, falling back to default."""
    try:
        return get_config(key)
    except AttributeError:
        return default


class Command(BaseCommand):
    help = "Remove expired OTP records, passkey challenges, and TOTP verification logs."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            help="Preview counts without deleting any records.",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        now = timezone.now()

        otp_deleted = self._cleanup_otp(now, dry_run)
        challenge_deleted = self._cleanup_challenges(now, dry_run)
        totp_log_deleted = self._cleanup_totp_logs(now, dry_run)

        total = otp_deleted + challenge_deleted + totp_log_deleted

        if dry_run:
            self.stdout.write(
                f"[dry-run] Would delete: "
                f"{otp_deleted} OTP, "
                f"{challenge_deleted} challenges, "
                f"{totp_log_deleted} TOTP logs "
                f"({total} total)"
            )
        else:
            self.stdout.write(
                f"Cleanup complete: "
                f"{otp_deleted} OTP, "
                f"{challenge_deleted} challenges, "
                f"{totp_log_deleted} TOTP logs "
                f"({total} total)"
            )
            if total > 0:
                logger.info(
                    "blockauth_cleanup deleted %d records " "(OTP=%d, challenges=%d, TOTP logs=%d)",
                    total,
                    otp_deleted,
                    challenge_deleted,
                    totp_log_deleted,
                )

    # ------------------------------------------------------------------
    # OTP cleanup
    # ------------------------------------------------------------------
    def _cleanup_otp(self, now, dry_run):
        from django.db.models import Q

        from blockauth.models.otp import OTP

        retention_hours = _get_retention("CLEANUP_OTP_RETENTION_HOURS", 24)
        cutoff = now - timedelta(hours=retention_hours)

        qs = OTP.objects.filter(Q(is_used=True) | Q(created_at__lt=cutoff))

        count = qs.count()
        if not dry_run and count > 0:
            qs.delete()
        return count

    # ------------------------------------------------------------------
    # Passkey challenge cleanup
    # ------------------------------------------------------------------
    def _cleanup_challenges(self, now, dry_run):
        from blockauth.passkey.models import PasskeyChallenge

        retention_minutes = _get_retention("CLEANUP_CHALLENGE_RETENTION_MINUTES", 5)
        cutoff = now - timedelta(minutes=retention_minutes)

        from django.db.models import Q

        # Expired (with grace period) OR already used
        qs = PasskeyChallenge.objects.filter(Q(expires_at__lt=cutoff) | Q(is_used=True))

        count = qs.count()
        if not dry_run and count > 0:
            qs.delete()
        return count

    # ------------------------------------------------------------------
    # TOTP verification log cleanup
    # ------------------------------------------------------------------
    def _cleanup_totp_logs(self, now, dry_run):
        from blockauth.totp.models import TOTPVerificationLog

        retention_days = _get_retention("CLEANUP_TOTP_LOG_RETENTION_DAYS", 30)
        cutoff = now - timedelta(days=retention_days)

        qs = TOTPVerificationLog.objects.filter(created_at__lt=cutoff)

        count = qs.count()
        if not dry_run and count > 0:
            qs.delete()
        return count
