"""
``prune_wallet_nonces`` — delete expired / consumed wallet login nonces.

Wallet login nonces are single-use and TTL-bounded. Once ``expires_at`` has
passed (or ``consumed_at`` is set) the row is dead weight. The challenge
endpoint doesn't clean up after itself -- keeping cleanup out of the hot
path is important because a reaper coinciding with a login burst would
slow down the login burst.

Recommended cadence: run every 5-15 minutes. ``expires_at`` is indexed
(see ``blockauth/migrations/0002_walletloginnonce.py``) so the sweep is
cheap even on a busy table.

Usage
-----
Cron / systemd::

    python manage.py prune_wallet_nonces --older-than 3600

Celery Beat::

    from celery import shared_task
    from django.core.management import call_command

    @shared_task
    def prune_wallet_nonces():
        call_command("prune_wallet_nonces")

By default the command removes every expired row plus every consumed row
older than 1 hour. ``--dry-run`` prints the counts without deleting.
"""

from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from blockauth.models.wallet_login_nonce import WalletLoginNonce


class Command(BaseCommand):
    help = "Delete expired or consumed wallet login nonces."

    def add_arguments(self, parser):
        parser.add_argument(
            "--older-than",
            type=int,
            default=3600,
            help=(
                "Also delete consumed rows whose consumed_at is at least this "
                "many seconds in the past. Default: 3600 (1 hour). "
                "Expired-but-unconsumed rows are always deleted."
            ),
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Count what would be deleted without actually deleting.",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=1000,
            help=("Delete in batches of this size to keep transactions small " "on busy tables. Default: 1000."),
        )

    def handle(self, *args, **options):
        older_than = options["older_than"]
        dry_run = options["dry_run"]
        batch_size = options["batch_size"]

        now = timezone.now()
        consumed_cutoff = now - timedelta(seconds=older_than)

        queryset = WalletLoginNonce.objects.filter(Q(expires_at__lt=now) | Q(consumed_at__lt=consumed_cutoff))
        total = queryset.count()

        if dry_run:
            self.stdout.write(
                self.style.NOTICE(
                    f"[dry-run] would delete {total} wallet login nonce(s) "
                    f"(cutoff={now.isoformat()}, consumed_older_than={consumed_cutoff.isoformat()})"
                )
            )
            return

        if total == 0:
            self.stdout.write("No wallet login nonces to prune.")
            return

        deleted = 0
        while True:
            ids = list(queryset.values_list("id", flat=True)[:batch_size])
            if not ids:
                break
            batch_deleted, _ = WalletLoginNonce.objects.filter(id__in=ids).delete()
            deleted += batch_deleted
            if batch_deleted == 0:
                # Safety belt against an infinite loop if something goes
                # wrong with the filter predicate.
                break

        self.stdout.write(self.style.SUCCESS(f"Deleted {deleted} wallet login nonce(s)."))
