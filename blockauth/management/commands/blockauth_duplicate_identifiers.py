"""Report accounts that collide after identifier normalization. Writes nothing."""

from django.core.management.base import BaseCommand, CommandError

from blockauth.utils.config import get_block_auth_user_model
from blockauth.utils.validators import normalize_email, normalize_phone


class Command(BaseCommand):
    help = "Report users whose email or phone collides after normalization. Writes nothing."

    def handle(self, *args, **options):
        User = get_block_auth_user_model()
        before = User.objects.count()
        emails = {}
        phones = {}
        for user in User.objects.all().only("id", "email", "phone_number"):
            if user.email:
                emails.setdefault(normalize_email(user.email), []).append(str(user.id))
            if user.phone_number:
                phones.setdefault(normalize_phone(user.phone_number), []).append(str(user.id))
        for label, groups in (("email", emails), ("phone", phones)):
            for key in sorted(groups):
                ids = groups[key]
                if len(ids) < 2:
                    continue
                self.stdout.write(f"{label} {key}: {', '.join(ids)}")
        if User.objects.count() != before:
            raise CommandError("duplicate report must not write rows")
