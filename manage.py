#!/usr/bin/env python
"""Django management script for blockauth development tasks (migrations, etc)."""
import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "blockauth.settings")

    # Configure minimal Django settings for migration generation
    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            DATABASES={
                "default": {
                    "ENGINE": "django.db.backends.sqlite3",
                    "NAME": ":memory:",
                }
            },
            INSTALLED_APPS=[
                "django.contrib.auth",
                "django.contrib.contenttypes",
                "rest_framework",
                "blockauth",
            ],
            SECRET_KEY="dev-only-not-for-production",
            DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
            AUTH_USER_MODEL="auth.User",
            BLOCK_AUTH_SETTINGS={
                "SECRET_KEY": "dev-only-not-for-production",
                "ALGORITHM": "HS256",
                "BLOCK_AUTH_USER_MODEL": "auth.User",
            },
        )
        django.setup()

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
