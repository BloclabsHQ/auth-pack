#!/usr/bin/env python
"""Django manage.py for the E2E test project.

Run with::

    uv run python -m tests_e2e.manage migrate
    uv run python -m tests_e2e.manage runserver 0.0.0.0:8000
"""

import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests_e2e.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
