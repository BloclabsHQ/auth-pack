"""SEC-08: duplicate identifier report writes nothing."""

from io import StringIO

import pytest
from django.core.management import call_command

from blockauth.utils.config import get_block_auth_user_model

_PASSWORD = "StrongP@ss1!"


@pytest.mark.django_db
def test_duplicate_identifiers_reports_email_case_and_writes_nothing():
    User = get_block_auth_user_model()

    def make(email):
        user = User(email=email, is_verified=True)
        user.set_password(_PASSWORD)
        user.save()
        return user

    first = make("User@Example.com")
    second = make("user@example.com")
    before = User.objects.count()
    output = StringIO()
    call_command("blockauth_duplicate_identifiers", stdout=output)
    assert User.objects.count() == before
    text = output.getvalue()
    assert "email user@example.com:" in text
    assert str(first.id) in text
    assert str(second.id) in text
