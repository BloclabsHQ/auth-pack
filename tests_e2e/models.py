from django.db import models

from blockauth.models.user import BlockUser


class E2EUser(BlockUser):
    """Concrete BlockUser for the E2E Django project.

    Adds first/last name so the social/login user payload has
    non-null fields to serialize.
    """

    first_name = models.CharField(max_length=150, blank=True, null=True)
    last_name = models.CharField(max_length=150, blank=True, null=True)

    class Meta:
        managed = True
        db_table = "e2e_user"
