from django.db import models

from blockauth.models.user import BlockUser


class TestBlockUser(BlockUser):
    """Concrete user model for testing. Inherits all BlockUser fields.

    ``is_active`` is test-only: downstream models commonly add it as a
    real column (Django's disable convention), while the abstract
    ``BlockUser`` intentionally does not define it, so enforcement must
    read it defensively via ``getattr``.
    """

    is_active = models.BooleanField(default=True)

    class Meta:
        managed = True
        db_table = "test_block_user"
