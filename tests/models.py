from blockauth.models.user import BlockUser


class TestBlockUser(BlockUser):
    """Concrete user model for testing. Inherits all BlockUser fields."""

    class Meta:
        managed = True
        db_table = "test_block_user"
