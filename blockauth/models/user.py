
from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from uuid6 import uuid7

# Import from enums module (Django-independent) for backwards compatibility


class BlockUser(AbstractBaseUser):
    """
    Custom User model that can be updated as per the project requirements.
    This model is not allowed to be managed by Django migrations.
    & also it is not encouraged to be created using Django admin.

    Inherit this model in your project's User model to become compitable
    with this app functionalities.
    """

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    email = models.EmailField(unique=True, blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True, unique=True)
    wallet_address = models.CharField(
        max_length=42, blank=True, null=True, unique=True, help_text="Ethereum wallet address"
    )
    is_verified = models.BooleanField(default=False)
    authentication_types = models.JSONField(
        default=list,
        blank=True,
        help_text="List of authentication methods used by this user (e.g., ['EMAIL', 'WALLET'])",
    )
    username = None

    USERNAME_FIELD = "id"
    REQUIRED_FIELDS = []

    class Meta:
        managed = False
        abstract = True

    def add_authentication_type(self, auth_type: str):
        """
        Add an authentication type to the user's authentication_types list.
        Ensures no duplicates and maintains the list format.
        """
        if not isinstance(self.authentication_types, list):
            self.authentication_types = []

        if auth_type not in self.authentication_types:
            self.authentication_types.append(auth_type)
            self.save(update_fields=["authentication_types"])

    def remove_authentication_type(self, auth_type: str):
        """
        Remove an authentication type from the user's authentication_types list.
        """
        if isinstance(self.authentication_types, list) and auth_type in self.authentication_types:
            self.authentication_types.remove(auth_type)
            self.save(update_fields=["authentication_types"])

    def has_authentication_type(self, auth_type: str) -> bool:
        """
        Check if user has a specific authentication type.
        """
        return isinstance(self.authentication_types, list) and auth_type in self.authentication_types
