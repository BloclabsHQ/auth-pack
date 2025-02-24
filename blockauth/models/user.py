import base64
import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models


class BlockUser(AbstractUser):
    """
    Custom User model that can be updated as per the project requirements.
    This model is not allowed to be managed by Django migrations.
    & also it is not encouraged to be created using Django admin.

    Inherit this model in your project's User model to become compitable
    with this app functionalities.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True, unique=True)
    is_verified = models.BooleanField(default=False)
    username = None

    USERNAME_FIELD = 'id'
    REQUIRED_FIELDS = ["first_name"]

    class Meta:
        managed = False
        abstract = True