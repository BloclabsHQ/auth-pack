"""SocialIdentity — durable link between an OIDC `(provider, subject)` and a User.

`user` cascades on delete so an account-deletion in the application
removes its OAuth links too.
`unique_together` on (provider, subject) is the primary lookup key the
verification path uses to find an existing user without falling back to email.
`encrypted_refresh_token` stores the AES-GCM blob (nonce || ciphertext || tag);
plaintext refresh tokens never reach the database.
"""

from django.conf import settings
from django.db import models


class SocialIdentity(models.Model):
    provider = models.CharField(max_length=20)
    subject = models.CharField(max_length=255)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="social_identities",
    )
    email_at_link = models.EmailField(blank=True, null=True)
    email_verified_at_link = models.BooleanField()
    encrypted_refresh_token = models.BinaryField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "blockauth_social"
        db_table = "social_identity"
        unique_together = (("provider", "subject"),)
        indexes = [models.Index(fields=["user", "provider"])]
