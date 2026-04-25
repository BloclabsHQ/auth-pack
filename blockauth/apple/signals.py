"""Apple pre_delete signal handler.

When a User row is about to be deleted, find every linked Apple
`SocialIdentity` and revoke its refresh token at Apple's /auth/revoke
endpoint. The actual cascade-delete of SocialIdentity rows is done by
Django's CASCADE via SocialIdentity.user.on_delete=CASCADE.

The signal is connected explicitly in `apple/apps.py:ready()` rather than
via a top-level `@receiver` decorator so the User model lookup happens
after the app registry is populated. Sender = settings.AUTH_USER_MODEL
(string reference) so the signal targets whichever user model the
integrator configured.
"""

import logging

from blockauth.apple.revocation_client import AppleRevocationClient
from blockauth.social.models import SocialIdentity
from blockauth.social.service import SocialIdentityService

logger = logging.getLogger(__name__)


def revoke_apple_identities(sender, instance, **kwargs):
    """pre_delete handler for the configured user model.

    Looks up apple SocialIdentity rows for the user being deleted and
    invokes AppleRevocationClient.revoke for each. Decryption and
    revocation failures are logged but never raise — the user deletion
    must complete regardless of Apple-side state.
    """
    apple_identities = SocialIdentity.objects.filter(user=instance, provider="apple")
    if not apple_identities.exists():
        return

    service = SocialIdentityService()
    client = AppleRevocationClient()
    for identity in apple_identities:
        try:
            refresh_token = service.decrypt_refresh_token(identity)
        except Exception as exc:  # decryption failure should not block deletion
            logger.error(
                "apple.revocation.refresh_decrypt_failed",
                extra={"user_id": str(instance.id), "error_class": exc.__class__.__name__},
            )
            continue
        if not refresh_token:
            continue
        client.revoke(refresh_token)
