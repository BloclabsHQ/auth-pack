"""SocialIdentity layer: durable links between OIDC `(provider, subject)` and User.

`blockauth.social` is registered as a separate Django app (label
`blockauth_social`) — distinct from sibling sub-packages `totp` and `passkey`,
which share the parent `blockauth` app label. The split is deliberate: the
`SocialIdentity` table belongs to its own migration namespace so it can be
introduced (and, if ever needed, retired) without entangling the existing
`blockauth` migrations.
"""
