"""Service-layer modules for BlockAuth.

Services encapsulate business logic that is too substantial for a view or
serializer but does not need to be a public API surface. Each service is
meant to be constructed once per request (or once per process, for read-only
singletons) and has no framework ties beyond Django's settings/ORM.
"""
