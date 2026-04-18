"""End-to-end test harness for BlockAuth.

This package ships a minimal Django project + pytest suite that exercises
every public BlockAuth endpoint against a live ``runserver`` instance.

Two artifacts are produced:

* ``tests_e2e/flows/test_*.py`` — pytest functions using ``requests`` that
  hit the dev server over real HTTP.  Run via ``make e2e-run``.
* ``.insomnia/collection.json`` — importable Insomnia v4 export for manual
  exploration of the same endpoints.

The Django project here is deliberately separate from
``conftest.py``'s in-memory pytest harness; the E2E suite needs a real
HTTP server, a real database, and a few dev-only helper endpoints
(``/auth/_test/otp/...``) that must never exist in production.
"""
