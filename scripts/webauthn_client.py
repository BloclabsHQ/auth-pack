"""Software WebAuthn authenticator used by the passkey E2E flow.

A full FIDO2 authenticator emulator is more code than this E2E suite
warrants. Rather than hand-roll one, we adapt the open-source
``soft-webauthn`` package if it is installed. The package ships a
``SoftWebauthnDevice`` class that generates valid registration and
authentication responses the server's ``py-webauthn`` verifier accepts
end-to-end.

Install on demand::

    uv add --dev soft-webauthn

If ``soft-webauthn`` is not importable, :func:`make_device` raises
``RuntimeError`` and the pytest module skips.  That keeps the default
``make e2e-run`` green on fresh checkouts while still letting engineers
opt in to the full passkey sweep with one dep.
"""

from __future__ import annotations


def make_device(origin: str = "http://localhost:8765"):
    """Return a ``SoftWebauthnDevice`` bound to the E2E server origin.

    Raises :class:`RuntimeError` if ``soft-webauthn`` isn't installed —
    callers should catch and skip the test.
    """
    try:
        from soft_webauthn import SoftWebauthnDevice  # type: ignore
    except ImportError as exc:  # pragma: no cover - optional dep
        raise RuntimeError(
            "soft-webauthn not installed. Run `uv add --dev soft-webauthn` "
            "to enable the passkey E2E flow."
        ) from exc

    device = SoftWebauthnDevice()
    device.origin = origin
    return device


def registration_response(device, options: dict) -> dict:
    """Drive ``SoftWebauthnDevice.create`` to produce a registration response.

    ``options`` is the ``publicKey`` dict from
    ``POST /auth/passkey/register/options/``.  Returns the shape the
    ``verify/`` endpoint expects.
    """
    response = device.create({"publicKey": options}, device.origin)
    return response


def authentication_response(device, options: dict) -> dict:
    """Drive ``SoftWebauthnDevice.get`` for authentication."""
    response = device.get({"publicKey": options}, device.origin)
    return response
