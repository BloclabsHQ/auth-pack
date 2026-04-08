# Import passkey models (they use app_label='blockauth' so no separate app needed)
# Models are always imported for Django migration discovery.
# If py_webauthn is not installed, a warning is shown.
try:
    from blockauth.passkey.models import PasskeyChallenge, PasskeyCredential
except ImportError as e:
    import warnings

    warnings.warn(
        f"Passkey models not available: {e}. "
        "Install 'py_webauthn' for passkey/WebAuthn support: pip install py_webauthn",
        ImportWarning,
    )
    PasskeyCredential = None
    PasskeyChallenge = None
