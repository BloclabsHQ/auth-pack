"""
Tests for per-request RP_ID resolution (see auth-pack#143).

Covers:
- ``PasskeyConfiguration.resolve_rp_id`` precedence: resolver > map > fallback
- Config loader: resolves dotted-path resolver, validates map shape
- ``PasskeyService`` accepts ``rp_id`` / ``expected_rp_id`` overrides and
  forwards them to py-webauthn
- Views derive origin from request and call the resolver
"""

import unittest
from unittest.mock import MagicMock, patch

from django.test import RequestFactory, override_settings

from ..config import PasskeyConfigManager, PasskeyConfiguration, _config_manager
from ..constants import (
    AttestationConveyance,
    COSEAlgorithm,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from ..exceptions import ConfigurationError
from ..services.passkey_service import PasskeyService


def _sample_resolver(origin):
    """Module-level resolver used by dotted-path loading tests."""
    if origin == "https://localhost:5173":
        return "localhost"
    if origin == "https://app.example.com":
        return "example.com"
    return None


def _make_config(
    rp_id="example.com",
    rp_id_resolver=None,
    rp_id_by_origin=None,
):
    """Build a minimal valid PasskeyConfiguration for unit tests."""
    return PasskeyConfiguration(
        rp_id=rp_id,
        rp_name="Test App",
        allowed_origins=["https://app.example.com"],
        attestation=AttestationConveyance.NONE.value,
        authenticator_attachment=None,
        resident_key=ResidentKeyRequirement.PREFERRED.value,
        user_verification=UserVerificationRequirement.REQUIRED.value,
        registration_timeout=60000,
        authentication_timeout=60000,
        challenge_length=32,
        challenge_expiry=300,
        supported_algorithms=[COSEAlgorithm.ES256, COSEAlgorithm.RS256],
        max_credentials_per_user=10,
        storage_backend="memory",
        rate_limits={},
        features={"COUNTER_VALIDATION": True},
        rp_id_resolver=rp_id_resolver,
        rp_id_by_origin=rp_id_by_origin or {},
    )


class ResolveRpIdPrecedenceTests(unittest.TestCase):
    """``PasskeyConfiguration.resolve_rp_id`` chooses the right source."""

    def test_fallback_when_nothing_configured(self):
        config = _make_config(rp_id="example.com")
        self.assertEqual(config.resolve_rp_id("https://anything.test"), "example.com")

    def test_fallback_when_origin_is_none(self):
        config = _make_config(rp_id="example.com", rp_id_by_origin={"https://a.test": "a.test"})
        self.assertEqual(config.resolve_rp_id(None), "example.com")
        self.assertEqual(config.resolve_rp_id(""), "example.com")

    def test_map_hit(self):
        config = _make_config(
            rp_id="example.com",
            rp_id_by_origin={"https://localhost:5173": "localhost"},
        )
        self.assertEqual(config.resolve_rp_id("https://localhost:5173"), "localhost")

    def test_map_miss_returns_fallback(self):
        config = _make_config(
            rp_id="example.com",
            rp_id_by_origin={"https://localhost:5173": "localhost"},
        )
        self.assertEqual(config.resolve_rp_id("https://other.test"), "example.com")

    def test_resolver_wins_over_map(self):
        """Resolver is checked first so it can override static mappings."""
        config = _make_config(
            rp_id="example.com",
            rp_id_resolver=lambda origin: "from-resolver" if origin.endswith(".preview.test") else None,
            rp_id_by_origin={"https://x.preview.test": "from-map"},
        )
        self.assertEqual(config.resolve_rp_id("https://x.preview.test"), "from-resolver")

    def test_resolver_none_falls_through_to_map(self):
        config = _make_config(
            rp_id="example.com",
            rp_id_resolver=lambda origin: None,
            rp_id_by_origin={"https://x.test": "x.test"},
        )
        self.assertEqual(config.resolve_rp_id("https://x.test"), "x.test")

    def test_resolver_empty_string_falls_through_to_fallback(self):
        config = _make_config(
            rp_id="example.com",
            rp_id_resolver=lambda origin: "",
        )
        self.assertEqual(config.resolve_rp_id("https://x.test"), "example.com")


class ConfigLoaderTests(unittest.TestCase):
    """Loading resolver and map from BLOCK_AUTH_SETTINGS."""

    def setUp(self):
        # Reset both the class cache and the module-level singleton's instance attribute.
        PasskeyConfigManager._config = None
        _config_manager._config = None

    def tearDown(self):
        PasskeyConfigManager._config = None
        _config_manager._config = None

    @override_settings(
        BLOCK_AUTH_SETTINGS={
            "FEATURES": {"PASSKEY_AUTH": True},
            "PASSKEY_CONFIG": {
                "RP_ID": "example.com",
                "RP_ID_RESOLVER": "blockauth.passkey.tests.test_rp_id_resolver._sample_resolver",
                "RP_ID_BY_ORIGIN": {
                    "https://app.example.com": "example.com",
                    "https://localhost:5173": "localhost",
                },
            },
        }
    )
    def test_dotted_path_resolver_is_loaded(self):
        config = PasskeyConfigManager().get_config(force_reload=True)
        self.assertTrue(callable(config.rp_id_resolver))
        self.assertEqual(config.rp_id_resolver("https://localhost:5173"), "localhost")
        self.assertEqual(
            config.rp_id_by_origin,
            {"https://app.example.com": "example.com", "https://localhost:5173": "localhost"},
        )

    @override_settings(
        BLOCK_AUTH_SETTINGS={
            "PASSKEY_CONFIG": {
                "RP_ID": "example.com",
                "RP_ID_RESOLVER": "does.not.exist.resolve",
            }
        }
    )
    def test_unimportable_resolver_raises_configuration_error(self):
        with self.assertRaises(ConfigurationError):
            PasskeyConfigManager().get_config(force_reload=True)

    @override_settings(
        BLOCK_AUTH_SETTINGS={
            "PASSKEY_CONFIG": {
                "RP_ID": "example.com",
                "RP_ID_RESOLVER": "not-a-dotted-path",
            }
        }
    )
    def test_non_dotted_resolver_raises_configuration_error(self):
        with self.assertRaises(ConfigurationError):
            PasskeyConfigManager().get_config(force_reload=True)

    @override_settings(
        BLOCK_AUTH_SETTINGS={
            "PASSKEY_CONFIG": {
                "RP_ID": "example.com",
                "RP_ID_BY_ORIGIN": "not-a-dict",
            }
        }
    )
    def test_non_dict_map_raises_configuration_error(self):
        with self.assertRaises(ConfigurationError):
            PasskeyConfigManager().get_config(force_reload=True)

    @override_settings(
        BLOCK_AUTH_SETTINGS={
            "PASSKEY_CONFIG": {
                "RP_ID": "example.com",
                "RP_ID_BY_ORIGIN": {"not-an-origin": "foo"},
            }
        }
    )
    def test_map_with_invalid_origin_key_raises_configuration_error(self):
        with self.assertRaises(ConfigurationError):
            PasskeyConfigManager().get_config(force_reload=True)

    @override_settings(
        BLOCK_AUTH_SETTINGS={
            "PASSKEY_CONFIG": {
                "RP_ID": "example.com",
                "RP_ID_BY_ORIGIN": {"https://app.test": ""},
            }
        }
    )
    def test_map_with_empty_rp_id_value_raises_configuration_error(self):
        with self.assertRaises(ConfigurationError):
            PasskeyConfigManager().get_config(force_reload=True)

    @override_settings(
        BLOCK_AUTH_SETTINGS={
            "PASSKEY_CONFIG": {"RP_ID": "example.com"},
        }
    )
    def test_defaults_are_backward_compatible(self):
        """Existing configs without the new keys keep working."""
        config = PasskeyConfigManager().get_config(force_reload=True)
        self.assertIsNone(config.rp_id_resolver)
        self.assertEqual(config.rp_id_by_origin, {})
        self.assertEqual(config.resolve_rp_id("https://anywhere.test"), "example.com")


class ServiceOverrideTests(unittest.TestCase):
    """``PasskeyService`` forwards ``rp_id`` / ``expected_rp_id`` overrides."""

    def _build_service_with_config(self, config):
        with patch("blockauth.passkey.services.passkey_service.get_passkey_config", return_value=config):
            return PasskeyService(
                credential_store=MagicMock(),
                challenge_service=MagicMock(),
            )

    def test_generate_registration_options_uses_override_rp_id(self):
        config = _make_config(rp_id="example.com")
        service = self._build_service_with_config(config)
        service._credential_store.count_by_user.return_value = 0
        service._credential_store.get_by_user.return_value = []
        service._challenge_service.generate.return_value = "AAAAAAAAAAAAAAAAAAAAAA"

        with (
            patch("blockauth.passkey.services.passkey_service.generate_registration_options") as mocked,
            patch(
                "blockauth.passkey.services.passkey_service.options_to_json",
                return_value='{"rp": {"id": "localhost"}}',
            ),
        ):
            mocked.return_value = MagicMock()
            service.generate_registration_options(
                user_id="user-1",
                username="a@b.test",
                rp_id="localhost",
            )
            self.assertEqual(mocked.call_args.kwargs["rp_id"], "localhost")

    def test_generate_registration_options_falls_back_to_config(self):
        config = _make_config(rp_id="example.com")
        service = self._build_service_with_config(config)
        service._credential_store.count_by_user.return_value = 0
        service._credential_store.get_by_user.return_value = []
        service._challenge_service.generate.return_value = "AAAAAAAAAAAAAAAAAAAAAA"

        with (
            patch("blockauth.passkey.services.passkey_service.generate_registration_options") as mocked,
            patch(
                "blockauth.passkey.services.passkey_service.options_to_json",
                return_value='{"rp": {"id": "example.com"}}',
            ),
        ):
            mocked.return_value = MagicMock()
            service.generate_registration_options(user_id="user-1", username="a@b.test")
            self.assertEqual(mocked.call_args.kwargs["rp_id"], "example.com")

    def test_generate_authentication_options_uses_override_rp_id(self):
        config = _make_config(rp_id="example.com")
        service = self._build_service_with_config(config)
        service._credential_store.get_by_user.return_value = []
        service._challenge_service.generate.return_value = "AAAAAAAAAAAAAAAAAAAAAA"

        with (
            patch("blockauth.passkey.services.passkey_service.generate_authentication_options") as mocked,
            patch(
                "blockauth.passkey.services.passkey_service.options_to_json",
                return_value='{"rpId": "localhost"}',
            ),
        ):
            mocked.return_value = MagicMock()
            service.generate_authentication_options(rp_id="localhost")
            self.assertEqual(mocked.call_args.kwargs["rp_id"], "localhost")


class ViewOriginResolutionTests(unittest.TestCase):
    """Views extract request origin and pass the resolved RP_ID to the service."""

    def setUp(self):
        self.factory = RequestFactory()
        PasskeyConfigManager._config = None
        _config_manager._config = None

    def tearDown(self):
        PasskeyConfigManager._config = None
        _config_manager._config = None

    def test_request_origin_uses_origin_header(self):
        from ..views import _request_origin

        request = self.factory.post(
            "/auth/passkey/register/options/",
            HTTP_ORIGIN="https://localhost:5173",
        )
        self.assertEqual(_request_origin(request), "https://localhost:5173")

    def test_request_origin_ignores_referer_header(self):
        """Referer is not CORS-controlled - it MUST NOT be used as a trust signal."""
        from ..views import _request_origin

        request = self.factory.post(
            "/auth/passkey/register/options/",
            HTTP_REFERER="https://attacker.test/login",
        )
        self.assertEqual(_request_origin(request), "")

    def test_request_origin_empty_when_no_headers(self):
        from ..views import _request_origin

        request = self.factory.post("/auth/passkey/register/options/")
        self.assertEqual(_request_origin(request), "")

    @override_settings(
        BLOCK_AUTH_SETTINGS={
            "FEATURES": {"PASSKEY_AUTH": True},
            "PASSKEY_CONFIG": {
                "RP_ID": "example.com",
                "RP_ID_BY_ORIGIN": {"https://localhost:5173": "localhost"},
            },
        }
    )
    def test_resolve_rp_id_uses_config_resolve(self):
        from ..views import _resolve_rp_id

        PasskeyConfigManager().get_config(force_reload=True)
        request = self.factory.post(
            "/auth/passkey/register/options/",
            HTTP_ORIGIN="https://localhost:5173",
        )
        self.assertEqual(_resolve_rp_id(request), "localhost")

        request_other = self.factory.post(
            "/auth/passkey/register/options/",
            HTTP_ORIGIN="https://unknown.test",
        )
        self.assertEqual(_resolve_rp_id(request_other), "example.com")

    @override_settings(
        BLOCK_AUTH_SETTINGS={
            "FEATURES": {"PASSKEY_AUTH": True},
            "PASSKEY_CONFIG": {
                "RP_ID": "example.com",
                "RP_ID_RESOLVER": "does.not.exist.resolve",
            },
        }
    )
    def test_resolve_rp_id_propagates_configuration_error(self):
        """Misconfigured resolver MUST surface loudly, not silently fall back."""
        from ..views import _resolve_rp_id

        request = self.factory.post(
            "/auth/passkey/register/options/",
            HTTP_ORIGIN="https://app.example.com",
        )
        with self.assertRaises(ConfigurationError):
            _resolve_rp_id(request)
