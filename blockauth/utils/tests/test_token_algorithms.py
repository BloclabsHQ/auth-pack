"""
Tests for JWT token algorithm support (HS256 + RS256/ES256).

Validates:
- HS256 backward compatibility (no config change needed)
- RS256 sign with private key, verify with public key
- RS256 missing keys raises clear error
- Cross-algorithm rejection (HS256 token can't be verified with RS256)
- Token payload integrity across algorithms
"""

import os
from datetime import timedelta
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from blockauth.utils.token import Token, _resolve_keys, _ASYMMETRIC_ALGORITHMS

TEST_HS256_SECRET = os.environ.get("TEST_JWT_SECRET", "test-hs256-secret-key-for-unit-tests")


def _generate_rsa_keypair():
    """Generate a fresh RSA key pair for testing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


class TestResolveKeys:
    """Test _resolve_keys helper."""

    def test_explicit_secret_key_overrides_everything(self):
        signing, verification = _resolve_keys("RS256", explicit_secret_key="override")
        assert signing == "override"
        assert verification == "override"

    @patch("blockauth.utils.token.get_config")
    def test_hs256_uses_jwt_secret_key(self, mock_config):
        mock_config.return_value = TEST_HS256_SECRET
        signing, verification = _resolve_keys("HS256")
        assert signing == TEST_HS256_SECRET
        assert verification == TEST_HS256_SECRET

    @patch("blockauth.utils.token.get_config")
    def test_rs256_uses_private_and_public_keys(self, mock_config):
        private_pem, public_pem = _generate_rsa_keypair()

        def side_effect(key):
            return {"JWT_PRIVATE_KEY": private_pem, "JWT_PUBLIC_KEY": public_pem}[key]

        mock_config.side_effect = side_effect
        signing, verification = _resolve_keys("RS256")
        assert signing == private_pem
        assert verification == public_pem

    @patch("blockauth.utils.token.get_config")
    def test_rs256_missing_keys_raises_error(self, mock_config):
        mock_config.return_value = None
        with pytest.raises(ValueError, match="requires both JWT_PRIVATE_KEY and JWT_PUBLIC_KEY"):
            _resolve_keys("RS256")

    def test_asymmetric_algorithms_set(self):
        assert "RS256" in _ASYMMETRIC_ALGORITHMS
        assert "ES256" in _ASYMMETRIC_ALGORITHMS
        assert "HS256" not in _ASYMMETRIC_ALGORITHMS


class TestTokenHS256:
    """Test Token with HS256 (backward compatibility)."""

    def test_generate_and_decode(self):
        token = Token(secret_key=TEST_HS256_SECRET, algorithm="HS256")
        encoded = token.generate_token(
            user_id="user-123",
            token_type="access",
            token_lifetime=timedelta(minutes=15),
        )
        payload = token.decode_token(encoded)
        assert payload["user_id"] == "user-123"
        assert payload["type"] == "access"

    def test_signing_key_equals_verification_key(self):
        token = Token(secret_key=TEST_HS256_SECRET, algorithm="HS256")
        assert token.signing_key == token.verification_key

    def test_backward_compat_secret_key_attribute(self):
        token = Token(secret_key=TEST_HS256_SECRET, algorithm="HS256")
        assert token.secret_key == TEST_HS256_SECRET

    def test_user_data_in_payload(self):
        token = Token(secret_key=TEST_HS256_SECRET, algorithm="HS256")
        encoded = token.generate_token(
            user_id="user-456",
            token_type="access",
            token_lifetime=timedelta(minutes=15),
            user_data={"role": "admin", "tier": "pro"},
        )
        payload = token.decode_token(encoded)
        assert payload["role"] == "admin"
        assert payload["tier"] == "pro"


class TestTokenRS256:
    """Test Token with RS256 (asymmetric)."""

    @pytest.fixture
    def rsa_keys(self):
        return _generate_rsa_keypair()

    @patch("blockauth.utils.token.get_config")
    def test_generate_and_decode(self, mock_config, rsa_keys):
        private_pem, public_pem = rsa_keys

        def side_effect(key):
            return {
                "ALGORITHM": "RS256",
                "JWT_PRIVATE_KEY": private_pem,
                "JWT_PUBLIC_KEY": public_pem,
            }.get(key)

        mock_config.side_effect = side_effect
        token = Token(algorithm="RS256")

        encoded = token.generate_token(
            user_id="user-rs256",
            token_type="access",
            token_lifetime=timedelta(minutes=15),
        )
        payload = token.decode_token(encoded)
        assert payload["user_id"] == "user-rs256"
        assert payload["type"] == "access"

    @patch("blockauth.utils.token.get_config")
    def test_signing_key_differs_from_verification_key(self, mock_config, rsa_keys):
        private_pem, public_pem = rsa_keys

        def side_effect(key):
            return {
                "ALGORITHM": "RS256",
                "JWT_PRIVATE_KEY": private_pem,
                "JWT_PUBLIC_KEY": public_pem,
            }.get(key)

        mock_config.side_effect = side_effect
        token = Token(algorithm="RS256")
        assert token.signing_key != token.verification_key

    def test_hs256_token_rejected_by_rs256(self, rsa_keys):
        private_pem, public_pem = rsa_keys

        # Sign with HS256
        hs_token = Token(secret_key=TEST_HS256_SECRET, algorithm="HS256")
        encoded = hs_token.generate_token(
            user_id="user-cross",
            token_type="access",
            token_lifetime=timedelta(minutes=15),
        )

        # Try to decode with RS256 public key — should fail
        with pytest.raises(Exception):
            jwt.decode(encoded, public_pem, algorithms=["RS256"])

    @patch("blockauth.utils.token.get_config")
    def test_public_key_cannot_sign(self, mock_config, rsa_keys):
        _, public_pem = rsa_keys

        # Try to sign with public key — PyJWT should reject
        with pytest.raises(Exception):
            jwt.encode(
                {"user_id": "attacker", "type": "access"},
                public_pem,
                algorithm="RS256",
            )

    @patch("blockauth.utils.token.get_config")
    def test_user_data_preserved(self, mock_config, rsa_keys):
        private_pem, public_pem = rsa_keys

        def side_effect(key):
            return {
                "ALGORITHM": "RS256",
                "JWT_PRIVATE_KEY": private_pem,
                "JWT_PUBLIC_KEY": public_pem,
            }.get(key)

        mock_config.side_effect = side_effect
        token = Token(algorithm="RS256")

        encoded = token.generate_token(
            user_id="user-data",
            token_type="access",
            token_lifetime=timedelta(minutes=15),
            user_data={"email": "test@example.com", "tier": "enterprise"},
        )
        payload = token.decode_token(encoded)
        assert payload["email"] == "test@example.com"
        assert payload["tier"] == "enterprise"
