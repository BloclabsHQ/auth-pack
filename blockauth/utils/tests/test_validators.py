"""
Tests for FabricBloc validators.

Tests the password validation functions and Django validator class.
"""

import pytest
from django.core.exceptions import ValidationError

from blockauth.utils.validators import (
    PASSWORD_MIN_LENGTH,
    PASSWORD_MAX_LENGTH,
    PASSWORD_VALIDATION_ERROR,
    validate_password,
    is_valid_password,
    is_valid_phone_number,
    FabricBlocPasswordValidator,
)


class TestPasswordConstants:
    """Test password validation constants."""

    def test_min_length_is_8(self):
        assert PASSWORD_MIN_LENGTH == 8

    def test_max_length_is_128(self):
        assert PASSWORD_MAX_LENGTH == 128

    def test_validation_error_message_format(self):
        assert "8-128 characters" in PASSWORD_VALIDATION_ERROR
        assert "uppercase" in PASSWORD_VALIDATION_ERROR
        assert "lowercase" in PASSWORD_VALIDATION_ERROR
        assert "number" in PASSWORD_VALIDATION_ERROR
        assert "symbol" in PASSWORD_VALIDATION_ERROR


class TestValidatePassword:
    """Test the validate_password function."""

    def test_valid_password_returns_empty_list(self):
        """Valid passwords should return empty error list."""
        valid_passwords = [
            "MyP@ssw0rd!",
            "Str0ng!Pass",
            "Test123!@#",
            "Abcd1234!",
            "P@ssword1",
        ]
        for password in valid_passwords:
            errors = validate_password(password)
            assert errors == [], f"Expected no errors for '{password}', got {errors}"

    def test_invalid_password_returns_standard_error(self):
        """Invalid passwords should return the standard error message."""
        invalid_passwords = [
            "weak",
            "password",
            "PASSWORD",
            "12345678",
            "!@#$%^&*",
        ]
        for password in invalid_passwords:
            errors = validate_password(password)
            assert len(errors) == 1, f"Expected 1 error for '{password}', got {len(errors)}"
            assert errors[0] == PASSWORD_VALIDATION_ERROR

    def test_too_short_password(self):
        """Passwords shorter than 8 characters should fail."""
        errors = validate_password("Ab1!xyz")  # 7 chars
        assert len(errors) == 1
        assert errors[0] == PASSWORD_VALIDATION_ERROR

    def test_too_long_password(self):
        """Passwords longer than 128 characters should fail."""
        long_password = "Ab1!" + "a" * 130
        errors = validate_password(long_password)
        assert len(errors) == 1
        assert errors[0] == PASSWORD_VALIDATION_ERROR

    def test_missing_uppercase(self):
        """Passwords without uppercase letter should fail."""
        errors = validate_password("password1!")
        assert len(errors) == 1
        assert errors[0] == PASSWORD_VALIDATION_ERROR

    def test_missing_lowercase(self):
        """Passwords without lowercase letter should fail."""
        errors = validate_password("PASSWORD1!")
        assert len(errors) == 1
        assert errors[0] == PASSWORD_VALIDATION_ERROR

    def test_missing_number(self):
        """Passwords without number should fail."""
        errors = validate_password("Password!")
        assert len(errors) == 1
        assert errors[0] == PASSWORD_VALIDATION_ERROR

    def test_missing_symbol(self):
        """Passwords without symbol should fail."""
        errors = validate_password("Password1")
        assert len(errors) == 1
        assert errors[0] == PASSWORD_VALIDATION_ERROR

    def test_all_valid_symbols(self):
        """All allowed symbols should be accepted."""
        symbols = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '-', '=',
                   '[', ']', '{', '}', ';', "'", ':', '"', '\\', '|', ',', '.', '<', '>', '/', '?']
        for symbol in symbols:
            password = f"Password1{symbol}"
            errors = validate_password(password)
            assert errors == [], f"Symbol '{symbol}' should be valid, got errors: {errors}"

    def test_exact_min_length(self):
        """Password with exactly 8 characters should be valid if other requirements met."""
        errors = validate_password("Abcd12!@")  # Exactly 8 chars
        assert errors == []

    def test_exact_max_length(self):
        """Password with exactly 128 characters should be valid if other requirements met."""
        password = "Ab1!" + "a" * 124  # Exactly 128 chars
        errors = validate_password(password)
        assert errors == []


class TestIsValidPassword:
    """Test the is_valid_password function."""

    def test_valid_password_returns_true(self):
        assert is_valid_password("MyP@ssw0rd!") is True
        assert is_valid_password("Str0ng!Pass") is True

    def test_invalid_password_returns_false(self):
        assert is_valid_password("weak") is False
        assert is_valid_password("password") is False
        assert is_valid_password("Password1") is False  # missing symbol
        assert is_valid_password("password1!") is False  # missing uppercase


class TestFabricBlocPasswordValidator:
    """Test the Django password validator class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.validator = FabricBlocPasswordValidator()

    def test_valid_password_does_not_raise(self):
        """Valid passwords should not raise ValidationError."""
        valid_passwords = [
            "MyP@ssw0rd!",
            "Str0ng!Pass",
            "Test123!@#",
        ]
        for password in valid_passwords:
            # Should not raise
            self.validator.validate(password)

    def test_invalid_password_raises_validation_error(self):
        """Invalid passwords should raise ValidationError."""
        invalid_passwords = [
            "weak",
            "password",
            "Password1",  # missing symbol
        ]
        for password in invalid_passwords:
            with pytest.raises(ValidationError) as exc_info:
                self.validator.validate(password)
            assert PASSWORD_VALIDATION_ERROR in str(exc_info.value)

    def test_validate_with_user_parameter(self):
        """Validator should accept optional user parameter (Django compatibility)."""
        # Should not raise with user=None
        self.validator.validate("MyP@ssw0rd!", user=None)

    def test_get_help_text_returns_standard_message(self):
        """Help text should match the standard error message."""
        help_text = self.validator.get_help_text()
        assert "8-128 characters" in help_text
        assert "uppercase" in help_text
        assert "lowercase" in help_text
        assert "number" in help_text
        assert "symbol" in help_text


class TestIsValidPhoneNumber:
    """Test the phone number validator."""

    def test_valid_international_phone_numbers(self):
        """Valid international phone numbers should return True."""
        valid_numbers = [
            "+12345678901",
            "+123456789012345",
            "+1 234 567 8901",
            "+1-234-567-8901",
            "+1(234)567-8901",
        ]
        for number in valid_numbers:
            assert is_valid_phone_number(number) is True, f"Expected True for '{number}'"

    def test_invalid_phone_numbers(self):
        """Invalid phone numbers should return False."""
        invalid_numbers = [
            "1234567890",  # No + prefix
            "+123456789",  # Too short
            "+1234567890123456",  # Too long
            "invalid",
            "",
            "+abc12345678",  # Contains letters
        ]
        for number in invalid_numbers:
            assert is_valid_phone_number(number) is False, f"Expected False for '{number}'"


class TestPasswordEdgeCases:
    """Test edge cases for password validation."""

    def test_empty_password(self):
        """Empty password should fail."""
        errors = validate_password("")
        assert len(errors) == 1
        assert is_valid_password("") is False

    def test_whitespace_only_password(self):
        """Whitespace-only password should fail."""
        errors = validate_password("        ")  # 8 spaces
        assert len(errors) == 1
        assert is_valid_password("        ") is False

    def test_unicode_characters(self):
        """Unicode characters should not count as required character types."""
        # Has length, but uses unicode instead of ASCII
        errors = validate_password("Pässwörd1!")
        # Should still be valid since it has ASCII uppercase, lowercase, number, symbol
        assert errors == []

    def test_password_with_spaces(self):
        """Password with spaces should be valid if other requirements met."""
        errors = validate_password("My Pass1!")
        assert errors == []
