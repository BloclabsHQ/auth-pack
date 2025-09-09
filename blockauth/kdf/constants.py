"""
Constants for Key Derivation Function (KDF) Module

This module defines constants used throughout the KDF system including
feature flags, configuration keys, and security parameters.
"""

from enum import Enum


class KDFFeatures:
    """Feature flags for KDF functionality"""
    
    # Core KDF features
    ENABLE_KDF = 'ENABLE_KDF'                    # Master switch for KDF
    DETERMINISTIC_KEYS = 'DETERMINISTIC_KEYS'    # Same input always produces same key
    PASSWORD_VERIFICATION = 'PASSWORD_VERIFICATION'  # Verify passwords via KDF
    
    # Security features
    KEY_ENCRYPTION = 'KEY_ENCRYPTION'            # Encrypt private keys at rest
    KEY_ROTATION = 'KEY_ROTATION'                # Enable key rotation
    AUDIT_LOGGING = 'AUDIT_LOGGING'              # Log all key operations
    
    # Advanced features
    MULTI_ALGORITHM = 'MULTI_ALGORITHM'          # Support multiple KDF algorithms
    CUSTOM_ITERATIONS = 'CUSTOM_ITERATIONS'       # Allow custom iteration counts
    EXPORT_KEYS = 'EXPORT_KEYS'                  # Allow users to export private keys
    
    @classmethod
    def all_features(cls):
        """Get all available KDF feature constants"""
        return [
            cls.ENABLE_KDF,
            cls.DETERMINISTIC_KEYS,
            cls.PASSWORD_VERIFICATION,
            cls.KEY_ENCRYPTION,
            cls.KEY_ROTATION,
            cls.AUDIT_LOGGING,
            cls.MULTI_ALGORITHM,
            cls.CUSTOM_ITERATIONS,
            cls.EXPORT_KEYS,
        ]


class KDFAlgorithms:
    """Supported key derivation algorithms"""
    
    PBKDF2_SHA256 = 'pbkdf2_sha256'      # PBKDF2 with SHA-256 (default)
    PBKDF2_SHA512 = 'pbkdf2_sha512'      # PBKDF2 with SHA-512
    ARGON2ID = 'argon2id'                 # Argon2id (most secure)
    SCRYPT = 'scrypt'                     # Scrypt (memory-hard)
    
    @classmethod
    def all_algorithms(cls):
        """Get all supported algorithms"""
        return [
            cls.PBKDF2_SHA256,
            cls.PBKDF2_SHA512,
            cls.ARGON2ID,
            cls.SCRYPT,
        ]
    
    @classmethod
    def is_supported(cls, algorithm: str) -> bool:
        """Check if algorithm is supported"""
        return algorithm in cls.all_algorithms()


class ConfigKeys:
    """Configuration keys for KDF settings"""
    
    # KDF algorithm configuration
    KDF_ALGORITHM = 'KDF_ALGORITHM'              # Default algorithm to use
    KDF_ITERATIONS = 'KDF_ITERATIONS'             # Default iteration count
    KDF_MASTER_SALT = 'KDF_MASTER_SALT'          # Platform master salt
    
    # Security configuration
    MASTER_ENCRYPTION_KEY = 'MASTER_ENCRYPTION_KEY'  # Master encryption key
    KEY_ROTATION_DAYS = 'KEY_ROTATION_DAYS'          # Days between key rotations
    MAX_FAILED_ATTEMPTS = 'MAX_FAILED_ATTEMPTS'      # Max failed password attempts
    
    # Performance configuration
    CACHE_DERIVED_KEYS = 'CACHE_DERIVED_KEYS'        # Cache derived keys (addresses only)
    CACHE_TTL_SECONDS = 'CACHE_TTL_SECONDS'          # Cache TTL in seconds


class SecurityConstants:
    """Security-related constants and thresholds"""
    
    # Salt requirements
    MIN_SALT_LENGTH = 32                    # Minimum salt length in characters
    MIN_SALT_BYTES = 16                     # Minimum salt length in bytes (for binary salts)
    
    # Key requirements
    MIN_PASSWORD_LENGTH = 8                 # Minimum password length
    MIN_ITERATIONS = 1000                   # Minimum KDF iterations
    
    # Encryption requirements
    AES_KEY_LENGTH = 32                     # AES-256 key length in bytes
    AES_NONCE_LENGTH = 12                   # AES-GCM nonce length in bytes
    AES_TAG_LENGTH = 16                     # AES-GCM tag length in bytes


class SecurityLevels:
    """Security level presets for different use cases"""
    
    LOW = {
        'iterations': 10000,
        'algorithm': KDFAlgorithms.PBKDF2_SHA256,
        'description': 'Development/testing only'
    }
    
    MEDIUM = {
        'iterations': 100000,
        'algorithm': KDFAlgorithms.PBKDF2_SHA256,
        'description': 'Standard production use'
    }
    
    HIGH = {
        'iterations': 500000,
        'algorithm': KDFAlgorithms.ARGON2ID,
        'description': 'High security applications'
    }
    
    CRITICAL = {
        'iterations': 1000000,
        'algorithm': KDFAlgorithms.ARGON2ID,
        'description': 'Financial/critical systems'
    }
    
    @classmethod
    def get_preset(cls, level: str) -> dict:
        """Get security preset configuration"""
        return getattr(cls, level.upper(), cls.MEDIUM)


class ErrorMessages:
    """Standard error messages for KDF operations"""
    
    INVALID_ALGORITHM = "Unsupported key derivation algorithm"
    INVALID_ITERATIONS = "Invalid iteration count (must be > 1000)"
    INVALID_MASTER_SALT = "Master salt must be at least 32 characters"
    INVALID_ENCRYPTION_KEY = "Invalid encryption key format"
    KEY_DERIVATION_FAILED = "Failed to derive key from credentials"
    ENCRYPTION_FAILED = "Failed to encrypt private key"
    DECRYPTION_FAILED = "Failed to decrypt private key"
    INVALID_PASSWORD = "Invalid password for key verification"
    KEY_NOT_FOUND = "Private key not found for user"
    KEY_COMPROMISED = "Private key has been marked as compromised"
    RATE_LIMIT_EXCEEDED = "Too many key derivation attempts"
    INSUFFICIENT_ENTROPY = "Insufficient entropy in password"
