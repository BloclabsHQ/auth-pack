"""
Key Derivation Function (KDF) Module for BlockAuth

This module provides secure key derivation from email/password combinations,
enabling Web2 users to have blockchain accounts without managing crypto keys.

IMPORTANT: This is an OPTIONAL module that must be explicitly enabled.
It will not be loaded unless KDF_ENABLED=True is set in your project settings.

Core Services:
- KDFManager: Main manager with dual encryption (user control + platform access)
- MultipleWalletService: Support for multiple wallets per user
- KeyDerivationService: Core KDF functionality
- KeyEncryptionService: Encryption/decryption services

Key Features:
- Dual encryption: User password + Platform key
- Platform can recover any user wallet
- Users maintain control over their wallets
- Multiple wallets per user with different salts
- Framework-agnostic design

Usage:
    # In your project's settings.py
    BLOCK_AUTH_SETTINGS = {
        'KDF_ENABLED': True,  # Enable KDF functionality
        'KDF_ALGORITHM': 'pbkdf2_sha256',
        'KDF_ITERATIONS': 100000,
        'KDF_MASTER_SALT': 'your-platform-salt-32-chars-minimum',
        'MASTER_ENCRYPTION_KEY': '0x' + 'your-256-bit-key-in-hex',
        'PLATFORM_MASTER_SALT': 'your-platform-master-salt-32-chars',  # For passwordless
    }
    
    # In your code
    from blockauth.kdf import get_kdf_manager
    
    if blockauth.kdf.is_enabled():
        kdf_manager = get_kdf_manager()
        
        # Create wallet with dual encryption
        wallet = kdf_manager.create_wallet(email, password, 'primary')
        
        # Create multiple wallets
        wallets = kdf_manager.create_multiple_wallets(email, password, ['primary', 'savings'])
        
        # User decrypts with password
        private_key = kdf_manager.decrypt_with_user_password(email, password, wallet['user_encrypted_key'], wallet['user_salt'])
        
        # Platform decrypts without password
        private_key = kdf_manager.decrypt_with_platform_key(wallet['platform_encrypted_key'])
"""

# Don't import services by default - they're loaded lazily when needed
from .constants import KDFFeatures

# Only expose constants and utility functions
__all__ = [
    'KDFFeatures',
    'is_enabled',
    'get_kdf_manager',
    'get_multiple_wallet_service'
]


def is_enabled():
    """
    Check if KDF is enabled in the current project
    
    Returns:
        bool: True if KDF is enabled, False otherwise
    """
    try:
        from django.conf import settings
        return getattr(settings, 'BLOCK_AUTH_SETTINGS', {}).get('KDF_ENABLED', False)
    except ImportError:
        # Not in Django context
        return False


def get_kdf_manager():
    """
    Get the main KDF manager (RECOMMENDED)
    
    Returns:
        KDFManager: Configured KDF manager with dual encryption
        
    Raises:
        ImportError: If KDF is not enabled
    """
    if not is_enabled():
        raise ImportError(
            "KDF is not enabled. Set KDF_ENABLED=True in BLOCK_AUTH_SETTINGS "
            "to use KDF functionality."
        )
    
    # Lazy import to avoid loading when not needed
    from .services import KDFManager
    return KDFManager()


def get_multiple_wallet_service():
    """
    Get the multiple wallet service (for multiple wallets per user)
    
    Returns:
        MultipleWalletService: Configured service for multiple wallet management
        
    Raises:
        ImportError: If KDF is not enabled
    """
    if not is_enabled():
        raise ImportError(
            "KDF is not enabled. Set KDF_ENABLED=True in BLOCK_AUTH_SETTINGS "
            "to use KDF functionality."
        )
    
    # Lazy import to avoid loading when not needed
    from .services import MultipleWalletService
    return MultipleWalletService()
