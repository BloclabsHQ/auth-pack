"""
Core KDF Services for BlockAuth

This module provides the main services for key derivation and encryption:
- KeyDerivationService: Derives private keys from user credentials (password-based)
- PasswordlessKDFService: Generates wallets for passwordless users
- KeyEncryptionService: Securely encrypts/decrypts private keys
- KDFManager: Main manager with dual encryption for platform access + user control
- MultipleWalletService: Support for multiple wallets per user

Key Features:
- Dual encryption: User password + Platform key
- Platform can recover any user wallet
- Users maintain control over their wallets
- Multiple wallets per user with different salts
- Framework-agnostic design
"""

import os
import hashlib
import json
import logging
import time
import uuid
from typing import Dict, List, Optional, Tuple, Union
from abc import ABC, abstractmethod
from datetime import datetime, timedelta

# Web3 imports
from web3 import Web3
from eth_account import Account

# Import constants
from .constants import (
    KDFAlgorithms, 
    ConfigKeys, 
    SecurityLevels, 
    ErrorMessages
)

logger = logging.getLogger(__name__)


def get_kdf_config():
    """
    Get KDF configuration from project settings
    
    Returns:
        dict: Configuration dictionary with defaults
    """
    try:
        from django.conf import settings
        block_auth_settings = getattr(settings, 'BLOCK_AUTH_SETTINGS', {})
        
        return {
            'algorithm': block_auth_settings.get('KDF_ALGORITHM', KDFAlgorithms.PBKDF2_SHA256),
            'iterations': block_auth_settings.get('KDF_ITERATIONS', 100000),
            'master_salt': block_auth_settings.get('KDF_MASTER_SALT', ''),
            'encryption_key': block_auth_settings.get('MASTER_ENCRYPTION_KEY', ''),
            'security_level': block_auth_settings.get('KDF_SECURITY_LEVEL', 'MEDIUM'),
            'platform_master_salt': block_auth_settings.get('PLATFORM_MASTER_SALT', ''),
        }
    except ImportError:
        # Not in Django context, use environment variables
        return {
            'algorithm': os.environ.get('KDF_ALGORITHM', KDFAlgorithms.PBKDF2_SHA256),
            'iterations': int(os.environ.get('KDF_ITERATIONS', '100000')),
            'master_salt': os.environ.get('KDF_MASTER_SALT', ''),
            'encryption_key': os.environ.get('MASTER_ENCRYPTION_KEY', ''),
            'security_level': os.environ.get('KDF_SECURITY_LEVEL', 'MEDIUM'),
            'platform_master_salt': os.environ.get('PLATFORM_MASTER_SALT', ''),
        }


class BaseKDFService(ABC):
    """Abstract base class for KDF implementations"""
    
    @abstractmethod
    def derive_key(self, email: str, password: str, salt: str, **kwargs) -> str:
        """Derive a private key from credentials"""
        pass
    
    @abstractmethod
    def verify_key(self, email: str, password: str, salt: str, 
                  expected_key: str, **kwargs) -> bool:
        """Verify if credentials produce expected key"""
        pass


class PBKDF2Service(BaseKDFService):
    """PBKDF2-based key derivation service"""
    
    def __init__(self, iterations: int = 100000, hash_algorithm: str = 'sha256'):
        self.iterations = max(1000, iterations)  # Minimum security threshold
        self.hash_algorithm = hash_algorithm
        
        if hash_algorithm not in ['sha256', 'sha512']:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
    
    def derive_key(self, email: str, password: str, salt: str, **kwargs) -> str:
        """Derive private key using PBKDF2"""
        try:
            # Normalize inputs
            email = email.lower().strip()
            password = password.strip()
            
            # Create input string with platform master salt if available
            master_salt = kwargs.get('master_salt', '')
            kdf_input = f"{email}:{password}:{salt}:{master_salt}"
            
            # Derive key material using PBKDF2
            key_material = hashlib.pbkdf2_hmac(
                self.hash_algorithm,
                kdf_input.encode('utf-8'),
                salt.encode('utf-8'),
                self.iterations,
                dklen=32  # 32 bytes for private key
            )
            
            return '0x' + key_material.hex()
            
        except Exception as e:
            logger.error(f"PBKDF2 key derivation failed: {e}")
            raise ValueError(ErrorMessages.KEY_DERIVATION_FAILED)
    
    def verify_key(self, email: str, password: str, salt: str, 
                  expected_key: str, **kwargs) -> bool:
        """Verify if credentials produce expected key"""
        try:
            derived_key = self.derive_key(email, password, salt, **kwargs)
            return derived_key.lower() == expected_key.lower()
        except Exception:
            return False


class Argon2Service(BaseKDFService):
    """Argon2-based key derivation service (most secure)"""
    
    def __init__(self, time_cost: int = 3, memory_cost: int = 65536, 
                 parallelism: int = 4):
        self.time_cost = max(1, time_cost)
        self.memory_cost = max(1024, memory_cost)  # Minimum 1MB
        self.parallelism = max(1, parallelism)
        
        # Try to import argon2, fallback to PBKDF2 if not available
        try:
            import argon2
            self.argon2_available = True
        except ImportError:
            logger.warning("Argon2 not available, falling back to PBKDF2")
            self.argon2_available = False
    
    def derive_key(self, email: str, password: str, salt: str, **kwargs) -> str:
        """Derive private key using Argon2id"""
        if not self.argon2_available:
            # Fallback to PBKDF2
            fallback_service = PBKDF2Service(iterations=100000)
            return fallback_service.derive_key(email, password, salt, **kwargs)
        
        try:
            import argon2
            
            # Normalize inputs
            email = email.lower().strip()
            password = password.strip()
            
            # Create input string
            master_salt = kwargs.get('master_salt', '')
            kdf_input = f"{email}:{password}:{salt}:{master_salt}"
            
            # Create Argon2 hasher
            hasher = argon2.PasswordHasher(
                time_cost=self.time_cost,
                memory_cost=self.memory_cost,
                parallelism=self.parallelism,
                hash_len=32,
                type=argon2.Type.ID  # Argon2id variant
            )
            
            # Generate hash
            hash_result = hasher.hash(kdf_input, salt=salt.encode())
            
            # Extract key material (last 64 hex chars = 32 bytes)
            key_material = hash_result[-64:]
            
            return '0x' + key_material
            
        except Exception as e:
            logger.error(f"Argon2 key derivation failed: {e}")
            raise ValueError(ErrorMessages.KEY_DERIVATION_FAILED)
    
    def verify_key(self, email: str, password: str, salt: str, 
                  expected_key: str, **kwargs) -> bool:
        """Verify if credentials produce expected key"""
        try:
            derived_key = self.derive_key(email, password, salt, **kwargs)
            return derived_key.lower() == expected_key.lower()
        except Exception:
            return False


class PasswordlessKDFService:
    """
    Service for generating wallets for passwordless users
    
    This service creates deterministic wallets from email addresses
    and encrypts them with platform-level keys.
    """
    
    def __init__(self, platform_master_salt: str = None):
        """
        Initialize passwordless KDF service
        
        Args:
            platform_master_salt: Platform master salt for deterministic generation
        """
        config = get_kdf_config()
        self.platform_master_salt = platform_master_salt or config['platform_master_salt']
        
        if not self.platform_master_salt:
            raise ValueError("Platform master salt required for passwordless wallets")
        
        if len(self.platform_master_salt) < 32:
            raise ValueError("Platform master salt must be at least 32 characters")
    
    def create_user_wallet(self, email: str) -> Dict[str, str]:
        """
        Create deterministic wallet for passwordless user
        
        Args:
            email: User's email address
        
        Returns:
            Dict containing wallet data
        """
        try:
            # Generate deterministic salt from email
            email_salt = self._generate_email_salt(email)
            
            # Derive private key from email + platform salt
            private_key = self._derive_private_key(email, email_salt)
            
            # Generate wallet address
            account = Account.from_key(private_key)
            wallet_address = account.address
            
            # Clear private key from memory immediately
            private_key = '0' * len(private_key)
            del private_key
            
            return {
                'wallet_address': wallet_address,
                'salt': email_salt,
                'public_key': account.key.hex(),
                'algorithm': 'sha256_deterministic',
                'auth_method': 'passwordless',
                'deterministic': True,
                'created_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Passwordless wallet creation failed: {e}")
            raise ValueError(f"Failed to create passwordless wallet: {str(e)}")
    
    def get_wallet_address(self, email: str) -> str:
        """
        Get wallet address for email (deterministic)
        
        Args:
            email: User's email address
        
        Returns:
            Wallet address (always the same for same email)
        """
        try:
            email_salt = self._generate_email_salt(email)
            private_key = self._derive_private_key(email, email_salt)
            account = Account.from_key(private_key)
            address = account.address
            
            # Clear private key from memory
            private_key = '0' * len(private_key)
            del private_key
            
            return address
            
        except Exception as e:
            logger.error(f"Failed to get passwordless wallet address: {e}")
            raise ValueError(f"Failed to get wallet address: {str(e)}")
    
    def _generate_email_salt(self, email: str) -> str:
        """Generate deterministic salt from email"""
        email = email.lower().strip()
        salt_input = f"{email}:{self.platform_master_salt}"
        return hashlib.sha256(salt_input.encode()).hexdigest()
    
    def _derive_private_key(self, email: str, salt: str) -> str:
        """Derive private key from email + platform salt"""
        email = email.lower().strip()
        kdf_input = f"{email}:{salt}:{self.platform_master_salt}"
        
        # Use SHA-256 for deterministic generation
        key_material = hashlib.sha256(kdf_input.encode()).digest()
        return '0x' + key_material.hex()


class KeyDerivationService:
    """
    Main service for deriving cryptographic keys from user credentials
    
    This service is framework-agnostic and can be used in any Python project.
    It supports multiple KDF algorithms and provides a unified interface.
    Configuration is automatically read from project settings.
    """
    
    def __init__(self, 
                 algorithm: str = None,
                 iterations: int = None,
                 master_salt: str = None,
                 security_level: str = None):
        """
        Initialize KDF service
        
        Args:
            algorithm: KDF algorithm to use (defaults to settings)
            iterations: Number of iterations for PBKDF2 (defaults to settings)
            master_salt: Platform master salt (defaults to settings)
            security_level: Security preset (defaults to settings)
        """
        # Get configuration from project settings
        config = get_kdf_config()
        
        # Use provided values or defaults from settings
        self.algorithm = algorithm or config['algorithm']
        self.iterations = iterations or config['iterations']
        self.master_salt = master_salt or config['master_salt']
        security_level = security_level or config['security_level']
        
        # Validate algorithm
        if not KDFAlgorithms.is_supported(self.algorithm):
            raise ValueError(ErrorMessages.INVALID_ALGORITHM)
        
        # Apply security preset if specified
        if security_level:
            preset = SecurityLevels.get_preset(security_level)
            self.algorithm = preset['algorithm']
            self.iterations = preset['iterations']
        
        self.iterations = max(1000, self.iterations)
        
        # Initialize algorithm-specific service
        if self.algorithm == KDFAlgorithms.ARGON2ID:
            self.kdf_service = Argon2Service()
        elif self.algorithm == KDFAlgorithms.PBKDF2_SHA512:
            self.kdf_service = PBKDF2Service(self.iterations, 'sha512')
        else:  # Default to PBKDF2_SHA256
            self.kdf_service = PBKDF2Service(self.iterations, 'sha256')
        
        # Validate master salt if provided
        if self.master_salt and len(self.master_salt) < 32:
            raise ValueError(ErrorMessages.INVALID_MASTER_SALT)
    
    def create_user_wallet(self, email: str, password: str, 
                          user_salt: str = None) -> Dict[str, str]:
        """
        Create a new wallet for an email user (password-based)
        
        Args:
            email: User's email address
            password: User's password
            user_salt: Optional custom salt (generated if not provided)
        
        Returns:
            Dict containing wallet_address, encrypted_private_key, salt
            
        Raises:
            ValueError: If key derivation fails
        """
        try:
            # Generate unique salt for this user if not provided
            if not user_salt:
                user_salt = os.urandom(32).hex()
            
            # Derive private key
            private_key = self.derive_private_key(email, password, user_salt)
            
            # Generate wallet address
            account = Account.from_key(private_key)
            wallet_address = account.address
            
            # Clear private key from memory immediately
            private_key = '0' * len(private_key)
            del private_key
            
            return {
                'wallet_address': wallet_address,
                'salt': user_salt,
                'public_key': account.key.hex(),
                'algorithm': self.algorithm,
                'iterations': self.iterations,
                'auth_method': 'password',
                'deterministic': False
            }
            
        except Exception as e:
            logger.error(f"Wallet creation failed: {e}")
            raise ValueError(f"Failed to create wallet: {str(e)}")
    
    def derive_private_key(self, email: str, password: str, salt: str) -> str:
        """
        Derive private key from user credentials
        
        Args:
            email: User's email address
            password: User's password
            salt: User-specific salt
        
        Returns:
            32-byte private key as hex string
        """
        return self.kdf_service.derive_key(
            email, 
            password, 
            salt, 
            master_salt=self.master_salt
        )
    
    def verify_password(self, email: str, password: str, 
                       stored_salt: str, stored_address: str) -> bool:
        """
        Verify if the provided password generates the correct wallet address
        
        Args:
            email: User's email address
            password: Password to verify
            stored_salt: Salt stored in database
            stored_address: Wallet address stored in database
        
        Returns:
            True if password is correct, False otherwise
        """
        try:
            # Derive private key with provided credentials
            private_key = self.derive_private_key(email, password, stored_salt)
            
            # Generate address
            account = Account.from_key(private_key)
            derived_address = account.address
            
            # Clear private key from memory
            private_key = '0' * len(private_key)
            del private_key
            
            # Compare addresses (case-insensitive)
            return derived_address.lower() == stored_address.lower()
            
        except Exception as e:
            logger.error(f"Password verification failed: {e}")
            return False
    
    def get_wallet_address(self, email: str, password: str, salt: str) -> str:
        """
        Get wallet address for given credentials without storing private key
        
        Args:
            email: User's email address
            password: User's password
            salt: User-specific salt
        
        Returns:
            Wallet address (0x...)
        """
        try:
            private_key = self.derive_private_key(email, password, salt)
            account = Account.from_key(private_key)
            address = account.address
            
            # Clear private key from memory
            private_key = '0' * len(private_key)
            del private_key
            
            return address
            
        except Exception as e:
            logger.error(f"Failed to get wallet address: {e}")
            raise ValueError(f"Failed to get wallet address: {str(e)}")


class KeyEncryptionService:
    """
    Service for securely encrypting and decrypting private keys
    
    This service provides AES-256-GCM encryption for private keys
    and can be extended to use HSM/KMS in production.
    """
    
    def __init__(self, encryption_key: str = None):
        """
        Initialize encryption service
        
        Args:
            encryption_key: 256-bit encryption key in hex format (defaults to settings)
        """
        if encryption_key is None:
            # Try to get from settings
            config = get_kdf_config()
            encryption_key = config['encryption_key']
        
        self.encryption_key = self._get_or_create_key(encryption_key)
    
    def encrypt_private_key(self, private_key: str) -> Dict[str, str]:
        """
        Encrypt private key using AES-256-GCM
        
        Args:
            private_key: Private key to encrypt (hex string)
        
        Returns:
            Dict with encrypted_key, nonce, and tag
        """
        try:
            # Generate random nonce
            nonce = os.urandom(12)  # 96 bits for GCM
            
            # Import cryptography library
            try:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.backends import default_backend
            except ImportError:
                raise ImportError("cryptography library required for encryption")
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Encrypt the private key
            ciphertext = encryptor.update(private_key.encode()) + encryptor.finalize()
            
            return {
                'encrypted_key': ciphertext.hex(),
                'nonce': nonce.hex(),
                'tag': encryptor.tag.hex()
            }
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise ValueError(ErrorMessages.ENCRYPTION_FAILED)
    
    def decrypt_private_key(self, encrypted_data: Dict[str, str]) -> str:
        """
        Decrypt private key
        
        Args:
            encrypted_data: Dict with encrypted_key, nonce, and tag
        
        Returns:
            Decrypted private key
        """
        try:
            # Import cryptography library
            try:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.backends import default_backend
            except ImportError:
                raise ImportError("cryptography library required for decryption")
            
            # Decode from hex
            ciphertext = bytes.fromhex(encrypted_data['encrypted_key'])
            nonce = bytes.fromhex(encrypted_data['nonce'])
            tag = bytes.fromhex(encrypted_data['tag'])
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt
            private_key = decryptor.update(ciphertext) + decryptor.finalize()
            
            return private_key.decode()
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError(ErrorMessages.DECRYPTION_FAILED)
    
    def _get_or_create_key(self, encryption_key: str = None) -> bytes:
        """
        Get or create master encryption key
        
        Args:
            encryption_key: Optional encryption key in hex format
        
        Returns:
            Encryption key as bytes
        """
        if encryption_key:
            # Use provided key
            if encryption_key.startswith('0x'):
                encryption_key = encryption_key[2:]
            
            if len(encryption_key) != 64:  # 32 bytes = 64 hex chars
                raise ValueError(ErrorMessages.INVALID_ENCRYPTION_KEY)
            
            return bytes.fromhex(encryption_key)
        
        # Try to get from environment
        env_key = os.environ.get('MASTER_ENCRYPTION_KEY')
        if env_key:
            if env_key.startswith('0x'):
                env_key = env_key[2:]
            
            if len(env_key) != 64:
                raise ValueError(ErrorMessages.INVALID_ENCRYPTION_KEY)
            
            return bytes.fromhex(env_key)
        
        # Generate new key (first time setup)
        key = os.urandom(32)  # 256 bits
        
        logger.warning(
            "Generated new master encryption key. "
            "Set this as MASTER_ENCRYPTION_KEY environment variable "
            "or in BLOCK_AUTH_SETTINGS for production use."
        )
        
        return key


class KDFManager:
    """
    Main KDF Manager with dual encryption for platform access + user control
    
    This manager creates wallets that can be decrypted by:
    1. User password (for user operations)
    2. Platform key (for platform operations/recovery)
    
    It also supports multiple wallets per user with different salts.
    """
    
    def __init__(self, 
                 algorithm: str = None,
                 security_level: str = None,
                 master_salt: str = None,
                 encryption_key: str = None,
                 platform_master_salt: str = None):
        """
        Initialize KDF manager
        
        Args:
            algorithm: KDF algorithm to use
            security_level: Security preset
            master_salt: Platform master salt for KDF
            encryption_key: Master encryption key for platform decryption
            platform_master_salt: Platform master salt for passwordless wallets
        """
        # Initialize password-based KDF service
        self.password_kdf_service = KeyDerivationService(
            algorithm=algorithm,
            security_level=security_level,
            master_salt=master_salt
        )
        
        # Initialize platform encryption service
        self.platform_encryption_service = KeyEncryptionService(encryption_key)
        
        # Store platform master salt for passwordless wallets
        config = get_kdf_config()
        self.platform_master_salt = platform_master_salt or config.get('platform_master_salt', '')
        
        if not self.platform_master_salt:
            logger.warning("Platform master salt not set. Passwordless wallets will not work.")
    
    def create_wallet(self, email: str, password: str = None, 
                     wallet_name: str = None, 
                     custom_salt: str = None,
                     auth_method: str = 'auto') -> Dict[str, str]:
        """
        Create wallet with dual encryption (user password + platform key)
        
        Args:
            email: User's email address
            password: User's password (required for password-based)
            wallet_name: Optional name for the wallet (for multiple wallets)
            custom_salt: Optional custom salt (generated if not provided)
            auth_method: 'auto', 'password', or 'passwordless'
        
        Returns:
            Dict containing complete wallet data with dual encryption
        """
        # Auto-detect method if not specified
        if auth_method == 'auto':
            auth_method = 'password' if password else 'passwordless'
        
        if auth_method == 'password':
            if not password:
                raise ValueError("Password required for password-based authentication")
            return self._create_password_wallet(email, password, wallet_name, custom_salt)
        
        elif auth_method == 'passwordless':
            return self._create_passwordless_wallet(email, wallet_name, custom_salt)
        
        else:
            raise ValueError(f"Invalid authentication method: {auth_method}")
    
    def _create_password_wallet(self, email: str, password: str, 
                              wallet_name: str = None, custom_salt: str = None) -> Dict[str, str]:
        """Create password-based wallet with dual encryption"""
        
        # Generate or use custom salt
        if custom_salt:
            user_salt = custom_salt
        else:
            user_salt = self._generate_wallet_salt(email, wallet_name)
        
        # Derive private key using KDF
        private_key = self.password_kdf_service.derive_private_key(
            email, password, user_salt
        )
        
        # Generate wallet address
        account = Account.from_key(private_key)
        wallet_address = account.address
        
        # Encrypt with user password (primary encryption)
        user_encrypted = self._encrypt_with_user_key(
            private_key, email, password, user_salt
        )
        
        # Encrypt with platform key (backup encryption)
        platform_encrypted = self.platform_encryption_service.encrypt_private_key(
            private_key
        )
        
        # Clear private key from memory immediately
        private_key = '0' * len(private_key)
        del private_key
        
        # Generate wallet ID for multiple wallet support
        wallet_id = self._generate_wallet_id(email, user_salt)
        
        return {
            'wallet_id': wallet_id,
            'wallet_address': wallet_address,
            'wallet_name': wallet_name or 'default',
            'user_salt': user_salt,
            'user_encrypted_key': user_encrypted,
            'platform_encrypted_key': platform_encrypted,
            'public_key': account.key.hex(),
            'algorithm': self.password_kdf_service.algorithm,
            'iterations': self.password_kdf_service.iterations,
            'encryption_type': 'dual',
            'auth_method': 'password',
            'deterministic': True,  # Same input = same output
            'created_at': datetime.now().isoformat(),
            'wallet_version': '2.0'
        }
    
    def _create_passwordless_wallet(self, email: str, wallet_name: str = None, 
                                  custom_salt: str = None) -> Dict[str, str]:
        """Create passwordless wallet (deterministic)"""
        
        # Generate deterministic salt from email
        if custom_salt:
            email_salt = custom_salt
        else:
            email_salt = self._generate_email_salt(email, wallet_name)
        
        # Derive private key from email + platform salt
        private_key = self._derive_private_key(email, email_salt)
        
        # Generate wallet address
        account = Account.from_key(private_key)
        wallet_address = account.address
        
        # For passwordless, encrypt with platform key only
        platform_encrypted = self.platform_encryption_service.encrypt_private_key(
            private_key
        )
        
        # Clear private key from memory
        private_key = '0' * len(private_key)
        del private_key
        
        # Generate wallet ID
        wallet_id = self._generate_wallet_id(email, email_salt)
        
        return {
            'wallet_id': wallet_id,
            'wallet_address': wallet_address,
            'wallet_name': wallet_name or 'default',
            'user_salt': email_salt,
            'user_encrypted_key': '',  # No user encryption for passwordless
            'platform_encrypted_key': platform_encrypted,
            'public_key': account.key.hex(),
            'algorithm': 'sha256_deterministic',
            'iterations': 0,
            'encryption_type': 'platform_only',
            'auth_method': 'passwordless',
            'deterministic': True,
            'created_at': datetime.now().isoformat(),
            'wallet_version': '2.0'
        }
    
    def create_multiple_wallets(self, email: str, password: str, 
                               wallet_names: List[str]) -> List[Dict[str, str]]:
        """
        Create multiple wallets for a user with different salts
        
        Args:
            email: User's email address
            password: User's password
            wallet_names: List of wallet names to create
        
        Returns:
            List of wallet data dictionaries
        """
        wallets = []
        
        for wallet_name in wallet_names:
            try:
                wallet = self.create_wallet(
                    email=email,
                    password=password,
                    wallet_name=wallet_name
                )
                
                wallets.append(wallet)
                logger.info(f"Created wallet '{wallet_name}' for {email}")
                
            except Exception as e:
                logger.error(f"Failed to create wallet '{wallet_name}' for {email}: {e}")
                wallets.append({
                    'wallet_name': wallet_name,
                    'error': str(e),
                    'success': False
                })
        
        return wallets
    
    def decrypt_with_user_password(self, email: str, password: str, 
                                 user_encrypted_key: str, user_salt: str) -> str:
        """
        Decrypt private key using user password (for user operations)
        
        Args:
            email: User's email address
            password: User's password
            user_encrypted_key: User-encrypted private key
            user_salt: Salt used for this wallet
        
        Returns:
            Decrypted private key
        """
        try:
            # Recreate user encryption key
            user_key = self._derive_user_encryption_key(email, password, user_salt)
            
            # Decrypt private key
            private_key = self._decrypt_with_user_key(user_encrypted_key, user_key)
            
            # Clear user key from memory
            user_key = b'\x00' * len(user_key)
            del user_key
            
            return private_key
            
        except Exception as e:
            logger.error(f"User password decryption failed: {e}")
            raise ValueError(f"Failed to decrypt with user password: {str(e)}")
    
    def decrypt_with_platform_key(self, platform_encrypted_key: str) -> str:
        """
        Decrypt private key using platform key (for platform operations)
        
        Args:
            platform_encrypted_key: Platform-encrypted private key
        
        Returns:
            Decrypted private key
        """
        try:
            # Platform can decrypt any wallet without user password
            private_key = self.platform_encryption_service.decrypt_private_key(
                json.loads(platform_encrypted_key)
            )
            
            return private_key
            
        except Exception as e:
            logger.error(f"Platform key decryption failed: {e}")
            raise ValueError(f"Failed to decrypt with platform key: {str(e)}")
    
    def verify_wallet_ownership(self, email: str, password: str, 
                               wallet_address: str, user_salt: str) -> bool:
        """
        Verify that user owns the wallet (for authentication)
        
        Args:
            email: User's email address
            password: User's password
            wallet_address: Wallet address to verify
            user_salt: Salt used for this wallet
        
        Returns:
            True if user owns the wallet, False otherwise
        """
        try:
            # Derive private key
            private_key = self.password_kdf_service.derive_private_key(
                email, password, user_salt
            )
            
            # Generate address
            account = Account.from_key(private_key)
            derived_address = account.address
            
            # Clear private key from memory
            private_key = '0' * len(private_key)
            del private_key
            
            # Compare addresses
            return derived_address.lower() == wallet_address.lower()
            
        except Exception as e:
            logger.error(f"Wallet ownership verification failed: {e}")
            return False
    
    def get_wallet_address(self, email: str, password: str, user_salt: str) -> str:
        """
        Get wallet address for given credentials
        
        Args:
            email: User's email address
            password: User's password
            user_salt: Salt used for this wallet
        
        Returns:
            Wallet address
        """
        try:
            private_key = self.password_kdf_service.derive_private_key(
                email, password, user_salt
            )
            account = Account.from_key(private_key)
            address = account.address
            
            # Clear private key from memory
            private_key = '0' * len(private_key)
            del private_key
            
            return address
            
        except Exception as e:
            logger.error(f"Failed to get wallet address: {e}")
            raise ValueError(f"Failed to get wallet address: {str(e)}")
    
    def _generate_wallet_salt(self, email: str, wallet_name: str = None) -> str:
        """Generate unique salt for wallet"""
        if wallet_name:
            # Include wallet name in salt generation for uniqueness
            salt_input = f"{email}:{wallet_name}:{self.password_kdf_service.master_salt}"
        else:
            # Default salt generation
            salt_input = f"{email}:{self.password_kdf_service.master_salt}"
        
        # Generate deterministic but unique salt
        salt_hash = hashlib.sha256(salt_input.encode()).hexdigest()
        return salt_hash[:32]  # 32 characters for salt
    
    def _generate_email_salt(self, email: str, wallet_name: str = None) -> str:
        """Generate deterministic salt from email"""
        email = email.lower().strip()
        if wallet_name:
            salt_input = f"{email}:{wallet_name}:{self.platform_master_salt}"
        else:
            salt_input = f"{email}:{self.platform_master_salt}"
        return hashlib.sha256(salt_input.encode()).hexdigest()
    
    def _generate_wallet_id(self, email: str, user_salt: str) -> str:
        """Generate unique wallet ID"""
        wallet_input = f"{email}:{user_salt}:{time.time()}"
        wallet_hash = hashlib.sha256(wallet_input.encode()).hexdigest()
        return wallet_hash[:16]  # 16 characters for wallet ID
    
    def _derive_user_encryption_key(self, email: str, password: str, user_salt: str) -> bytes:
        """Derive user-specific encryption key"""
        key_input = f"{email}:{password}:{user_salt}:user_encryption"
        key_material = hashlib.sha256(key_input.encode()).digest()
        return key_material
    
    def _encrypt_with_user_key(self, private_key: str, email: str, 
                              password: str, user_salt: str) -> str:
        """Encrypt private key with user-derived key"""
        user_key = self._derive_user_encryption_key(email, password, user_salt)
        
        # Simple XOR encryption for demonstration
        # In production, use proper encryption like AES
        private_key_bytes = private_key.encode()
        encrypted_bytes = bytes(a ^ b for a, b in zip(private_key_bytes, user_key))
        
        return encrypted_bytes.hex()
    
    def _decrypt_with_user_key(self, encrypted_key: str, user_key: bytes) -> str:
        """Decrypt private key with user key"""
        encrypted_bytes = bytes.fromhex(encrypted_key)
        
        # XOR decryption (same as encryption)
        decrypted_bytes = bytes(a ^ b for a, b in zip(encrypted_bytes, user_key))
        
        return decrypted_bytes.decode()
    
    def _derive_private_key(self, email: str, salt: str) -> str:
        """Derive private key from email + platform salt"""
        email = email.lower().strip()
        kdf_input = f"{email}:{salt}:{self.platform_master_salt}"
        
        # Use SHA-256 for deterministic generation
        key_material = hashlib.sha256(kdf_input.encode()).digest()
        return '0x' + key_material.hex()


class MultipleWalletService:
    """
    High-level service for managing multiple wallets per user
    
    This service provides convenient methods for:
    - Creating multiple wallets
    - Managing wallet collections
    - Batch operations
    - Wallet recovery
    """
    
    def __init__(self):
        """Initialize multiple wallet service"""
        self.kdf_manager = KDFManager()
    
    def create_user_wallet_collection(self, email: str, password: str, 
                                    wallet_configs: List[Dict]) -> Dict[str, str]:
        """
        Create a collection of wallets for a user
        
        Args:
            email: User's email address
            password: User's password
            wallet_configs: List of wallet configurations
        
        Returns:
            Dict containing collection info and wallet list
        """
        try:
            collection_id = str(uuid.uuid4())
            wallets = []
            
            for config in wallet_configs:
                wallet_name = config.get('name', f'wallet_{len(wallets) + 1}')
                custom_salt = config.get('custom_salt')
                
                wallet = self.kdf_manager.create_wallet(
                    email=email,
                    password=password,
                    wallet_name=wallet_name,
                    custom_salt=custom_salt
                )
                
                wallets.append(wallet)
            
            return {
                'collection_id': collection_id,
                'user_email': email,
                'wallet_count': len(wallets),
                'wallets': wallets,
                'created_at': datetime.now().isoformat(),
                'collection_type': 'multiple_wallets'
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'success': False
            }
    
    def get_user_wallet_summary(self, email: str, password: str, 
                               wallet_data_list: List[Dict]) -> Dict[str, str]:
        """
        Get summary of all user wallets
        
        Args:
            email: User's email address
            password: User's password
            wallet_data_list: List of wallet data from database
        
        Returns:
            Dict containing wallet summary
        """
        try:
            wallet_summaries = []
            
            for wallet_data in wallet_data_list:
                if wallet_data['auth_method'] != 'password':
                    continue
                
                # Verify ownership
                if self.kdf_manager.verify_wallet_ownership(
                    email, password,
                    wallet_data['wallet_address'],
                    wallet_data['user_salt']
                ):
                    wallet_summaries.append({
                        'wallet_id': wallet_data.get('wallet_id'),
                        'wallet_name': wallet_data.get('wallet_name', 'default'),
                        'wallet_address': wallet_data['wallet_address'],
                        'created_at': wallet_data.get('created_at'),
                        'verified': True
                    })
                else:
                    wallet_summaries.append({
                        'wallet_id': wallet_data.get('wallet_id'),
                        'wallet_name': wallet_data.get('wallet_name', 'default'),
                        'wallet_address': wallet_data['wallet_address'],
                        'verified': False,
                        'error': 'Ownership verification failed'
                    })
            
            return {
                'user_email': email,
                'total_wallets': len(wallet_summaries),
                'verified_wallets': len([w for w in wallet_summaries if w['verified']]),
                'wallets': wallet_summaries,
                'summary_generated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'success': False
            }
    
    def batch_sign_transactions(self, email: str, password: str,
                               wallet_data_list: List[Dict],
                               transaction_data: Dict) -> List[Dict[str, str]]:
        """
        Sign the same transaction with multiple user wallets
        
        Args:
            email: User's email address
            password: User's password
            wallet_data_list: List of wallet data
            transaction_data: Transaction to sign
        
        Returns:
            List of signed transactions
        """
        signed_transactions = []
        
        for wallet_data in wallet_data_list:
            try:
                if wallet_data['auth_method'] != 'password':
                    continue
                
                # Decrypt private key
                private_key = self.kdf_manager.decrypt_with_user_password(
                    email, password,
                    wallet_data['user_encrypted_key'],
                    wallet_data['user_salt']
                )
                
                # Sign transaction
                account = Account.from_key(private_key)
                signed_tx = account.sign_transaction(transaction_data)
                
                signed_transactions.append({
                    'wallet_id': wallet_data.get('wallet_id'),
                    'wallet_name': wallet_data.get('wallet_name', 'default'),
                    'wallet_address': wallet_data['wallet_address'],
                    'signed_transaction': signed_tx.rawTransaction.hex(),
                    'signature_success': True
                })
                
                # Clear private key from memory
                private_key = '0' * len(private_key)
                del private_key
                
            except Exception as e:
                signed_transactions.append({
                    'wallet_id': wallet_data.get('wallet_id'),
                    'wallet_name': wallet_data.get('wallet_name', 'default'),
                    'wallet_address': wallet_data['wallet_address'],
                    'signature_success': False,
                    'error': str(e)
                })
        
        return signed_transactions


# Convenience functions for easy access
def get_kdf_manager():
    """Get the main KDF manager (RECOMMENDED)"""
    return KDFManager()


def get_multiple_wallet_service():
    """Get the multiple wallet service"""
    return MultipleWalletService()
