"""
KDF Configuration Examples

This file shows how to configure KDF functionality in your Django project.
Copy the relevant configuration to your project's settings.py file.
"""

# Example 1: Basic KDF Configuration
# Add this to your Django settings.py

BLOCK_AUTH_SETTINGS = {
    # Enable KDF functionality
    'KDF_ENABLED': True,
    
    # KDF Algorithm (choose one)
    'KDF_ALGORITHM': 'pbkdf2_sha256',  # Options: pbkdf2_sha256, pbkdf2_sha512, argon2id
    
    # Security settings
    'KDF_ITERATIONS': 100000,  # For PBKDF2 (higher = more secure, slower)
    'KDF_SECURITY_LEVEL': 'MEDIUM',  # Options: LOW, MEDIUM, HIGH, CRITICAL
    
    # Platform security (REQUIRED for production)
    'KDF_MASTER_SALT': 'your-platform-master-salt-32-characters-minimum',
    'MASTER_ENCRYPTION_KEY': '0x' + 'your-256-bit-encryption-key-in-hex',
    'PLATFORM_MASTER_SALT': 'your-platform-master-salt-32-characters-minimum',
}

# Example 2: High Security Configuration
# For financial applications or high-security requirements

BLOCK_AUTH_SETTINGS = {
    'KDF_ENABLED': True,
    'KDF_ALGORITHM': 'argon2id',  # Most secure algorithm
    'KDF_SECURITY_LEVEL': 'CRITICAL',  # Highest security preset
    'KDF_MASTER_SALT': 'your-very-long-platform-master-salt-64-characters',
    'MASTER_ENCRYPTION_KEY': '0x' + 'your-256-bit-encryption-key-in-hex',
    'PLATFORM_MASTER_SALT': 'your-very-long-platform-master-salt-64-characters',
}

# Example 3: Development Configuration
# For development/testing environments

BLOCK_AUTH_SETTINGS = {
    'KDF_ENABLED': True,
    'KDF_ALGORITHM': 'pbkdf2_sha256',
    'KDF_SECURITY_LEVEL': 'LOW',  # Faster for development
    'KDF_ITERATIONS': 10000,  # Lower iterations for speed
    'KDF_MASTER_SALT': 'dev-platform-salt-32-chars-minimum',
    'MASTER_ENCRYPTION_KEY': '0x' + 'dev-256-bit-key-in-hex',
    'PLATFORM_MASTER_SALT': 'dev-platform-master-salt-32-chars-minimum',
}

# Example 4: Environment Variable Configuration
# Use environment variables for sensitive configuration

import os

BLOCK_AUTH_SETTINGS = {
    'KDF_ENABLED': True,
    'KDF_ALGORITHM': 'pbkdf2_sha256',
    'KDF_SECURITY_LEVEL': 'MEDIUM',
    'KDF_MASTER_SALT': os.environ.get('KDF_MASTER_SALT', ''),
    'MASTER_ENCRYPTION_KEY': os.environ.get('MASTER_ENCRYPTION_KEY', ''),
    'PLATFORM_MASTER_SALT': os.environ.get('PLATFORM_MASTER_SALT', ''),
}

# Example 5: Complete Configuration with All Options
# Shows all available KDF configuration options

BLOCK_AUTH_SETTINGS = {
    # Master switch - must be True to use KDF
    'KDF_ENABLED': True,
    
    # Algorithm selection
    'KDF_ALGORITHM': 'pbkdf2_sha256',  # pbkdf2_sha256, pbkdf2_sha512, argon2id
    
    # Security presets (overrides individual settings)
    'KDF_SECURITY_LEVEL': 'MEDIUM',  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Individual security settings (used if no preset)
    'KDF_ITERATIONS': 100000,  # For PBKDF2 algorithms
    
    # Platform security (REQUIRED)
    'KDF_MASTER_SALT': 'your-platform-master-salt-32-characters-minimum',
    'MASTER_ENCRYPTION_KEY': '0x' + 'your-256-bit-encryption-key-in-hex',
    'PLATFORM_MASTER_SALT': 'your-platform-master-salt-32-characters-minimum',
    
    # Optional: Custom Argon2 parameters (if using argon2id)
    'KDF_ARGON2_TIME_COST': 3,        # Time cost (higher = more secure, slower)
    'KDF_ARGON2_MEMORY_COST': 65536,  # Memory cost in KB (64MB)
    'KDF_ARGON2_PARALLELISM': 4,      # Number of parallel threads
}

# Example 6: Non-Django Configuration
# For non-Django projects, use environment variables

# Set these environment variables in your system:
# export KDF_ENABLED=true
# export KDF_ALGORITHM=pbkdf2_sha256
# export KDF_ITERATIONS=100000
# export KDF_MASTER_SALT=your-platform-salt-32-chars
# export MASTER_ENCRYPTION_KEY=0xyour-256-bit-key
# export PLATFORM_MASTER_SALT=your-platform-master-salt-32-chars

# Then in your Python code:
# from blockauth.kdf import get_kdf_manager
# kdf_manager = get_kdf_manager()  # Will read from environment variables

# Example 7: Basic Usage Examples
# Show how to use the KDF system

"""
# In your Django views or services

from blockauth.kdf import get_kdf_manager

def create_wallet_for_user(request):
    '''Create wallet with dual encryption'''
    
    kdf_manager = get_kdf_manager()
    email = request.POST.get('email')
    password = request.POST.get('password')
    wallet_name = request.POST.get('wallet_name', 'default')
    
    # Create wallet with dual encryption
    wallet_data = kdf_manager.create_wallet(
        email=email,
        password=password,
        wallet_name=wallet_name
    )
    
    # Store in database
    from your_app.models import UserWallet
    UserWallet.objects.create(
        user=request.user,
        wallet_id=wallet_data['wallet_id'],
        wallet_name=wallet_data['wallet_name'],
        wallet_address=wallet_data['wallet_address'],
        user_salt=wallet_data['user_salt'],
        user_encrypted_key=wallet_data['user_encrypted_key'],
        platform_encrypted_key=wallet_data['platform_encrypted_key'],
        algorithm=wallet_data['algorithm'],
        iterations=wallet_data['iterations'],
        encryption_type=wallet_data['encryption_type'],
        auth_method=wallet_data['auth_method'],
        deterministic=wallet_data['deterministic']
    )
    
    return {
        'success': True,
        'wallet_address': wallet_data['wallet_address']
    }

def create_multiple_wallets(request):
    '''Create multiple wallets for a user'''
    
    kdf_manager = get_kdf_manager()
    email = request.POST.get('email')
    password = request.POST.get('password')
    
    # Create multiple wallets
    wallet_names = ['primary', 'savings', 'business', 'trading']
    wallets = kdf_manager.create_multiple_wallets(
        email=email,
        password=password,
        wallet_names=wallet_names
    )
    
    # Store all wallets
    for wallet_data in wallets:
        if 'error' not in wallet_data:
            UserWallet.objects.create(
                user=request.user,
                wallet_id=wallet_data['wallet_id'],
                wallet_name=wallet_data['wallet_name'],
                wallet_address=wallet_data['wallet_address'],
                user_salt=wallet_data['user_salt'],
                user_encrypted_key=wallet_data['user_encrypted_key'],
                platform_encrypted_key=wallet_data['platform_encrypted_key'],
                algorithm=wallet_data['algorithm'],
                iterations=wallet_data['iterations'],
                encryption_type=wallet_data['encryption_type'],
                auth_method=wallet_data['auth_method'],
                deterministic=wallet_data['deterministic']
            )
    
    return {
        'success': True,
        'total_wallets': len([w for w in wallets if 'error' not in w])
    }

def sign_transaction(request):
    '''User signs transaction with their wallet'''
    
    kdf_manager = get_kdf_manager()
    email = request.POST.get('email')
    password = request.POST.get('password')
    wallet_id = request.POST.get('wallet_id')
    
    # Get wallet from database
    wallet = UserWallet.objects.get(wallet_id=wallet_id)
    
    # User decrypts with their password
    private_key = kdf_manager.decrypt_with_user_password(
        email=email,
        password=password,
        user_encrypted_key=wallet.user_encrypted_key,
        user_salt=wallet.user_salt
    )
    
    # Sign transaction
    from web3 import Web3
    from eth_account import Account
    
    account = Account.from_key(private_key)
    transaction_data = {
        'to': request.POST.get('to_address'),
        'value': int(request.POST.get('amount', 0)),
        'gas': 200000,
        'gasPrice': web3.eth.gas_price,
        'nonce': web3.eth.get_transaction_count(wallet.wallet_address),
        'chainId': web3.eth.chain_id
    }
    
    signed_tx = account.sign_transaction(transaction_data)
    
    # Clear private key from memory
    private_key = '0' * len(private_key)
    del private_key
    
    return {
        'success': True,
        'signed_transaction': signed_tx.rawTransaction.hex()
    }

def platform_recover_wallet(request):
    '''Platform recovers user wallet (for support/recovery)'''
    
    kdf_manager = get_kdf_manager()
    wallet_id = request.POST.get('wallet_id')
    
    # Get wallet from database
    wallet = UserWallet.objects.get(wallet_id=wallet_id)
    
    # Platform decrypts without user password
    private_key = kdf_manager.decrypt_with_platform_key(
        wallet.platform_encrypted_key
    )
    
    # Platform can now:
    # - Check wallet balance
    # - Perform recovery operations
    # - Support user requests
    # - Emergency operations
    
    return {
        'success': True,
        'wallet_address': wallet.wallet_address,
        'recovery_success': True
    }
"""

# Example 8: Database Model for Wallets
# How to store the wallet data

"""
# Django Model Example for KDF Wallets

from django.db import models
from django.contrib.auth.models import User

class UserWallet(models.Model):
    # Basic wallet info
    wallet_id = models.CharField(max_length=32, unique=True, primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    wallet_name = models.CharField(max_length=100, default='default')
    wallet_address = models.CharField(max_length=42, unique=True)  # 0x... format
    
    # Encryption data
    user_salt = models.CharField(max_length=64)  # Salt for this wallet
    user_encrypted_key = models.TextField()      # Encrypted with user password
    platform_encrypted_key = models.TextField()  # Encrypted with platform key
    
    # Metadata
    algorithm = models.CharField(max_length=50)
    iterations = models.IntegerField()
    encryption_type = models.CharField(max_length=20, default='dual')
    auth_method = models.CharField(max_length=20, default='password')
    deterministic = models.BooleanField(default=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_wallets'
        unique_together = ['user', 'wallet_name']
    
    def __str__(self):
        return f"{self.user.email} - {self.wallet_name} ({self.wallet_address})"
"""

# Example 9: Security Best Practices
# Production deployment guidelines

"""
# Security Checklist:

1. **Master Keys**:
   - Use cryptographically secure random generation
   - Store in HSM/KMS in production
   - Rotate keys regularly
   - Never log or expose keys

2. **Salt Management**:
   - Ensure unique salts per wallet
   - Use sufficient entropy (32+ characters)
   - Store salts securely

3. **Access Control**:
   - Limit platform key access to authorized personnel
   - Implement audit logging for all key operations
   - Use role-based access control

4. **Monitoring**:
   - Monitor for unusual decryption patterns
   - Alert on multiple failed attempts
   - Log all wallet creation/access

5. **Recovery Procedures**:
   - Document recovery processes
   - Require multiple approvals for recovery
   - Maintain audit trail of all recoveries

# Example implementation:
import os
import secrets

# Generate secure keys
def generate_secure_keys():
    # Generate 256-bit encryption key
    encryption_key = '0x' + secrets.token_hex(32)
    
    # Generate 256-bit master salt
    master_salt = secrets.token_hex(32)
    
    # Generate 256-bit platform master salt
    platform_master_salt = secrets.token_hex(32)
    
    return {
        'MASTER_ENCRYPTION_KEY': encryption_key,
        'KDF_MASTER_SALT': master_salt,
        'PLATFORM_MASTER_SALT': platform_master_salt
    }

# Store securely (use environment variables or secure storage)
keys = generate_secure_keys()
for key, value in keys.items():
    os.environ[key] = value
"""

if __name__ == '__main__':
    print("KDF Configuration Examples")
    print("=========================")
    print("This file contains examples of how to configure KDF functionality.")
    print("Copy the relevant examples to your project's settings.py file.")
    print("\nKey Features:")
    print("- ✅ Dual encryption (user password + platform key)")
    print("- ✅ Platform can recover any user wallet")
    print("- ✅ Users maintain control over their wallets")
    print("- ✅ Multiple wallets per user with different salts")
    print("- ✅ Framework-agnostic design")
    print("\nFor more examples, see the usage_examples.py file.")
