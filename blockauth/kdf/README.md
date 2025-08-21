# Key Derivation Function (KDF) Module

The KDF module for BlockAuth provides secure key derivation from email/password combinations, enabling Web2 users to have blockchain accounts without managing crypto keys.

## 🚀 Features

- **Framework Agnostic**: Works with Django, FastAPI, Flask, or any Python project
- **Dual Encryption**: User password + Platform key for maximum security
- **Multiple Algorithms**: Support for PBKDF2-SHA256, PBKDF2-SHA512, and Argon2id
- **Security Presets**: Pre-configured security levels (LOW, MEDIUM, HIGH, CRITICAL)
- **Optional Module**: Only loads when explicitly enabled
- **Multiple Wallets**: Support for multiple wallets per user with different salts
- **Platform Recovery**: Platform can recover any user wallet when needed
- **Memory Safe**: Automatically clears sensitive data from memory

## 🔐 Dual Encryption Architecture

### **How It Works:**
```
User Password + Email + Salt → KDF → Private Key → Wallet Address
                                    ↓
                            ┌─────────────┬─────────────┐
                            │             │             │
                      User Key      Platform Key    Wallet Address
                            │             │
                            ↓             ↓
                      User Encrypted  Platform Encrypted
                      Private Key     Private Key
                            │             │
                            └─────────────┘
                                   ↓
                            Store in Database
```

### **Benefits:**
1. **User Control**: Users decrypt with their password (normal operations)
2. **Platform Access**: Platform can decrypt without password (recovery/support)
3. **Security**: Both encryption methods must be compromised to access wallet
4. **Recovery**: Platform can help recover lost wallets
5. **Compliance**: Meets regulatory requirements for user data control

## 📋 Requirements

- Python 3.8+
- `web3` library (for blockchain functionality)
- `eth-account` library (for wallet operations)
- `cryptography` library (for encryption)

## ⚙️ Installation

The KDF module is included with BlockAuth. No additional installation is required.

## 🔧 Configuration

### Enable KDF in Your Project

Add the following to your Django `settings.py`:

```python
BLOCK_AUTH_SETTINGS = {
    # Master switch - must be True to use KDF
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
```

### Environment Variables (Alternative)

For non-Django projects or additional security:

```bash
export KDF_ENABLED=true
export KDF_ALGORITHM=pbkdf2_sha256
export KDF_ITERATIONS=100000
export KDF_MASTER_SALT=your-platform-salt-32-chars
export MASTER_ENCRYPTION_KEY=0xyour-256-bit-key
export PLATFORM_MASTER_SALT=your-platform-master-salt-32-chars
```

### Security Level Presets

| Level | Algorithm | Iterations | Use Case |
|-------|-----------|------------|----------|
| LOW | PBKDF2-SHA256 | 10,000 | Development/Testing |
| MEDIUM | PBKDF2-SHA256 | 100,000 | Standard Production |
| HIGH | Argon2id | 500,000 | High Security Apps |
| CRITICAL | Argon2id | 1,000,000 | Financial/Critical Systems |

## 🎯 Basic Usage

### Check if KDF is Enabled

```python
from blockauth.kdf import is_enabled

if is_enabled():
    print("KDF is available")
else:
    print("KDF is not enabled")
```

### Create Wallet with Dual Encryption

```python
from blockauth.kdf import get_kdf_manager

# Get KDF manager
kdf_manager = get_kdf_manager()

# Create wallet with dual encryption
wallet_data = kdf_manager.create_wallet(
    email="user@example.com",
    password="SecurePassword123",
    wallet_name="primary"
)

print(f"Wallet address: {wallet_data['wallet_address']}")
print(f"User encrypted key: {wallet_data['user_encrypted_key'][:50]}...")
print(f"Platform encrypted key: {wallet_data['platform_encrypted_key'][:50]}...")
```

### Create Multiple Wallets

```python
# Create multiple wallets for a user
wallet_names = ['primary', 'savings', 'business', 'trading']
wallets = kdf_manager.create_multiple_wallets(
    email="user@example.com",
    password="SecurePassword123",
    wallet_names=wallet_names
)

print(f"Created {len(wallets)} wallets")
for wallet in wallets:
    if 'error' not in wallet:
        print(f"  {wallet['wallet_name']}: {wallet['wallet_address']}")
```

### User Decryption (Normal Operations)

```python
# User decrypts with their password
private_key = kdf_manager.decrypt_with_user_password(
    email="user@example.com",
    password="SecurePassword123",
    user_encrypted_key=wallet_data['user_encrypted_key'],
    user_salt=wallet_data['user_salt']
)

print(f"Decrypted private key: {private_key[:20]}...")
```

### Platform Decryption (Recovery Operations)

```python
# Platform can decrypt without user password
private_key = kdf_manager.decrypt_with_platform_key(
    wallet_data['platform_encrypted_key']
)

print(f"Platform recovered private key: {private_key[:20]}...")
```

### Verify Wallet Ownership

```python
# Verify user owns the wallet
is_owner = kdf_manager.verify_wallet_ownership(
    email="user@example.com",
    password="SecurePassword123",
    wallet_address=wallet_data['wallet_address'],
    user_salt=wallet_data['user_salt']
)

if is_owner:
    print("User owns this wallet")
else:
    print("User does not own this wallet")
```

## 🏗️ Architecture

### Core Components

1. **KDFManager**: Main manager with dual encryption capabilities
2. **KeyDerivationService**: Core KDF functionality for password-based wallets
3. **PasswordlessKDFService**: Deterministic wallets for passwordless users
4. **KeyEncryptionService**: Handles encryption/decryption of private keys
5. **MultipleWalletService**: Support for multiple wallets per user

### Data Flow

#### Password-Based Flow
```
Email + Password + Salt → KDF Algorithm → Private Key → Wallet Address
                                    ↓
                            ┌─────────────┬─────────────┐
                            │             │             │
                      User Key      Platform Key    Wallet Address
                            │             │
                            ↓             ↓
                      User Encrypted  Platform Encrypted
                      Private Key     Private Key
                            │             │
                            └─────────────┘
                                   ↓
                            Store in Database
```

#### Passwordless Flow
```
Email + Platform Salt → Deterministic Hash → Private Key → Wallet Address
                                    ↓
                            Platform Encrypted Private Key
```

### Security Model

- **Dual Encryption**: User password + Platform key encrypt private key
- **User Control**: Users can decrypt with their password
- **Platform Access**: Platform can decrypt for recovery/support
- **Salt Management**: Unique salt per wallet for security
- **Deterministic**: Same input always produces same output
- **Memory Safety**: Sensitive data automatically cleared from memory

## 🔐 Security Considerations

### Required Security Measures

1. **Master Salt**: Must be at least 32 characters, unique to your platform
2. **Encryption Key**: 256-bit key for AES-256-GCM encryption
3. **Platform Master Salt**: Required for passwordless wallets
4. **Iteration Count**: Minimum 10,000 for PBKDF2, higher for production
5. **Secure Storage**: Store encrypted keys securely, never in plain text

### Best Practices

1. **Environment Variables**: Use environment variables for sensitive configuration
2. **Key Rotation**: Implement key rotation policies
3. **Audit Logging**: Log all key access operations for security monitoring
4. **Access Control**: Limit access to platform key functions
5. **Regular Updates**: Keep dependencies updated for security patches

### Production Checklist

- [ ] KDF_ENABLED set to True
- [ ] Strong master salt (32+ characters)
- [ ] Secure encryption key (256-bit)
- [ ] Platform master salt (32+ characters)
- [ ] Appropriate security level for your use case
- [ ] Environment variables for sensitive data
- [ ] Key rotation procedures in place
- [ ] Security monitoring and alerting

## 📚 Examples

See the following files for comprehensive examples:

- `config_example.py` - Configuration examples
- `usage_examples.py` - Usage examples for different frameworks
- `tests.py` - Unit tests and testing examples

## 🧪 Testing

### Run Unit Tests

```bash
# From the blockauth directory
python -m pytest blockauth/kdf/tests.py -v
```

### Test Dual Encryption

```python
# Mock Django settings for testing
from unittest.mock import patch

with patch('django.conf.settings') as mock_settings:
    mock_settings.BLOCK_AUTH_SETTINGS = {
        'KDF_ENABLED': True,
        'KDF_ALGORITHM': 'pbkdf2_sha256',
        'KDF_ITERATIONS': 1000,  # Low for testing
        'KDF_MASTER_SALT': 'test-salt-32-chars-minimum',
        'MASTER_ENCRYPTION_KEY': '0x' + 'a' * 64,
        'PLATFORM_MASTER_SALT': 'test-platform-salt-32-chars',
    }
    
    # Test dual encryption functionality
    from blockauth.kdf import get_kdf_manager
    kdf_manager = get_kdf_manager()
    
    # Create wallet
    wallet = kdf_manager.create_wallet(
        'test@example.com', 'TestPassword123', 'test_wallet'
    )
    
    # Test user decryption
    user_key = kdf_manager.decrypt_with_user_password(
        'test@example.com', 'TestPassword123',
        wallet['user_encrypted_key'], wallet['user_salt']
    )
    
    # Test platform decryption
    platform_key = kdf_manager.decrypt_with_platform_key(
        wallet['platform_encrypted_key']
    )
    
    # Both should be identical
    assert user_key == platform_key
    print(f"✅ Dual encryption test passed: {wallet['wallet_address']}")
```

## 🚨 Troubleshooting

### Common Issues

1. **KDF not enabled**: Check `KDF_ENABLED=True` in settings
2. **Missing dependencies**: Install `cryptography` library
3. **Invalid configuration**: Verify salt length and encryption key format
4. **Import errors**: Ensure BlockAuth is properly installed
5. **Platform salt missing**: Check `PLATFORM_MASTER_SALT` is set

### Error Messages

- `"KDF is not enabled"`: Set `KDF_ENABLED=True` in settings
- `"Master salt must be at least 32 characters"`: Increase salt length
- `"Invalid encryption key format"`: Use 64-character hex string
- `"Platform master salt required"`: Set `PLATFORM_MASTER_SALT`
- `"cryptography library required"`: Install cryptography package

## 📖 API Reference

### KDFManager (Main Class)

#### Methods

- `create_wallet(email, password, wallet_name=None, custom_salt=None, auth_method='auto')` → dict
- `create_multiple_wallets(email, password, wallet_names)` → list
- `decrypt_with_user_password(email, password, user_encrypted_key, user_salt)` → str
- `decrypt_with_platform_key(platform_encrypted_key)` → str
- `verify_wallet_ownership(email, password, wallet_address, user_salt)` → bool
- `get_wallet_address(email, password, user_salt)` → str

#### Properties

- `password_kdf_service`: Password-based KDF service
- `platform_encryption_service`: Platform encryption service

### MultipleWalletService

#### Methods

- `create_user_wallet_collection(email, password, wallet_configs)` → dict
- `get_user_wallet_summary(email, password, wallet_data_list)` → dict
- `batch_sign_transactions(email, password, wallet_data_list, transaction_data)` → list

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📄 License

This module is part of BlockAuth and follows the same license terms.

## 🆘 Support

For support and questions:

1. Check the examples and documentation
2. Review the test files for usage patterns
3. Open an issue on the BlockAuth repository
4. Check the BlockAuth documentation

---

**Note**: This is an optional module that must be explicitly enabled. It provides powerful functionality for bridging Web2 and Web3 authentication with dual encryption for maximum security and platform recovery capabilities.
