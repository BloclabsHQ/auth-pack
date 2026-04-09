# KDF System

The Key Derivation Function (KDF) system bridges Web2 and Web3 by generating blockchain wallets from email/password credentials. Users get blockchain accounts without managing private keys.

## How It Works

```
Email + Password --> KDF --> Private Key --> EOA --> Smart Contract Account
     |               |          |            |              |
  Web2 Auth    Key Derivation  Hidden    Internal     User's Wallet
```

The same email/password always generates the same private key (deterministic derivation). The key is then encrypted with dual keys (user password + platform key) for storage.

## Services

### PBKDF2Service

Direct key derivation using PBKDF2-SHA256:

```python
from blockauth.kdf.services import PBKDF2Service

service = PBKDF2Service(iterations=100000)
private_key = service.derive_key(email, password, salt)
```

### Argon2Service

Key derivation using Argon2id (memory-hard, more resistant to GPU attacks):

```python
from blockauth.kdf.services import Argon2Service

service = Argon2Service()
private_key = service.derive_key(email, password, salt)
```

!!! note
    Argon2 requires the `argon2-cffi` package: `pip install argon2-cffi`

### KeyDerivationService

Full key derivation with wallet address generation:

```python
from blockauth.kdf.services import KeyDerivationService

kds = KeyDerivationService()
private_key = kds.derive_private_key(email, password, salt)
address = kds.get_wallet_address(email, password, salt)
```

### KDFManager

Manages dual encryption (user key + platform key):

```python
from blockauth.kdf.services import KDFManager

manager = KDFManager(master_key, platform_salt)
```

The KDFManager handles:

- Deriving user-specific encryption keys
- Encrypting private keys with AES-256-GCM
- Platform-level backup encryption
- Key recovery when needed

## Configuration

```python
BLOCK_AUTH_SETTINGS = {
    'KDF_ENABLED': True,
    'KDF_ALGORITHM': 'pbkdf2_sha256',       # or 'argon2id'
    'KDF_ITERATIONS': 100000,                # Production: 100k+
    'KDF_SECURITY_LEVEL': 'HIGH',            # LOW, MEDIUM, HIGH, CRITICAL
    'KDF_MASTER_SALT': 'your-32-char-minimum-salt',
    'MASTER_ENCRYPTION_KEY': '0x' + '64-char-hex-key',
    'PLATFORM_MASTER_SALT': 'your-platform-salt-32-chars-minimum',
}
```

## Security Architecture

```
Layer 1: User Credentials (Email + Password)
Layer 2: Key Derivation (PBKDF2/Argon2 with 100k+ iterations)
Layer 3: Private Key Generation (32-byte deterministic)
Layer 4: Dual Encryption (AES-256-GCM)
Layer 5: Secure Storage (Database + Platform key backup)
```

All key comparisons use `hmac.compare_digest()` for timing-safe comparison.

## Use Cases

- **E-commerce** -- users own NFTs without crypto knowledge
- **Gaming** -- true ownership of in-game items on blockchain
- **DeFi** -- access decentralized finance with familiar email/password login
- **Governance** -- participate in DAOs without MetaMask

## Requirements

The KDF system requires additional dependencies:

```bash
pip install cryptography>=41.0.0 web3>=6.0.0 eth-account>=0.9.0
```

For Argon2:

```bash
pip install argon2-cffi>=21.3.0
```
