# Wallet Authentication

BlockAuth supports Web3 wallet authentication via Ethereum signature verification. Users sign a message with their wallet (MetaMask, etc.) and BlockAuth verifies the signature to authenticate.

Requires the `WALLET_LOGIN` feature flag.

## How It Works

1. Client requests a challenge message from the server
2. User signs the message with their wallet
3. Client sends the signed message, signature, and wallet address to BlockAuth
4. BlockAuth recovers the signer address from the signature and verifies it matches

## Login

```bash
POST /auth/login/wallet/

{
  "wallet_address": "0x1234567890abcdef1234567890abcdef12345678",
  "message": "Sign this message to authenticate with BlockAuth: 1704067200",
  "signature": "0x..."
}
```

Returns JWT tokens on success:

```json
{
  "access": "eyJ...",
  "refresh": "eyJ..."
}
```

If the wallet address is not associated with an existing account, a new account is created.

## Replay Protection

Signed messages have a TTL to prevent replay attacks. Configure with:

```python
BLOCK_AUTH_SETTINGS = {
    'WALLET_MESSAGE_TTL': 300,  # 5 minutes (default)
}
```

Messages older than the TTL are rejected.

## Add Email to Wallet Account

Wallet-only accounts can add an email address for password-based login:

```bash
POST /auth/wallet/email/add/
Authorization: Bearer <access_token>

{
  "email": "user@example.com"
}
```

Requires the `WALLET_EMAIL_ADD` feature flag.

## Security Considerations

- Wallet addresses are validated for correct format (0x + 40 hex chars)
- Zero address (`0x0000...0000`) is rejected
- Signature malleability is checked (s-value validation)
- Message size is limited to prevent DoS
- All signature verification uses `eth_account` for ECDSA recovery

## Integration with KDF

The [KDF System](kdf-system.md) complements wallet auth by generating blockchain wallets from email/password credentials, bridging Web2 users into Web3 without requiring them to manage private keys.
