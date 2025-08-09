"""
Web3 Wallet Authentication Utilities

This module provides utilities for Ethereum wallet signature verification.
It handles the cryptographic verification of messages signed by Web3 wallets
like MetaMask, ensuring the authenticity of wallet-based authentication.

Dependencies:
    - web3: Ethereum Web3 library for blockchain interactions
    - eth_account: Ethereum account utilities for signature verification

Author: BlockAuth Team
License: All Rights Reserved
"""

try:
    from web3 import Web3  # type: ignore
    from web3.middleware import geth_poa_middleware  # type: ignore
    from eth_account.messages import encode_defunct  # type: ignore
    _web3_import_error = None
except Exception as _exc:  # pragma: no cover - import-time guard
    Web3 = None  # type: ignore
    geth_poa_middleware = None  # type: ignore
    encode_defunct = None  # type: ignore
    _web3_import_error = _exc


class WalletAuthenticator:
    """
    Ethereum Wallet Signature Authenticator

    This class provides methods to verify Ethereum wallet signatures.
    It supports standard Ethereum signature verification using the Web3 library.

    Example:
        authenticator = WalletAuthenticator()
        is_valid = authenticator.verify_signature(
            address="0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
            message="ABC",
            signature="0x1234567890abcdef1234567890abcdef1234567890abcd..."
        )
    """

    def __init__(self):
        if Web3 is None or encode_defunct is None:  # web3 extra not installed
            raise ImportError(
                "Wallet features require the 'wallet' extra. Install with: pip install blockauth[wallet]",
            ) from _web3_import_error
        # Initialize Web3 instance and inject POA middleware for compatibility
        self.w3 = Web3()
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    def verify_signature(self, address, message, signature):
        """
        Verify that the provided signature matches the message and wallet address.

        Args:
            address (str): Ethereum wallet address (0x...)
            message (str): The original message that was signed
            signature (str): The signed message (hex string, e.g. '0x1234...')

        Returns:
            bool: True if the signature is valid and matches the address, else False

        Raises:
            Exception: If the signature is invalid or cannot be processed
        """
        if signature.startswith("0x"):
            signature = signature[2:]
        signature = signature.strip().lower()
        if len(signature) != 130:
            raise Exception("Invalid signature length")
        try:
            signature_bytes = bytes.fromhex(signature)
        except ValueError:
            raise Exception("Invalid hex in signature")
        message_encoded = encode_defunct(text=message)
        recovered_address = self.w3.eth.account.recover_message(
            message_encoded, signature=signature_bytes
        )
        return recovered_address.lower() == address.lower() 