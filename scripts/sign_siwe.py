"""SIWE signer used by the E2E wallet-login flow.

Hits ``POST /auth/login/wallet/challenge/`` to get a server-issued SIWE
plaintext, signs it with ``eth-account`` using a fixed dev-only private
key, then returns the tuple ``(wallet_address, message, signature)``
for the pytest suite or for Insomnia's pre-request script.

Usage (CLI, dumps JSON for Insomnia)::

    uv run python -m scripts.sign_siwe --base http://localhost:8000

Usage (library)::

    from scripts.sign_siwe import sign_for_login
    addr, msg, sig = sign_for_login("http://localhost:8000")
"""

from __future__ import annotations

import argparse
import json
import time
import uuid
from typing import Tuple

import requests
from eth_account import Account
from eth_account.messages import encode_defunct

# Deterministic dev-only key.  NEVER use in production.  Address:
# 0x8fd379246834eac74B8419FfdA202CF8051F7A03
DEV_PRIVATE_KEY = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"


def _derive_address(private_key: str) -> str:
    return Account.from_key(private_key).address


def sign_for_login(
    base_url: str,
    private_key: str = DEV_PRIVATE_KEY,
    *,
    chain_id: int = 1,
    domain: str = "localhost",
) -> Tuple[str, str, str]:
    """Request a SIWE challenge and sign it.

    Returns ``(wallet_address_lowercase, siwe_message, hex_signature)``
    suitable for ``POST /auth/login/wallet/``.
    """
    address = _derive_address(private_key)
    challenge_resp = requests.post(
        f"{base_url.rstrip('/')}/auth/login/wallet/challenge/",
        json={"address": address, "chain_id": chain_id, "domain": domain},
        timeout=10,
    )
    challenge_resp.raise_for_status()
    payload = challenge_resp.json()
    message = payload["message"]

    signed = Account.sign_message(encode_defunct(text=message), private_key=private_key)
    signature = signed.signature.hex()
    if not signature.startswith("0x"):
        signature = "0x" + signature

    return address.lower(), message, signature


def sign_link_message(
    private_key: str = DEV_PRIVATE_KEY,
    *,
    body: str = "Link this wallet to my account",
) -> Tuple[str, str, str]:
    """Build and sign a wallet-link JSON message.

    The ``/auth/wallet/link/`` endpoint uses the legacy
    :class:`WalletAuthenticator` contract: a JSON-encoded message with
    a ``nonce`` (>=16 chars) and integer ``timestamp``, signed as an
    Ethereum personal message.

    Returns ``(wallet_address_lowercase, json_message, hex_signature)``.
    """
    address = _derive_address(private_key)
    payload = {
        "body": body,
        "nonce": uuid.uuid4().hex,  # 32 hex chars, satisfies the 16-char min
        "timestamp": int(time.time()),
    }
    message = json.dumps(payload, separators=(",", ":"))

    signed = Account.sign_message(encode_defunct(text=message), private_key=private_key)
    signature = signed.signature.hex()
    if not signature.startswith("0x"):
        signature = "0x" + signature

    return address.lower(), message, signature


def _cli() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://localhost:8765")
    parser.add_argument("--key", default=DEV_PRIVATE_KEY)
    args = parser.parse_args()

    address, message, signature = sign_for_login(args.base, args.key)
    print(
        json.dumps(
            {"wallet_address": address, "message": message, "signature": signature},
            indent=2,
        )
    )


if __name__ == "__main__":
    _cli()
