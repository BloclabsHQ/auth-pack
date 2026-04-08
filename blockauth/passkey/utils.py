"""
Passkey/WebAuthn Utilities for BlockAuth

Helper functions for base64url encoding/decoding and other utilities.
"""

import base64
import hashlib
import secrets
from typing import Union


def base64url_encode(data: Union[bytes, bytearray]) -> str:
    """
    Encode bytes to base64url string (no padding).

    WebAuthn uses base64url encoding without padding for all binary data.

    Args:
        data: Bytes to encode

    Returns:
        Base64url encoded string without padding
    """
    if isinstance(data, bytearray):
        data = bytes(data)
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(data: str) -> bytes:
    """
    Decode base64url string to bytes.

    Handles missing padding automatically.

    Args:
        data: Base64url encoded string (with or without padding)

    Returns:
        Decoded bytes
    """
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def generate_challenge(length: int = 32) -> bytes:
    """
    Generate cryptographically secure random challenge.

    Args:
        length: Number of random bytes (default 32)

    Returns:
        Random bytes for use as challenge
    """
    return secrets.token_bytes(length)


def generate_user_handle() -> bytes:
    """
    Generate random user handle for WebAuthn.

    User handles are opaque identifiers that should not contain
    personally identifiable information.

    Returns:
        64 random bytes as user handle
    """
    return secrets.token_bytes(64)


def sha256(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of data.

    Args:
        data: Data to hash

    Returns:
        SHA-256 hash (32 bytes)
    """
    return hashlib.sha256(data).digest()


def parse_authenticator_data(auth_data: bytes) -> dict:
    """
    Parse authenticator data from WebAuthn response.

    Authenticator data structure:
    - rpIdHash (32 bytes): SHA-256 hash of RP ID
    - flags (1 byte): Bit flags
    - signCount (4 bytes): Signature counter (big-endian)
    - attestedCredentialData (variable): Only present if AT flag set
    - extensions (variable): Only present if ED flag set

    Args:
        auth_data: Raw authenticator data bytes

    Returns:
        Parsed authenticator data dictionary
    """
    if len(auth_data) < 37:
        raise ValueError("Authenticator data too short")

    rp_id_hash = auth_data[:32]
    flags = auth_data[32]
    sign_count = int.from_bytes(auth_data[33:37], "big")

    # Parse flags
    user_present = bool(flags & 0x01)  # Bit 0: UP
    user_verified = bool(flags & 0x04)  # Bit 2: UV
    backup_eligible = bool(flags & 0x08)  # Bit 3: BE
    backup_state = bool(flags & 0x10)  # Bit 4: BS
    attested_credential_data = bool(flags & 0x40)  # Bit 6: AT
    extension_data = bool(flags & 0x80)  # Bit 7: ED

    result = {
        "rp_id_hash": rp_id_hash,
        "flags": flags,
        "flags_parsed": {
            "user_present": user_present,
            "user_verified": user_verified,
            "backup_eligible": backup_eligible,
            "backup_state": backup_state,
            "attested_credential_data": attested_credential_data,
            "extension_data": extension_data,
        },
        "sign_count": sign_count,
    }

    offset = 37

    # Parse attested credential data if present
    if attested_credential_data and len(auth_data) > offset:
        aaguid = auth_data[offset : offset + 16]
        offset += 16

        cred_id_len = int.from_bytes(auth_data[offset : offset + 2], "big")
        offset += 2

        credential_id = auth_data[offset : offset + cred_id_len]
        offset += cred_id_len

        # The rest is the COSE public key (CBOR encoded)
        # We'll let py-webauthn handle the CBOR parsing
        credential_public_key = auth_data[offset:]

        result["attested_credential_data"] = {
            "aaguid": aaguid,
            "credential_id": credential_id,
            "credential_public_key_raw": credential_public_key,
        }

    return result


def format_aaguid(aaguid: bytes) -> str:
    """
    Format AAGUID bytes as UUID string.

    Args:
        aaguid: 16 bytes AAGUID

    Returns:
        UUID formatted string (e.g., "00000000-0000-0000-0000-000000000000")
    """
    if len(aaguid) != 16:
        return ""

    hex_str = aaguid.hex()
    return f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:]}"


def validate_rp_id(rp_id: str, origin: str) -> bool:
    """
    Validate that RP ID is valid for the given origin.

    RP ID must be equal to or a registrable domain suffix of the origin's
    effective domain.

    Args:
        rp_id: Relying Party ID (e.g., "example.com")
        origin: Request origin (e.g., "https://app.example.com")

    Returns:
        True if RP ID is valid for origin
    """
    from urllib.parse import urlparse

    parsed = urlparse(origin)
    hostname = parsed.hostname

    if not hostname:
        return False

    # Exact match
    if hostname == rp_id:
        return True

    # Suffix match (e.g., app.example.com matches example.com)
    if hostname.endswith("." + rp_id):
        return True

    return False


def bytes_to_int(data: bytes, byteorder: str = "big") -> int:
    """
    Convert bytes to integer.

    Args:
        data: Bytes to convert
        byteorder: 'big' or 'little'

    Returns:
        Integer value
    """
    return int.from_bytes(data, byteorder)


def int_to_bytes(value: int, length: int, byteorder: str = "big") -> bytes:
    """
    Convert integer to bytes.

    Args:
        value: Integer to convert
        length: Number of bytes
        byteorder: 'big' or 'little'

    Returns:
        Bytes representation
    """
    return value.to_bytes(length, byteorder)
