"""
Minimal EIP-4361 (Sign-In with Ethereum) message parser and builder.

Why roll our own
----------------
The canonical ``siwe-py`` library from Spruce pulls in a handful of transitive
deps (pydantic, abnf, etc.) and has had periodic maintenance gaps. EIP-4361's
on-the-wire grammar is compact enough that a purpose-built parser is cheaper
than a new dependency. We only validate the fields blockauth actually cares
about -- domain binding, address, nonce, chain_id, issued/expiration
timestamps -- and surface everything else as-is for downstream callers.

Spec: https://eips.ethereum.org/EIPS/eip-4361

Hardening applied in this port of fabric-auth#402 (see issue #90):

* CRLF tolerant line splits. Clients that emit ``\\r\\n`` don't get rejected
  with an obscure missing-field error (#7).
* Duplicate-field detection. Repeated ``Nonce:`` / ``Chain ID:`` / ``URI:``
  lines are rejected rather than silently last-one-wins, because the full
  plaintext is what gets signed and accepting duplicates creates a nasty
  parser-differential surface (#8).
* Hard cap on message length at parse time. The DRF serializer caps input at
  4096 bytes too, but the parser's own guard stays in the library so any
  other caller gets the same protection (#9).

Grammar (EBNF-ish, trimmed to what we implement):

    ${domain} wants you to sign in with your Ethereum account:
    ${address}

    ${statement}                            # optional, single line, may be blank

    URI: ${uri}
    Version: 1
    Chain ID: ${chain_id}
    Nonce: ${nonce}
    Issued At: ${issued_at}                 # ISO-8601 UTC
    [Expiration Time: ${expiration_time}]   # ISO-8601 UTC, optional
    [Not Before: ${not_before}]             # ISO-8601 UTC, optional
    [Request ID: ${request_id}]             # optional
    [Resources:                             # optional
    - ${uri_1}
    - ${uri_2}
    ...]

The parser is strict on the mandatory fields and lenient on the optional
ones (we ignore resources contents but keep request_id if present).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

#: Maximum SIWE plaintext length, in bytes. Chosen to fit the EIP-4361 fields
#: plus a generous statement and a handful of ``Resources:`` URIs. Bigger
#: inputs are almost certainly an attack (or a client bug).
MAX_SIWE_MESSAGE_LENGTH = 4096


class SiweParseError(ValueError):
    """Raised when a SIWE message does not conform to EIP-4361."""


# EIP-4361 address must be the EIP-55 checksummed 0x-prefixed hex. We accept
# any 0x-prefixed 40-hex and lowercase during verification.
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
# Nonce must be at least 8 alphanumeric characters per spec.
_NONCE_RE = re.compile(r"^[A-Za-z0-9]{8,}$")
_HEADER_RE = re.compile(r"^(?P<domain>[^\s]+) wants you to sign in with your Ethereum account:$")


@dataclass
class SiweMessage:
    """Parsed EIP-4361 message, kept as plain data for downstream checks."""

    domain: str
    address: str  # preserved as-submitted (case-sensitive)
    statement: Optional[str]
    uri: str
    version: str
    chain_id: int
    nonce: str
    issued_at: datetime
    expiration_time: Optional[datetime] = None
    not_before: Optional[datetime] = None
    request_id: Optional[str] = None
    resources: List[str] = field(default_factory=list)


def _parse_iso8601_utc(value: str, field_name: str) -> datetime:
    """Parse an ISO-8601 timestamp and normalize to an aware UTC datetime.

    EIP-4361 mandates ISO-8601 with offset. Python 3.11+ ``fromisoformat``
    handles the common ``Z`` suffix directly.
    """
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise SiweParseError(f"Invalid ISO-8601 timestamp for {field_name}: {value!r}") from exc
    if parsed.tzinfo is None:
        raise SiweParseError(f"{field_name} must include a timezone offset (got naive datetime)")
    return parsed.astimezone(timezone.utc)


def _split_lines(message: str) -> List[str]:
    """Split a SIWE message on ``\\r?\\n`` so CRLF clients parse correctly."""
    # Normalize CRLF / CR to LF before splitting so one split handles every
    # line-ending variant. The plaintext the wallet signs is the original
    # message -- callers compare that byte-for-byte elsewhere. Here we only
    # need a clean field view.
    normalized = message.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.split("\n")


def parse_siwe_message(message: str) -> SiweMessage:
    """Parse a SIWE message string into a :class:`SiweMessage`.

    Strict on required fields (domain, address, URI, Version, Chain ID, Nonce,
    Issued At). Raises :class:`SiweParseError` with a specific reason on any
    malformed input.
    """
    if not isinstance(message, str) or not message:
        raise SiweParseError("SIWE message must be a non-empty string")

    if len(message) > MAX_SIWE_MESSAGE_LENGTH:
        raise SiweParseError(f"SIWE message exceeds maximum length of {MAX_SIWE_MESSAGE_LENGTH} bytes")

    lines = _split_lines(message)
    if len(lines) < 6:
        raise SiweParseError("SIWE message too short")

    header_match = _HEADER_RE.match(lines[0])
    if not header_match:
        raise SiweParseError("First line must be '<domain> wants you to sign in with your Ethereum account:'")
    domain = header_match.group("domain")

    address = lines[1].strip()
    if not _ADDRESS_RE.match(address):
        raise SiweParseError(f"Invalid Ethereum address on line 2: {address!r}")

    # Line 3 MUST be blank separator.
    if lines[2] != "":
        raise SiweParseError("Line 3 must be blank (separator)")

    # Line 4 is either a statement or a blank separator.
    cursor = 3
    statement: Optional[str] = None
    if lines[cursor] != "":
        statement = lines[cursor]
        cursor += 1
        # A statement line must be followed by a blank separator.
        if cursor >= len(lines) or lines[cursor] != "":
            raise SiweParseError("Statement line must be followed by a blank line")
        cursor += 1
    else:
        # Blank statement — still consume the separator.
        cursor += 1

    # Parse key-value section. Resources block is terminated by EOF or by the
    # first non-``- `` line (we are strict: no stray lines allowed after it).
    required_fields: dict[str, Optional[str]] = {
        "URI": None,
        "Version": None,
        "Chain ID": None,
        "Nonce": None,
        "Issued At": None,
    }
    optional_fields: dict[str, Optional[str]] = {
        "Expiration Time": None,
        "Not Before": None,
        "Request ID": None,
    }
    resources: List[str] = []
    in_resources = False

    while cursor < len(lines):
        line = lines[cursor]
        cursor += 1

        if in_resources:
            if line == "":
                # Trailing newline is fine.
                continue
            if not line.startswith("- "):
                raise SiweParseError(f"Expected resource line starting with '- ', got: {line!r}")
            resources.append(line[2:])
            continue

        if line == "":
            # Blank lines outside resources: tolerate trailing newline only.
            continue

        if line == "Resources:":
            in_resources = True
            continue

        key, sep, value = line.partition(": ")
        if not sep:
            raise SiweParseError(f"Malformed line (missing 'Key: value'): {line!r}")
        if key in required_fields:
            if required_fields[key] is not None:
                # Duplicate required field — reject rather than silently picking
                # last-one-wins. The signature covers the whole plaintext, so
                # both values were "signed"; accepting one silently is the
                # kind of ambiguity phishing relays love.
                raise SiweParseError(f"Duplicate SIWE field: {key!r}")
            required_fields[key] = value
        elif key in optional_fields:
            if optional_fields[key] is not None:
                raise SiweParseError(f"Duplicate SIWE field: {key!r}")
            optional_fields[key] = value
        else:
            raise SiweParseError(f"Unknown SIWE field: {key!r}")

    missing = [k for k, v in required_fields.items() if v is None]
    if missing:
        raise SiweParseError(f"Missing required SIWE fields: {', '.join(missing)}")

    nonce_value = required_fields["Nonce"] or ""
    if not _NONCE_RE.match(nonce_value):
        raise SiweParseError("Nonce must be at least 8 alphanumeric characters")

    try:
        chain_id = int(required_fields["Chain ID"] or "")
    except ValueError as exc:
        raise SiweParseError(f"Chain ID must be an integer, got {required_fields['Chain ID']!r}") from exc

    issued_at = _parse_iso8601_utc(required_fields["Issued At"] or "", "Issued At")
    expiration_time = (
        _parse_iso8601_utc(optional_fields["Expiration Time"], "Expiration Time")
        if optional_fields["Expiration Time"]
        else None
    )
    not_before = (
        _parse_iso8601_utc(optional_fields["Not Before"], "Not Before") if optional_fields["Not Before"] else None
    )

    return SiweMessage(
        domain=domain,
        address=address,
        statement=statement,
        uri=required_fields["URI"] or "",
        version=required_fields["Version"] or "",
        chain_id=chain_id,
        nonce=nonce_value,
        issued_at=issued_at,
        expiration_time=expiration_time,
        not_before=not_before,
        request_id=optional_fields["Request ID"],
        resources=resources,
    )


def build_siwe_message(
    *,
    domain: str,
    address: str,
    uri: str,
    chain_id: int,
    nonce: str,
    issued_at: datetime,
    expiration_time: Optional[datetime] = None,
    not_before: Optional[datetime] = None,
    statement: Optional[str] = None,
    version: str = "1",
    request_id: Optional[str] = None,
) -> str:
    """Build an EIP-4361 message string from typed inputs.

    Used by the challenge endpoint so the server fully controls the wording --
    the client never supplies any portion of the plaintext that will be signed.
    """
    if not _ADDRESS_RE.match(address):
        raise ValueError(f"Invalid Ethereum address: {address!r}")
    if not _NONCE_RE.match(nonce):
        raise ValueError("Nonce must be at least 8 alphanumeric characters")
    if issued_at.tzinfo is None:
        raise ValueError("issued_at must be timezone-aware")
    if expiration_time is not None and expiration_time.tzinfo is None:
        raise ValueError("expiration_time must be timezone-aware")
    if not_before is not None and not_before.tzinfo is None:
        raise ValueError("not_before must be timezone-aware")

    lines = [
        f"{domain} wants you to sign in with your Ethereum account:",
        address,
        "",
    ]
    if statement:
        lines.extend([statement, ""])
    else:
        lines.append("")
    lines.extend(
        [
            f"URI: {uri}",
            f"Version: {version}",
            f"Chain ID: {chain_id}",
            f"Nonce: {nonce}",
            f"Issued At: {_format_iso(issued_at)}",
        ]
    )
    if expiration_time is not None:
        lines.append(f"Expiration Time: {_format_iso(expiration_time)}")
    if not_before is not None:
        lines.append(f"Not Before: {_format_iso(not_before)}")
    if request_id:
        lines.append(f"Request ID: {request_id}")
    return "\n".join(lines)


def _format_iso(dt: datetime) -> str:
    """Format a UTC datetime as ``YYYY-MM-DDTHH:MM:SSZ`` for SIWE.

    SIWE reference clients (spruce, rainbow) emit the ``Z`` suffix. Python's
    ``isoformat`` uses ``+00:00`` which is equivalent per ISO-8601 but less
    common in the wild. Normalize to the ``Z`` form for compatibility.
    """
    utc = dt.astimezone(timezone.utc).replace(microsecond=0)
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")
