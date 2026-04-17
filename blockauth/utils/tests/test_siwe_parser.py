"""Tests for the EIP-4361 SIWE parser + builder (issue #90).

Covers the baseline round-trip plus the hardening items landed alongside
the upstream port:

* #7 — CRLF tolerance.
* #8 — duplicate-field rejection.
* #9 — max-length rejection at parse time.
"""

from datetime import datetime, timedelta, timezone

import pytest

from blockauth.utils.siwe import (
    MAX_SIWE_MESSAGE_LENGTH,
    SiweParseError,
    build_siwe_message,
    parse_siwe_message,
)

_TEST_ADDRESS = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A"


def _default_build(**overrides):
    issued = datetime(2026, 4, 16, 12, 0, 0, tzinfo=timezone.utc)
    kwargs = dict(
        domain="example.com",
        address=_TEST_ADDRESS,
        uri="https://example.com/",
        chain_id=1,
        nonce="abcdef1234567890abcdef1234567890",
        issued_at=issued,
        expiration_time=issued + timedelta(minutes=5),
    )
    kwargs.update(overrides)
    return build_siwe_message(**kwargs)


class TestRoundTrip:
    def test_roundtrip_with_statement(self):
        msg = _default_build(statement="Hello, fren.")
        parsed = parse_siwe_message(msg)
        assert parsed.domain == "example.com"
        assert parsed.address == _TEST_ADDRESS
        assert parsed.chain_id == 1
        assert parsed.nonce == "abcdef1234567890abcdef1234567890"
        assert parsed.version == "1"
        assert parsed.uri == "https://example.com/"
        assert parsed.statement == "Hello, fren."
        assert parsed.expiration_time is not None

    def test_roundtrip_without_statement(self):
        msg = _default_build()
        parsed = parse_siwe_message(msg)
        assert parsed.statement is None

    def test_roundtrip_with_not_before(self):
        issued = datetime(2026, 4, 16, 12, 0, 0, tzinfo=timezone.utc)
        msg = build_siwe_message(
            domain="example.com",
            address=_TEST_ADDRESS,
            uri="https://example.com/",
            chain_id=1,
            nonce="abcdef1234567890abcdef1234567890",
            issued_at=issued,
            not_before=issued + timedelta(seconds=30),
        )
        parsed = parse_siwe_message(msg)
        assert parsed.not_before == issued + timedelta(seconds=30)


class TestCRLF:
    """Hardening #7 — CRLF-terminated messages must parse."""

    def test_crlf_terminated_message_parses(self):
        msg = _default_build()
        crlf_msg = msg.replace("\n", "\r\n")
        parsed = parse_siwe_message(crlf_msg)
        assert parsed.nonce == "abcdef1234567890abcdef1234567890"
        assert parsed.domain == "example.com"

    def test_bare_cr_line_endings_parse(self):
        msg = _default_build()
        cr_msg = msg.replace("\n", "\r")
        parsed = parse_siwe_message(cr_msg)
        assert parsed.nonce == "abcdef1234567890abcdef1234567890"

    def test_mixed_crlf_and_lf_parses(self):
        msg = _default_build()
        lines = msg.split("\n")
        # Every other line uses CRLF.
        mixed = "\n".join(line + ("\r" if i % 2 == 0 else "") for i, line in enumerate(lines))
        parsed = parse_siwe_message(mixed)
        assert parsed.domain == "example.com"


class TestDuplicateFields:
    """Hardening #8 — duplicate required/optional fields must be rejected."""

    def test_duplicate_nonce_rejected(self):
        msg = _default_build()
        # Inject a second Nonce line.
        tampered = msg.replace(
            "Nonce: abcdef1234567890abcdef1234567890",
            "Nonce: abcdef1234567890abcdef1234567890\nNonce: zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        )
        with pytest.raises(SiweParseError, match="Duplicate SIWE field"):
            parse_siwe_message(tampered)

    def test_duplicate_chain_id_rejected(self):
        msg = _default_build()
        tampered = msg.replace("Chain ID: 1", "Chain ID: 1\nChain ID: 137")
        with pytest.raises(SiweParseError, match="Duplicate SIWE field"):
            parse_siwe_message(tampered)

    def test_duplicate_uri_rejected(self):
        msg = _default_build()
        tampered = msg.replace(
            "URI: https://example.com/",
            "URI: https://example.com/\nURI: https://phisher.example/",
        )
        with pytest.raises(SiweParseError, match="Duplicate SIWE field"):
            parse_siwe_message(tampered)


class TestMaxLength:
    """Hardening #9 — oversized messages must be rejected before parsing."""

    def test_rejects_oversized_message(self):
        # Build a base message, then append ``Resources:`` block lines until
        # the byte count blows past the cap. We want the size to trip the
        # check before any structural rule can.
        base = _default_build()
        padding = "- https://example.com/abc\n" * ((MAX_SIWE_MESSAGE_LENGTH // 24) + 16)
        oversized = base + "\nResources:\n" + padding
        assert len(oversized) > MAX_SIWE_MESSAGE_LENGTH
        with pytest.raises(SiweParseError, match="exceeds maximum length"):
            parse_siwe_message(oversized)

    def test_accepts_message_at_boundary(self):
        # Pad a valid message with extra newlines right up to the limit.
        msg = _default_build()
        # Trailing newlines are ignored in the resource-parsing loop, so we
        # can safely concatenate them without breaking the grammar.
        padded = msg + "\n" * (MAX_SIWE_MESSAGE_LENGTH - len(msg) - 1)
        assert len(padded) < MAX_SIWE_MESSAGE_LENGTH
        parsed = parse_siwe_message(padded)
        assert parsed.nonce == "abcdef1234567890abcdef1234567890"


class TestStructuralRejections:
    def test_rejects_missing_required_field(self):
        msg = _default_build()
        tampered = "\n".join(line for line in msg.split("\n") if not line.startswith("Nonce:"))
        with pytest.raises(SiweParseError, match="Missing required"):
            parse_siwe_message(tampered)

    def test_rejects_short_nonce_in_builder(self):
        issued = datetime(2026, 4, 16, 12, 0, 0, tzinfo=timezone.utc)
        with pytest.raises(ValueError, match="Nonce must be at least"):
            build_siwe_message(
                domain="example.com",
                address=_TEST_ADDRESS,
                uri="https://example.com/",
                chain_id=1,
                nonce="short",
                issued_at=issued,
            )

    def test_rejects_bad_address(self):
        issued = datetime(2026, 4, 16, 12, 0, 0, tzinfo=timezone.utc)
        with pytest.raises(ValueError, match="Invalid Ethereum address"):
            build_siwe_message(
                domain="example.com",
                address="not-an-address",
                uri="https://example.com/",
                chain_id=1,
                nonce="abcdef1234567890abcdef1234567890",
                issued_at=issued,
            )

    def test_rejects_bad_chain_id(self):
        msg = _default_build().replace("Chain ID: 1", "Chain ID: foo")
        with pytest.raises(SiweParseError, match="Chain ID must be an integer"):
            parse_siwe_message(msg)

    def test_rejects_unknown_field(self):
        msg = _default_build()
        tampered = msg + "\nX-Custom: surprise"
        with pytest.raises(SiweParseError, match="Unknown SIWE field"):
            parse_siwe_message(tampered)

    def test_rejects_empty_input(self):
        with pytest.raises(SiweParseError, match="non-empty"):
            parse_siwe_message("")

    def test_rejects_too_few_lines(self):
        with pytest.raises(SiweParseError, match="too short"):
            parse_siwe_message("just one line")
