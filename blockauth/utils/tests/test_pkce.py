"""RFC 7636 PKCE pair generation tests."""

import base64
import hashlib


from blockauth.utils.pkce import PkcePair, compute_pkce_challenge, generate_pkce_pair


def test_pair_lengths_match_rfc_7636():
    pair = generate_pkce_pair()
    assert 43 <= len(pair.verifier) <= 128
    assert len(pair.challenge) == 43  # base64url(sha256) without padding is always 43


def test_challenge_is_sha256_of_verifier():
    pair = generate_pkce_pair()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(pair.verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    )
    assert pair.challenge == expected


def test_two_calls_produce_distinct_pairs():
    a = generate_pkce_pair()
    b = generate_pkce_pair()
    assert a != b


def test_verifier_charset_is_url_safe():
    pair = generate_pkce_pair()
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    assert set(pair.verifier).issubset(allowed)


def test_pair_is_named_tuple_and_tuple_unpacks_for_back_compat():
    """PkcePair must support both attribute access AND positional tuple unpack."""
    pair = generate_pkce_pair()
    assert isinstance(pair, PkcePair)
    # Attribute access (the new safer interface).
    assert pair.verifier and pair.challenge
    # Positional unpack (the legacy contract).
    verifier, challenge = pair
    assert verifier == pair.verifier
    assert challenge == pair.challenge


def test_rfc_7636_appendix_b_known_answer():
    """RFC 7636 Appendix B fixed vector — locks in S256 conformance.

    The verifier and expected challenge come straight from
    https://www.rfc-editor.org/rfc/rfc7636#appendix-B, which any RFC 7636
    conformant implementation must reproduce exactly.
    """
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert compute_pkce_challenge(verifier) == expected_challenge
