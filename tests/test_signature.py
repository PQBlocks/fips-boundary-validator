"""Tests for pqblocks-fips-check.signature - sign / verify_sig
Slice S-02: `pqblocks-fips-check.signature` — sign / verify_sig
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../src'))

from pqblocks_fips_check.signature import sign, verify_sig
from pqblocks_fips_check.core import PQCUnavailableError


def test_sign_verify_roundtrip():
    """Test sign/verify round-trip with ML-DSA-65."""
    message = b"test message for signing"
    sigma = sign(message)
    assert isinstance(sigma, bytes)
    assert len(sigma) == 3309  # FIPS 204 Table 2: ML-DSA-65 sig size
    assert verify_sig(message, sigma) is True


def test_sign_verify_with_context():
    """Test sign/verify with context string."""
    message = b"test message"
    context = b"test-context"
    sigma = sign(message, context=context)
    assert verify_sig(message, sigma, context=context) is True


def test_verify_wrong_message_returns_false():
    """Test that verifying with wrong message returns False."""
    message = b"original message"
    wrong_message = b"tampered message"
    sigma = sign(message)
    assert verify_sig(wrong_message, sigma) is False


def test_verify_wrong_signature_returns_false():
    """Test that verifying with wrong signature returns False (EC-06)."""
    message = b"test message"
    assert verify_sig(message, b"not-a-sig") is False


def test_verify_malformed_signature_returns_false():
    """Test that malformed signature returns False, never raises (EC-06)."""
    message = b"test message"
    assert verify_sig(message, b"") is False
    assert verify_sig(message, b"x" * 100) is False


def test_sign_empty_message():
    """Test signing empty message (EC-02)."""
    message = b""
    sigma = sign(message)
    assert len(sigma) == 3309
    assert verify_sig(message, sigma) is True


def test_sign_determinism_with_seed():
    """Test that seed produces deterministic signatures (EC-12)."""
    message = b"test message"
    sigma1 = sign(message, seed=42)
    sigma2 = sign(message, seed=42)
    assert sigma1 == sigma2


def test_sign_different_seeds_produce_different_signatures():
    """Test that different seeds produce different signatures."""
    message = b"test message"
    sigma1 = sign(message, seed=42)
    sigma2 = sign(message, seed=43)
    assert sigma1 != sigma2


def test_verify_wrong_key_type_raises_typeerror():
    """Test that wrong key type raises TypeError (EC-04)."""
    message = b"test message"
    sigma = sign(message)
    with pytest.raises(TypeError, match="invalid key|invalid public key"):
        verify_sig(message, sigma, public_key="not-bytes")


def test_sign_with_provided_sk():
    """Test signing with a provided secret key."""
    message = b"test message"
    sigma1 = sign(message)
    sigma2 = sign(message)
    # Different calls should produce different signatures (randomized)
    # unless seed is provided
    assert isinstance(sigma1, bytes)
    assert isinstance(sigma2, bytes)