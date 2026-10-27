"""Tests for pqblocks-fips-check.core - error types, context handling, seed fixtures.

Slice S-04: `pqblocks-fips-check.core` — error types, context handling, seed fixtures
Contract: tests/test_core.py: `PQCUnavailableError`, context length check (§3 EC-10), seed determinism (§3 EC-12)
"""

import pytest
import sys
import os

# Add src to path so we can import pqblocks-fips-check
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../src'))


def test_pqc_unavailable_error_is_exception():
    """Test that PQCUnavailableError is an exception type (part of core contract)."""
    from pqblocks_fips_check.core import PQCUnavailableError, PQBlocksError

    # Should be able to raise and catch
    with pytest.raises(PQCUnavailableError):
        raise PQCUnavailableError("test error")

    # Should inherit from PQBlocksError
    assert issubclass(PQCUnavailableError, PQBlocksError)
    assert issubclass(PQCUnavailableError, Exception)


def test_pqc_unavailable_error_message():
    """Test that PQCUnavailableError accepts and preserves error message."""
    from pqblocks_fips_check.core import PQCUnavailableError

    msg = "Post-quantum component unavailable and fallback disabled"
    exc = PQCUnavailableError(msg)
    assert str(exc) == msg


def test_pq_shift_error_base():
    """Test that PQBlocksError is the base exception."""
    from pqblocks_fips_check.core import PQBlocksError

    with pytest.raises(PQBlocksError):
        raise PQBlocksError("base error")


def test_validate_context_accepts_valid_length():
    """Test that validate_context accepts context <= 256 bytes."""
    from pqblocks_fips_check.core import validate_context

    # Empty context
    validate_context(b"")

    # Exactly 256 bytes
    validate_context(b"x" * 256)

    # Under 256 bytes
    validate_context(b"valid context")


def test_validate_context_raises_on_excess(EC=10):
    """Test that validate_context raises ValueError for context > 256 bytes (EC-10)."""
    from pqblocks_fips_check.core import validate_context

    with pytest.raises(ValueError, match="context exceeds 256 bytes"):
        validate_context(b"x" * 257)


def test_validate_context_raises_with_exact_message():
    """Test that the error message matches spec exactly."""
    from pqblocks_fips_check.core import validate_context

    with pytest.raises(ValueError) as exc_info:
        validate_context(b"x" * 257)
    assert "context exceeds 256 bytes" in str(exc_info.value)


def test_seed_rng_accepts_none():
    """Test that seed_rng accepts None (no seeding)."""
    from pqblocks_fips_check.core import seed_rng

    # Should not raise
    seed_rng(None)


def test_seed_rng_accepts_integer():
    """Test that seed_rng accepts integer seed."""
    from pqblocks_fips_check.core import seed_rng

    # Should not raise for various seeds
    seed_rng(0)
    seed_rng(42)
    seed_rng(123456789)


def test_seed_determinism_hybrid_encap(EC=12):
    """Test that hybrid_encap with same seed produces identical results (EC-12)."""
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_keygen

    message = b"test message for seed determinism"

    # Generate recipient keypair
    pk, sk = hybrid_keygen(seed=123)

    # First call with seed
    ct1, ss1 = hybrid_encap(pk, message, seed=42)

    # Second call with same seed
    ct2, ss2 = hybrid_encap(pk, message, seed=42)

    # Should be bit-identical
    assert ct1 == ct2, "Ciphertexts should be identical with same seed"
    assert ss1 == ss2, "Shared secrets should be identical with same seed"


def test_seed_determinism_hybrid_keygen(EC=12):
    """Test that hybrid_keygen with same seed produces identical keypairs (EC-12)."""
    from pqblocks_fips_check.hybrid import hybrid_keygen

    pk1, sk1 = hybrid_keygen(seed=42)
    pk2, sk2 = hybrid_keygen(seed=42)

    assert pk1 == pk2, "Public keys should be identical with same seed"
    assert sk1 == sk2, "Secret keys should be identical with same seed"


def test_seed_determinism_sign(EC=12):
    """Test that sign with same seed produces identical signatures (EC-12)."""
    from pqblocks_fips_check.signature import sign

    message = b"test message for signing"

    # First signature with seed
    sig1 = sign(message, seed=42)

    # Second signature with same seed
    sig2 = sign(message, seed=42)

    assert sig1 == sig2, "Signatures should be identical with same seed"


def test_seed_determinism_sign_with_context(EC=12):
    """Test that sign with context and same seed produces identical signatures (EC-12)."""
    from pqblocks_fips_check.signature import sign

    message = b"test message with context"
    context = b"test context"

    sig1 = sign(message, seed=42, context=context)
    sig2 = sign(message, seed=42, context=context)

    assert sig1 == sig2, "Signatures with context should be identical with same seed"


def test_different_seeds_produce_different_results_hybrid():
    """Test that different seeds produce different outputs for hybrid."""
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_keygen

    message = b"test"
    pk, _ = hybrid_keygen(seed=1)

    ct1, ss1 = hybrid_encap(pk, message, seed=42)
    ct2, ss2 = hybrid_encap(pk, message, seed=43)

    # Different seeds should produce different results (with overwhelming probability)
    assert ct1 != ct2 or ss1 != ss2


def test_different_seeds_produce_different_results_sign():
    """Test that different seeds produce different signatures."""
    from pqblocks_fips_check.signature import sign

    message = b"test"

    sig1 = sign(message, seed=42)
    sig2 = sign(message, seed=43)

    assert sig1 != sig2


def test_context_separation_hybrid_encap(EC=13):
    """Test that different contexts produce different shared secrets (EC-13)."""
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_keygen

    message = b"test message"
    pk, _ = hybrid_keygen()

    ss1 = hybrid_encap(pk, message, context=b"ctx1")[1]
    ss2 = hybrid_encap(pk, message, context=b"ctx2")[1]

    assert ss1 != ss2, "Different contexts should produce different shared secrets"


def test_context_separation_sign(EC=13):
    """Test that different contexts produce different signatures."""
    from pqblocks_fips_check.signature import sign

    message = b"test message"

    sig1 = sign(message, seed=42, context=b"ctx1")
    sig2 = sign(message, seed=42, context=b"ctx2")

    assert sig1 != sig2, "Different contexts should produce different signatures"


def test_context_length_limit_in_hybrid_encap(EC=10):
    """Test that hybrid_encap enforces 256-byte context limit (EC-10)."""
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_keygen

    pk, _ = hybrid_keygen()

    with pytest.raises(ValueError, match="context exceeds 256 bytes"):
        hybrid_encap(pk, b"msg", context=b"x" * 257)


def test_context_length_limit_in_sign(EC=10):
    """Test that sign enforces 256-byte context limit (EC-10)."""
    from pqblocks_fips_check.signature import sign

    with pytest.raises(ValueError, match="context exceeds 256 bytes"):
        sign(b"msg", seed=42, context=b"x" * 257)


def test_context_length_limit_in_verify_sig(EC=10):
    """Test that verify_sig enforces 256-byte context limit (EC-10)."""
    from pqblocks_fips_check.signature import verify_sig

    with pytest.raises(ValueError, match="context exceeds 256 bytes"):
        verify_sig(b"msg", b"sig", b"pk", context=b"x" * 257)


def test_context_length_limit_in_hybrid_decap():
    """Test that hybrid_decap validates context length (EC-10) and binds context (EC-13)."""
    from pqblocks_fips_check.hybrid import hybrid_decap, hybrid_encap, hybrid_keygen

    pk, sk = hybrid_keygen()
    ct, ss = hybrid_encap(pk, b"msg", context=b"valid")

    # Same context reproduces the secret
    msg2, ss2 = hybrid_decap(sk, ct, context=b"valid")
    assert msg2 == b""
    assert ss == ss2

    # Overlong context raises (EC-10)
    with pytest.raises(ValueError, match="context exceeds 256 bytes"):
        hybrid_decap(sk, ct, context=b"x" * 257)

    # Different context yields a different secret (EC-13)
    _, ss3 = hybrid_decap(sk, ct, context=b"other")
    assert ss != ss3