"""
Tests for pqblocks-fips-check.hybrid - hybrid_encap / hybrid_decap
Slice S-01: `pqblocks-fips-check.hybrid` — hybrid_encap / hybrid_decap
"""

import pytest
import sys
import os

# Add src to path so we can import pqblocks-fips-check
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../src'))


def test_hybrid_encap_decap_roundtrip_empty_message():
    """Test round-trip with empty message returns correct sizes (EC-01)."""
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_decap

    # Generate key pair first
    from pqblocks_fips_check.hybrid import hybrid_keygen
    pk, sk = hybrid_keygen()

    message = b""
    pk_recipient, sk_recipient = hybrid_keygen()

    ct, ss = hybrid_encap(pk_recipient, message)

    # Check sizes per spec
    assert len(ct) == 1120, f"Expected ct length 1120, got {len(ct)}"
    assert len(ss) == 32, f"Expected ss length 32, got {len(ss)}"

    # Decapsulate
    msg2, ss2 = hybrid_decap(sk_recipient, ct)

    # Check that decapsulation returns empty message and matching shared secret
    assert msg2 == b"", f"Expected empty message, got {msg2}"
    assert len(ss2) == 32, f"Expected ss length 32, got {len(ss2)}"
    assert ss == ss2, f"Shared secrets don't match: {ss} != {ss2}"


def test_hybrid_encap_decap_roundtrip_nonempty_message():
    """Test round-trip with non-empty message returns correct sizes."""
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_decap

    # Generate key pair
    from pqblocks_fips_check.hybrid import hybrid_keygen
    pk, sk = hybrid_keygen()

    message = b"Hello, post-quantum world!"
    pk_recipient, sk_recipient = hybrid_keygen()

    ct, ss = hybrid_encap(pk_recipient, message)

    # Check sizes
    assert len(ct) == 1120
    assert len(ss) == 32

    # Decapsulate
    msg2, ss2 = hybrid_decap(sk_recipient, ct)

    # Check that decapsulation returns empty message and matching shared secret
    assert msg2 == b"", f"Expected empty message, got {msg2}"
    assert len(ss2) == 32
    assert ss == ss2, f"Shared secrets don't match: {ss} != {ss2}"


def test_hybrid_encap_with_seed_determinism():
    """Test that seed produces deterministic results (EC-12, test-only)."""
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_keygen

    message = b"test message"
    pk, sk = hybrid_keygen(seed=42)

    # Same seed should produce same results
    ct1, ss1 = hybrid_encap(pk, message, seed=42)
    ct2, ss2 = hybrid_encap(pk, message, seed=42)

    assert ct1 == ct2, f"Ciphertexts don't match with same seed"
    assert ss1 == ss2, f"Shared secrets don't match with same seed"


def test_hybrid_encap_different_seeds_produce_different_results():
    """Test that different seeds produce different outputs."""
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_keygen

    message = b"test message"
    pk1, sk1 = hybrid_keygen(seed=42)
    pk2, sk2 = hybrid_keygen(seed=43)

    ct1, ss1 = hybrid_encap(pk1, message, seed=42)
    ct2, ss2 = hybrid_encap(pk2, message, seed=43)

    # Should be different (with overwhelming probability)
    assert ct1 != ct2 or ss1 != ss2, "Different seeds should produce different outputs"


def test_hybrid_encap_context_separation():
    """Test that different contexts produce different shared secrets (EC-13)."""
    from pqblocks_fips_check.hybrid import hybrid_encap

    message = b"test message"

    # Generate a recipient public key first
    from pqblocks_fips_check.hybrid import hybrid_keygen
    pk, _ = hybrid_keygen()

    ct1, ss1 = hybrid_encap(pk, message, context=b"ctx1")
    ct2, ss2 = hybrid_encap(pk, message, context=b"ctx2")

    # Shared secrets should be different
    assert ss1 != ss2, "Different contexts should produce different shared secrets"


def test_hybrid_encap_context_length_limit():
    """Test that context exceeding 256 bytes raises ValueError (EC-10)."""
    from pqblocks_fips_check.hybrid import hybrid_encap

    # Generate a recipient public key first
    from pqblocks_fips_check.hybrid import hybrid_keygen
    pk, _ = hybrid_keygen()

    message = b"test"
    with pytest.raises(ValueError, match="context exceeds 256 bytes"):
        hybrid_encap(pk, message, context=b"x" * 257)


def test_hybrid_decap_wrong_key_type_raises_typeerror():
    """Test that wrong key type raises TypeError (EC-03)."""
    from pqblocks_fips_check.hybrid import hybrid_decap

    # Generate key pair
    from pqblocks_fips_check.hybrid import hybrid_keygen
    _, sk = hybrid_keygen()

    # Create a valid-looking ciphertext (correct length for hybrid construction)
    ct = b"x" * 1120

    # Pass wrong type (string instead of bytes)
    with pytest.raises(TypeError, match="invalid key"):
        hybrid_decap("not bytes", ct)

    # Pass wrong length (bytes but wrong size)
    with pytest.raises(TypeError, match="invalid key"):
        hybrid_decap(b"x" * 100, ct)  # Wrong length for secret key


def test_hybrid_decap_malformed_ciphertext_raises_valueerror():
    """Test that malformed ciphertext raises ValueError (EC-05)."""
    from pqblocks_fips_check.hybrid import hybrid_decap

    # Generate key pair
    from pqblocks_fips_check.hybrid import hybrid_keygen
    _, sk = hybrid_keygen()

    # Valid secret key (correct length for hybrid secret key)
    sk_valid = sk

    # Malformed ciphertext - wrong length
    with pytest.raises(ValueError, match="ciphertext must be 1120 bytes"):
        hybrid_decap(sk_valid, b"not-a-valid-ciphertext")

    with pytest.raises(ValueError, match="ciphertext must be 1120 bytes"):
        hybrid_decap(sk_valid, b"")


def test_hybrid_encap_pq_unavailable_without_fallback_raises_error():
    """Test that when unavailable and fallback disabled, raises PQCUnavailableError (EC-08)."""
    import oqs
    from unittest import mock
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_keygen
    from pqblocks_fips_check.core import PQCUnavailableError

    pk, _ = hybrid_keygen()

    with mock.patch.object(oqs, "KeyEncapsulation", side_effect=Exception("ML-KEM-768 unsupported")):
        with pytest.raises(PQCUnavailableError, match="Post-quantum component unavailable and fallback disabled"):
            hybrid_encap(pk, b"test message")


def test_hybrid_encap_pq_unavailable_with_fallback_returns_classical_only():
    """Test that when liboqs unavailable and fallback enabled, returns X25519-only (EC-09)."""
    import oqs
    from unittest import mock
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_decap, hybrid_keygen

    pk, sk = hybrid_keygen()

    with mock.patch.object(oqs, "KeyEncapsulation", side_effect=Exception("ML-KEM-768 unsupported")):
        ct, ss = hybrid_encap(pk, b"test message", allow_classical_fallback=True)

    # ct contains only X25519 ephemeral public key material, no ML-KEM ciphertext
    assert len(ct) == 32, f"Expected classical-only ct length 32, got {len(ct)}"
    assert len(ss) == 32, f"Expected ss length 32, got {len(ss)}"

    # Classical-only round-trip through decap recovers the same secret
    msg2, ss2 = hybrid_decap(sk, ct)
    assert msg2 == b""
    assert ss == ss2, "Classical-only fallback shared secrets don't match"


def test_hybrid_fallback_determinism_with_seed():
    """Test that fallback mode with a seed is deterministic (EC-12 on fallback path)."""
    import oqs
    from unittest import mock
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_keygen

    pk, _ = hybrid_keygen(seed=99)

    with mock.patch.object(oqs, "KeyEncapsulation", side_effect=Exception("ML-KEM-768 unsupported")):
        ct1, ss1 = hybrid_encap(pk, b"m", seed=99, allow_classical_fallback=True)
        ct2, ss2 = hybrid_encap(pk, b"m", seed=99, allow_classical_fallback=True)

    assert ct1 == ct2
    assert ss1 == ss2


def test_hybrid_context_bound_into_secret_with_same_seed():
    """Test that context is cryptographically bound: same seed, different context -> different ss."""
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_keygen

    pk, _ = hybrid_keygen(seed=7)

    ct1, ss1 = hybrid_encap(pk, b"m", seed=7, context=b"ctx1")
    ct2, ss2 = hybrid_encap(pk, b"m", seed=7, context=b"ctx2")

    assert ss1 != ss2, "Context must be bound into the shared secret"


def test_hybrid_decap_context_roundtrip():
    """Test that decap with the same context reproduces ss, and a different context does not."""
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_decap, hybrid_keygen

    pk, sk = hybrid_keygen()

    ct, ss = hybrid_encap(pk, b"m", context=b"ctx1")

    _, ss_same = hybrid_decap(sk, ct, context=b"ctx1")
    assert ss == ss_same, "Same-context decap must reproduce the shared secret"

    _, ss_other = hybrid_decap(sk, ct, context=b"ctx2")
    assert ss != ss_other, "Different-context decap must not reproduce the shared secret"


def test_hybrid_decap_context_length_limit():
    """Test that decap with context exceeding 256 bytes raises ValueError (EC-10)."""
    from pqblocks_fips_check.hybrid import hybrid_decap, hybrid_keygen

    _, sk = hybrid_keygen()
    ct = b"x" * 1120

    with pytest.raises(ValueError, match="context exceeds 256 bytes"):
        hybrid_decap(sk, ct, context=b"x" * 257)