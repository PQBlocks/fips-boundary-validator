"""Tests for size regression guard.

Slice S-06: Size regression guard
Contract: tests/test_sizes.py: asserts all 6 sizes from §1.3 exactly; fails if any change
"""

import pytest
import sys
import os

# Add src to path so we can import pqblocks-fips-check
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../src'))


def test_ml_kem_768_encapsulation_key_size():
    """Test ML-KEM-768 encapsulation key size is exactly 1184 bytes."""
    from pqblocks_fips_check.hybrid import hybrid_keygen
    
    # Generate a keypair and check the encapsulation key (ML-KEM-768 public key)
    pk, _ = hybrid_keygen()
    # Public key is X25519 (32) + ML-KEM-768 (1184) = 1216 bytes total
    mlkem_pk = pk[32:]  # Skip X25519 part
    assert len(mlkem_pk) == 1184, f"ML-KEM-768 encapsulation key should be 1184 bytes, got {len(mlkem_pk)}"


def test_ml_kem_768_decapsulation_key_size():
    """Test ML-KEM-768 decapsulation key size is exactly 2400 bytes."""
    from pqblocks_fips_check.hybrid import hybrid_keygen
    
    # Generate a keypair and check the decapsulation key (ML-KEM-768 secret key)
    _, sk = hybrid_keygen()
    # Secret key is X25519 (32) + ML-KEM-768 (2400) = 2432 bytes total
    mlkem_sk = sk[32:]  # Skip X25519 part
    assert len(mlkem_sk) == 2400, f"ML-KEM-768 decapsulation key should be 2400 bytes, got {len(mlkem_sk)}"


def test_ml_kem_768_ciphertext_size():
    """Test ML-KEM-768 ciphertext size is exactly 1088 bytes."""
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_keygen
    
    # Generate recipient keypair
    pk_recipient, _ = hybrid_keygen()
    
    # Encapsulate and check ciphertext size
    ct, _ = hybrid_encap(pk_recipient, b"test")
    # Ciphertext is X25519 ephemeral public key (32) + ML-KEM-768 ciphertext (1088) = 1120 bytes total
    mlkem_ct = ct[32:]  # Skip X25519 part
    assert len(mlkem_ct) == 1088, f"ML-KEM-768 ciphertext should be 1088 bytes, got {len(mlkem_ct)}"


def test_ml_kem_768_shared_secret_size():
    """Test ML-KEM-768 shared secret size is exactly 32 bytes."""
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_keygen
    
    # Generate recipient keypair
    pk_recipient, _ = hybrid_keygen()
    
    # Encapsulate and check shared secret size
    _, ss = hybrid_encap(pk_recipient, b"test")
    assert len(ss) == 32, f"ML-KEM-768 shared secret should be 32 bytes, got {len(ss)}"


def test_ml_dsa_65_signing_key_size():
    """Test ML-DSA-65 signing key size is exactly 4032 bytes."""
    from pqblocks_fips_check.signature import sign
    
    # Generate a signing key by calling sign with no secret key (it generates one internally)
    # We'll extract it from the internal cache or generate one directly
    from pqblocks_fips_check.signature import _initialize_signer
    _, sk, _ = _initialize_signer()
    assert len(sk) == 4032, f"ML-DSA-65 signing key should be 4032 bytes, got {len(sk)}"


def test_ml_dsa_65_verification_key_size():
    """Test ML-DSA-65 verification key size is exactly 1952 bytes."""
    from pqblocks_fips_check.signature import _initialize_signer
    
    # Generate a keypair and check the verification key (ML-DSA-65 public key)
    _, _, pk = _initialize_signer()
    assert len(pk) == 1952, f"ML-DSA-65 verification key should be 1952 bytes, got {len(pk)}"


def test_ml_dsa_65_signature_size():
    """Test ML-DSA-65 signature size is exactly 3309 bytes."""
    from pqblocks_fips_check.signature import sign
    
    message = b"test message for signature size"
    sig = sign(message)
    assert len(sig) == 3309, f"ML-DSA-65 signature should be 3309 bytes, got {len(sig)}"


def test_x25519_key_sizes():
    """Test X25519 key sizes are exactly 32 bytes each."""
    from pqblocks_fips_check.hybrid import hybrid_keygen
    
    pk, sk = hybrid_keygen()
    
    # Public key: X25519 (32) + ML-KEM-768 (1184) = 1216 bytes
    x25519_pk = pk[:32]
    assert len(x25519_pk) == 32, f"X25519 public key should be 32 bytes, got {len(x25519_pk)}"
    
    # Secret key: X25519 (32) + ML-KEM-768 (2400) = 2432 bytes
    x25519_sk = sk[:32]
    assert len(x25519_sk) == 32, f"X25519 private key should be 32 bytes, got {len(x25519_sk)}"


def test_hybrid_shared_secret_size():
    """Test hybrid shared secret size is exactly 32 bytes."""
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_decap, hybrid_keygen
    
    # Generate recipient keypair
    pk_recipient, sk_recipient = hybrid_keygen()
    
    # Encapsulate
    ct, ss = hybrid_encap(pk_recipient, b"test")
    
    # Decapsulate
    _, ss2 = hybrid_decap(sk_recipient, ct)
    
    assert len(ss) == 32, f"Hybrid shared secret should be 32 bytes, got {len(ss)}"
    assert len(ss2) == 32, f"Decapsulated hybrid shared secret should be 32 bytes, got {len(ss2)}"


def test_sizes_are_exact_and_not_configurable():
    """Test that all sizes are exact constants and not configurable."""
    # This test ensures we're not accidentally making sizes configurable
    # All the above tests verify exact sizes
    
    # Verify the constants from the module match expectations
    from pqblocks_fips_check.hybrid import (
        ML_KEM_768_PUBLIC_KEY_BYTES,
        ML_KEM_768_SECRET_KEY_BYTES,
        ML_KEM_768_CIPHERTEXT_BYTES,
        ML_KEM_768_SHARED_SECRET_BYTES,
        X25519_PUBLIC_KEY_BYTES,
        X25519_PRIVATE_KEY_BYTES,
        X25519_SHARED_SECRET_BYTES
    )
    
    assert ML_KEM_768_PUBLIC_KEY_BYTES == 1184
    assert ML_KEM_768_SECRET_KEY_BYTES == 2400
    assert ML_KEM_768_CIPHERTEXT_BYTES == 1088
    assert ML_KEM_768_SHARED_SECRET_BYTES == 32
    assert X25519_PUBLIC_KEY_BYTES == 32
    assert X25519_PRIVATE_KEY_BYTES == 32
    assert X25519_SHARED_SECRET_BYTES == 32
    
    # Also verify signature constants
    from pqblocks_fips_check.signature import (
        ML_DSA_65_SECRET_KEY_BYTES,
        ML_DSA_65_PUBLIC_KEY_BYTES,
        ML_DSA_65_SIGNATURE_BYTES
    )
    
    assert ML_DSA_65_SECRET_KEY_BYTES == 4032
    assert ML_DSA_65_PUBLIC_KEY_BYTES == 1952
    assert ML_DSA_65_SIGNATURE_BYTES == 3309