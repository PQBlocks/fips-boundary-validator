"""
Tests for edge cases - covering missing error handling paths.
This file tests the error handling code paths that were not covered by existing tests.
"""
import pytest
import sys
import os
from unittest.mock import MagicMock, patch

# Add src to path so we can import pqblocks-fips-check
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../src'))


def test_hybrid_xor_bytes():
    """Test the _xor_bytes helper function."""
    from pqblocks_fips_check.hybrid import _xor_bytes
    
    # Test basic XOR
    assert _xor_bytes(b'\x01\x02\x03', b'\x01\x02\x03') == b'\x00\x00\x00'
    assert _xor_bytes(b'\x00\x00\x00', b'\x01\x02\x03') == b'\x01\x02\x03'
    assert _xor_bytes(b'\xff\xff\xff', b'\x01\x02\x03') == b'\xfe\xfd\xfc'
    
    # Test with different lengths (should truncate to shortest)
    assert _xor_bytes(b'\x01\x02\x03\x04', b'\x01\x02\x03') == b'\x00\x00\x00'


def test_hybrid_encap_invalid_public_key_length():
    """Test that hybrid_encap raises ValueError for invalid public key length (covers line 193)."""
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_keygen
    
    # Generate a valid key to get the correct length
    pk, _ = hybrid_keygen()
    valid_len = len(pk)  # Should be 1216 bytes (X25519 + ML-KEM-768)
    
    # Test with too short key
    with pytest.raises(ValueError, match=f"recipient_public_key must be {valid_len} bytes"):
        hybrid_encap(b"x" * (valid_len - 1), b"test message")
    
    # Test with too long key
    with pytest.raises(ValueError, match=f"recipient_public_key must be {valid_len} bytes"):
        hybrid_encap(b"x" * (valid_len + 1), b"test message")


def test_hybrid_encap_x25519_exception_handling():
    """Test that hybrid_encap handles X25519 exceptions properly (covers lines 234-235)."""
    from pqblocks_fips_check.hybrid import hybrid_encap, hybrid_keygen, PQCUnavailableError
    from cryptography.hazmat.primitives.asymmetric import x25519
    
    # Generate a valid recipient key
    pk, sk = hybrid_keygen()
    
    # Mock X25519PrivateKey.from_private_bytes to raise an exception
    from unittest.mock import MagicMock
    mock_sk = MagicMock()
    mock_sk.exchange.side_effect = PQCUnavailableError("X25519 operation failed")
    with patch('pqblocks_fips_check.hybrid.x25519.X25519PrivateKey.from_private_bytes', return_value=mock_sk):
        with pytest.raises(PQCUnavailableError, match="X25519 operation failed"):
            hybrid_encap(pk, b"test message")


def test_hybrid_decap_invalid_ciphertext_type():
    """Test that hybrid_decap raises TypeError for invalid ciphertext type (covers line 281)."""
    from pqblocks_fips_check.hybrid import hybrid_decap, hybrid_keygen
    
    # Generate a valid secret key
    _, sk = hybrid_keygen()
    
    # Test with non-bytes type
    with pytest.raises(TypeError, match="invalid ciphertext type"):
        hybrid_decap(sk, "not bytes")
    
    with pytest.raises(TypeError, match="invalid ciphertext type"):
        hybrid_decap(sk, 123)
    
    with pytest.raises(TypeError, match="invalid ciphertext type"):
        hybrid_decap(sk, None)


def test_hybrid_decap_oqs_exception_handling():
    """Test that hybrid_decap handles OQS exceptions properly (covers lines 305-306)."""
    from pqblocks_fips_check.hybrid import hybrid_decap, hybrid_keygen
    import oqs
    
    # Generate a valid secret key and ciphertext
    _, sk = hybrid_keygen()
    ct = b"x" * 1120  # Valid length ciphertext
    
    # Mock oqs.KeyEncapsulation.decap_secret to raise MechanismNotSupportedError
    with patch('pqblocks_fips_check.hybrid.oqs.KeyEncapsulation.decap_secret') as mock_decap:
        mock_decap.side_effect = oqs.MechanismNotSupportedError("Mock OQS error")
      
        with pytest.raises(ValueError, match="decapsulation failed"):
            hybrid_decap(sk, ct)


def test_hybrid_decap_general_exception_handling():
    """Test that hybrid_decap handles general exceptions properly (covers lines 307-308)."""
    from pqblocks_fips_check.hybrid import hybrid_decap, hybrid_keygen
    
    # Generate a valid secret key and ciphertext
    _, sk = hybrid_keygen()
    ct = b"x" * 1120  # Valid length ciphertext
    
    # Mock oqs.KeyEncapsulation.decap_secret to raise a general exception
    with patch('pqblocks_fips_check.hybrid.oqs.KeyEncapsulation.decap_secret') as mock_decap:
        mock_decap.side_effect = Exception("Mock general error")
      
        with pytest.raises(ValueError, match="invalid ciphertext"):
            hybrid_decap(sk, ct)


def test_hybrid_decap_invalid_key_exception_handling():
    """Test that hybrid_decap handles invalid key exceptions properly (covers lines 318-319)."""
    from pqblocks_fips_check.hybrid import hybrid_decap, hybrid_keygen
    
    # Generate a valid secret key and ciphertext
    _, sk = hybrid_keygen()
    ct = b"x" * 1120  # Valid length ciphertext
    
    # Mock X25519PrivateKey.from_private_bytes to raise an exception
    # This simulates an invalid X25519 private key in the secret key
    with patch('pqblocks_fips_check.hybrid.x25519.X25519PrivateKey.from_private_bytes', side_effect=Exception("Mock key error")):
        with pytest.raises(ValueError, match="invalid key"):
            hybrid_decap(sk, ct)


def test_hybrid_decap_x25519_exception_handling():
    """Test that hybrid_decap handles X25519 exceptions properly (covers lines 326-327)."""
    from pqblocks_fips_check.hybrid import hybrid_decap, hybrid_keygen, PQCUnavailableError
    from cryptography.hazmat.primitives.asymmetric import x25519
    from unittest.mock import MagicMock
    
    # Generate a valid secret key and ciphertext
    _, sk = hybrid_keygen()
    ct = b"x" * 1120  # Valid length ciphertext
    
    # Patch X25519PrivateKey.from_private_bytes to return a mock whose exchange raises.
    # X25519PrivateKey.exchange is a read-only Rust attribute; patch from_private_bytes instead.
    mock_sk = MagicMock()
    mock_sk.exchange.side_effect = ValueError("X25519 operation failed")
    with patch('pqblocks_fips_check.hybrid.x25519.X25519PrivateKey.from_private_bytes', return_value=mock_sk):
        with pytest.raises(ValueError, match="X25519 operation failed"):
            hybrid_decap(sk, ct)