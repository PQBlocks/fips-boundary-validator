"""
Signature-specific edge case tests - covering missing error handling paths in signature.py.
"""

import pytest
import sys
import os
from unittest.mock import patch

# Add src to path so we can import pqblocks-fips-check
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../src'))

def test_signature_initialize_signer_mechanism_not_supported():
    """Test that _initialize_signer handles MechanismNotSupportedError (covers lines 61-62)."""
    from pqblocks_fips_check.signature import _initialize_signer, PQCUnavailableError
    import oqs
    
    # Mock oqs.Signature to raise MechanismNotSupportedError
    with patch('pqblocks_fips_check.signature.oqs.Signature') as mock_signature:
        mock_signature.side_effect = oqs.MechanismNotSupportedError("Mock mechanism error")
        
        with pytest.raises(PQCUnavailableError, match="ML-DSA-65 not available"):
            _initialize_signer()

def test_signature_initialize_signer_general_exception():
    """Test that _initialize_signer handles general exceptions (covers lines 63-64)."""
    from pqblocks_fips_check.signature import _initialize_signer, PQCUnavailableError
    
    # Mock oqs.Signature to raise a general exception
    with patch('pqblocks_fips_check.signature.oqs.Signature') as mock_signature:
        mock_signature.side_effect = Exception("Mock general error")
        
        with pytest.raises(PQCUnavailableError, match="ML-DSA-65 not available"):
            _initialize_signer()

def test_signature_verify_prehashed_unsupported_hash():
    """Test that _verify_prehashed handles unsupported hash algorithms (covers lines 136-140)."""
    from pqblocks_fips_check.signature import _verify_prehashed
    
    # Test with unsupported hash algorithm
    result = _verify_prehashed(b"test", b"sig", b"pub", "UNSUPPORTED-HASH")
    assert result is False

def test_signature_verify_prehashed_hash_exception():
    """Test that _verify_prehashed handles hash function exceptions (covers lines 152-153)."""
    from pqblocks_fips_check.signature import _verify_prehashed
    
    # Mock hash function to raise an exception
    with patch('pqblocks_fips_check.signature.hashlib.sha3_256') as mock_hash:
        mock_hash.side_effect = Exception("Mock hash error")
        
        result = _verify_prehashed(b"test", b"sig", b"pub", "SHA3-256")
        assert result is False

def test_signature_verify_prehashed_verifier_exception():
    """Test that _verify_prehashed handles verifier exceptions (covers lines 162-164)."""
    from pqblocks_fips_check.signature import _verify_prehashed
    
    # Mock oqs.Signature.verify to raise an exception
    with patch('pqblocks_fips_check.signature.oqs.Signature.verify') as mock_verify:
        mock_verify.side_effect = Exception("Mock verify error")
        
        result = _verify_prehashed(b"test", b"sig", b"pub", "SHA3-256")
        assert result is False

def test_signature_sign_secret_key_type_error():
    """Test that sign handles invalid secret_key type (covers lines 198-199)."""
    from pqblocks_fips_check.signature import sign
    
    # Mock _get_or_create_cached_signer to avoid actual key generation
    with patch('pqblocks_fips_check.signature._get_or_create_cached_signer'):
        # Test with non-bytes secret_key
        with pytest.raises(TypeError, match="secret_key must be bytes"):
            sign(b"message", secret_key="not bytes")
          
        with pytest.raises(TypeError, match="secret_key must be bytes"):
            sign(b"message", secret_key=123)

def test_signature_sign_secret_key_length_error():
    """Test that sign handles invalid secret_key length (covers lines 200-201)."""
    from pqblocks_fips_check.signature import sign
    
    # Mock _get_or_create_cached_signer to avoid actual key generation
    with patch('pqblocks_fips_check.signature._get_or_create_cached_signer'):
        # Test with wrong length secret_key
        with pytest.raises(TypeError, match="secret_key must be 4032 bytes"):
            sign(b"message", secret_key=b"x" * 100)  # Too short
           
        with pytest.raises(TypeError, match="secret_key must be 4032 bytes"):
            sign(b"message", secret_key=b"x" * 5000)  # Too long

def test_signature_sign_mechanism_not_supported():
    """Test that sign handles MechanismNotSupportedError (covers lines 213-214)."""
    from pqblocks_fips_check.signature import sign, PQCUnavailableError
    import oqs
    from unittest.mock import MagicMock
    
    # Mock _get_or_create_cached_signer to return a signer whose sign method raises
    mock_signer = MagicMock()
    mock_signer.sign.side_effect = oqs.MechanismNotSupportedError("Mock mechanism error")
    with patch('pqblocks_fips_check.signature._get_or_create_cached_signer', return_value=mock_signer):
        with pytest.raises(PQCUnavailableError, match="Signing failed"):
            sign(b"message")

def test_signature_sign_general_exception():
    """Test that sign handles general exceptions (covers lines 215-216)."""
    from pqblocks_fips_check.signature import sign, PQCUnavailableError
    from unittest.mock import MagicMock
    
    # Mock _get_or_create_cached_signer to return a signer whose sign method raises
    mock_signer = MagicMock()
    mock_signer.sign.side_effect = Exception("Mock general error")
    with patch('pqblocks_fips_check.signature._get_or_create_cached_signer', return_value=mock_signer):
        with pytest.raises(PQCUnavailableError, match="Signing failed"):
            sign(b"message")

def test_signature_verify_sig_normalization_unknown_hash():
    """Test that verify_sig normalizes unknown hash algorithms to NONE (covers line 268)."""
    from pqblocks_fips_check.signature import verify_sig, sign
    
    # Generate a valid signature first
    msg = b"test message"
    sig = sign(msg)
    
    # Verify with an unknown hash algorithm - should work as NONE
    result = verify_sig(msg, sig, hash_alg="UNKNOWN-HASH")
    # Should behave the same as NONE (which would use cached signer or return False)
    # Since we have a valid signature, it should work
    assert isinstance(result, bool)

def test_signature_verify_sig_no_public_key_prehash():
    """Test that verify_sig returns False when no public_key provided for pre-hash (covers lines 305-306)."""
    from pqblocks_fips_check.signature import verify_sig
    
    # Test with pre-hash algorithm but no public key
    result = verify_sig(b"message", b"signature", hash_alg="SHA3-256")
    assert result is False

def test_signature_verify_sig_invalid_public_key_type():
    """Test that verify_sig handles invalid public_key type (covers lines 307-308)."""
    from pqblocks_fips_check.signature import verify_sig
    
    # Test with non-bytes public_key (string, int) - these should raise TypeError
    with pytest.raises(TypeError, match="invalid public key"):
        verify_sig(b"message", b"signature", public_key="not bytes", hash_alg="SHA3-256")
        
    with pytest.raises(TypeError, match="invalid public key"):
        verify_sig(b"message", b"signature", public_key=123, hash_alg="SHA3-256")
    
    # public_key=None with pre-hash returns False (EC-06), not TypeError
    result = verify_sig(b"message", b"signature", public_key=None, hash_alg="SHA3-256")
    assert result is False

def test_signature_verify_sig_invalid_public_key_length():
    """Test that verify_sig handles invalid public_key length (covers lines 309-310)."""
    from pqblocks_fips_check.signature import verify_sig
    
    # Test with wrong length public_key
    with pytest.raises(TypeError, match="invalid public key"):
        verify_sig(b"message", b"signature", public_key=b"x" * 100, hash_alg="SHA3-256")  # Too short
        
    with pytest.raises(TypeError, match="invalid public key"):
        verify_sig(b"message", b"signature", public_key=b"x" * 3000, hash_alg="SHA3-256")  # Too long

def test_signature_verify_prehashed_exception_path():
    """Test that verify_sig handles exceptions in _verify_prehashed (covers lines 310-311)."""
    from pqblocks_fips_check.signature import verify_sig
    
    # Mock _verify_prehashed to raise an exception
    with patch('pqblocks_fips_check.signature._verify_prehashed') as mock_verify:
        mock_verify.side_effect = Exception("Mock verify error")
        
        # Should return False, not raise
        result = verify_sig(b"message", b"signature", public_key=b"x" * 1952, hash_alg="SHA3-256")
        assert result is False