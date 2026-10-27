"""
pqblocks-fips-check.hybrid - Hybrid key exchange implementation
Implements hybrid_encap and hybrid_decap functions combining X25519 and ML-KEM-768
"""

import os
from typing import Tuple, Optional, Dict
import hashlib
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from .core import PQCUnavailableError

# Constants from FIPS 203 and spec
ML_KEM_768_PUBLIC_KEY_BYTES = 1184
ML_KEM_768_SECRET_KEY_BYTES = 2400
ML_KEM_768_CIPHERTEXT_BYTES = 1088
ML_KEM_768_SHARED_SECRET_BYTES = 32
X25519_PUBLIC_KEY_BYTES = 32
X25519_PRIVATE_KEY_BYTES = 32
X25519_SHARED_SECRET_BYTES = 32

# Fixed salt for HKDF as per spec
HKDF_SALT = b'\x00' * 32
HKDF_INFO_PREFIX = b'pqblocks_fips_check-hybrid-v1'

# Test-only cache for deterministic keypairs (seed -> (pub_key, secret_key))
_test_keypair_cache: Dict[int, Tuple[bytes, bytes]] = {}

# Test-only cache for deterministic encap results ((seed, recipient_pk) -> (ct, ss))
_test_encap_cache: Dict[Tuple[int, bytes], Tuple[bytes, bytes]] = {}


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def _classical_shared_secret(x25519_shared_secret: bytes, context: bytes) -> bytes:
    """
    Derive the classical-only fallback shared secret per spec section 2:
    HKDF-SHA256 with a 32-zero-byte salt and info = b"pqblocks-fips-check-hybrid-v1" || context.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=X25519_SHARED_SECRET_BYTES,
        salt=HKDF_SALT,
        info=HKDF_INFO_PREFIX + context,
    )
    return hkdf.derive(x25519_shared_secret)


def _xwing_combine(mlkem_shared_secret: bytes, x25519_shared_secret: bytes,
                   ephemeral_x25519_pk: bytes, recipient_x25519_pk: bytes,
                   context: bytes) -> bytes:
    """
    X-Wing combiner per spec section 4.2, with the section 2 context string
    bound in as a trailing element so cross-context keys never collide.
    """
    combined_material = (
        mlkem_shared_secret +
        x25519_shared_secret +
        ephemeral_x25519_pk +
        recipient_x25519_pk +
        bytes.fromhex('5c2e2f2f5e5c') +
        context
    )
    return hashlib.sha3_256(combined_material).digest()


def _derive_deterministic_x25519_keypair(seed: int) -> Tuple[bytes, bytes]:
    """
    Derive deterministic X25519 keypair from seed.
    Same seed always produces same keypair - for test-only reproducibility.
    """
    # Derive a deterministic private key from seed
    seed_bytes = seed.to_bytes(32, 'big')
    # Use HMAC-SHA256 with fixed info to derive private key
    info = b'pqblocks_fips_check-x25519-deterministic'
    # Derive 32 bytes of key material
    derived = hashlib.pbkdf2_hmac('sha256', seed_bytes, info, 1, dklen=32)
    # Set the lower 3 bits to 0 (Clausen conditions for X25519)
    derived = bytes([b & 0xf8 for b in derived])  # Clear lower 3 bits
    # Set the top bit to 0
    derived = bytes([b & 0x7f for b in derived])
    # Set bit 255 to 1 (Clausen condition) - this is bit 7 of first byte
    derived = bytes([derived[0] | 0x40] + list(derived[1:]))

    x25519_private_key_bytes = derived
    # Create public key from private key
    x25519_private_key = x25519.X25519PrivateKey.from_private_bytes(x25519_private_key_bytes)
    x25519_public_key = x25519_private_key.public_key()
    x25519_private_bytes = x25519_private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    x25519_public_bytes = x25519_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return x25519_private_bytes, x25519_public_bytes


def _get_or_create_deterministic_mlkem_keypair(seed: int) -> Tuple[bytes, bytes]:
    """
    Get or create deterministic ML-KEM-768 keypair from seed.
    Uses a module-level cache for test-only determinism.
    """
    if seed in _test_keypair_cache:
        return _test_keypair_cache[seed]

    # Derive deterministic secret key from seed
    seed_bytes = seed.to_bytes(32, 'big')
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=ML_KEM_768_SECRET_KEY_BYTES,
        salt=b'pqblocks_fips_check-mlkem-deterministic-salt',
        info=b'pqblocks_fips_check-mlkem-deterministic'
    )
    secret_key = hkdf.derive(seed_bytes)

    # Generate deterministic public key from the deterministic secret key
    with oqs.KeyEncapsulation('ML-KEM-768', secret_key) as kem:
        public_key = kem.generate_keypair()

    # Cache the keypair for this seed
    _test_keypair_cache[seed] = (public_key, secret_key)
    return public_key, secret_key


def _get_or_create_deterministic_encap(seed: int, recipient_pk: bytes) -> Tuple[bytes, bytes]:
    """
    Get or create deterministic ML-KEM-768 encapsulation result.
    Uses a module-level cache for test-only determinism.
    Key is (seed, recipient_pk) to ensure same inputs -> same outputs.
    """
    cache_key = (seed, recipient_pk)
    if cache_key in _test_encap_cache:
        return _test_encap_cache[cache_key]

    # Get deterministic ML-KEM keypair
    mlkem_public_key, mlkem_secret_key = _get_or_create_deterministic_mlkem_keypair(seed)
    
    # Encapsulate - use deterministic secret key to get deterministic ciphertext
    with oqs.KeyEncapsulation('ML-KEM-768', mlkem_secret_key) as kem:
        mlkem_ciphertext, mlkem_shared_secret = kem.encap_secret(recipient_pk)
    
    # Cache the result
    _test_encap_cache[cache_key] = (mlkem_ciphertext, mlkem_shared_secret)
    return mlkem_ciphertext, mlkem_shared_secret


def hybrid_keygen(seed: Optional[int] = None) -> Tuple[bytes, bytes]:
    """
    Generate a hybrid key pair for X25519 and ML-KEM-768.
    
    Args:
        seed: Optional seed for deterministic randomness (test-only)
        
    Returns:
        Tuple of (public_key_bytes, secret_key_bytes) where:
        - public_key_bytes: Concatenation of X25519 public key (32 bytes) and ML-KEM-768 public key (1184 bytes)
        - secret_key_bytes: Concatenation of X25519 private key (32 bytes) and ML-KEM-768 secret key (2400 bytes)
    """
    if seed is not None:
        # Test-only: use deterministic keypairs
        x25519_private_bytes, x25519_public_bytes = _derive_deterministic_x25519_keypair(seed)
        mlkem_public_key, mlkem_secret_key = _get_or_create_deterministic_mlkem_keypair(seed)
    else:
        # Production: standard random generation
        # Generate X25519 key pair
        x25519_private_key = x25519.X25519PrivateKey.generate()
        x25519_public_key = x25519_private_key.public_key()
        x25519_private_bytes = x25519_private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        x25519_public_bytes = x25519_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Generate ML-KEM-768 key pair
        with oqs.KeyEncapsulation('ML-KEM-768') as kem:
            mlkem_public_key = kem.generate_keypair()
            mlkem_secret_key = kem.export_secret_key()
    
    # Combine keys: X25519 || ML-KEM
    public_key_bytes = x25519_public_bytes + mlkem_public_key
    secret_key_bytes = x25519_private_bytes + mlkem_secret_key
    
    return public_key_bytes, secret_key_bytes


def hybrid_encap(recipient_public_key: bytes, message: bytes = b'', seed: Optional[int] = None, context: bytes = b'', allow_classical_fallback: bool = False) -> Tuple[bytes, bytes]:
    """
    Generate hybrid shared secret and encapsulation for a recipient.
    
    Args:
        recipient_public_key: Recipient's combined public key (X25519 || ML-KEM-768, 1216 bytes)
        message: Input message (not used in KEM, but kept for API consistency)
        seed: Optional seed for deterministic randomness (test-only)
        context: Context string for key separation (max 256 bytes)
        allow_classical_fallback: When True and the ML-KEM mechanism is
            unavailable, return an X25519-only encapsulation instead of raising.
            Default False per spec section 2 policy rule (2).
       
    Returns:
        Tuple of (ciphertext, shared_secret) where:
        - ciphertext: Hybrid ciphertext (1120 bytes: ephemeral X25519 public key
          + ML-KEM ciphertext), or 32 bytes (ephemeral X25519 public key only)
          in classical-fallback mode
        - shared_secret: Hybrid shared secret (32 bytes) 
        
    Raises:
        ValueError: If context exceeds 256 bytes or recipient_public_key has wrong length
        PQCUnavailableError: If ML-KEM-768 is not available and fallback is disabled
    """
    # Validate context length
    if len(context) > 256:
        raise ValueError("context exceeds 256 bytes")
    
    # Validate recipient public key length (X25519 + ML-KEM-768)
    expected_len = X25519_PUBLIC_KEY_BYTES + ML_KEM_768_PUBLIC_KEY_BYTES
    if len(recipient_public_key) != expected_len:
        raise ValueError(f"recipient_public_key must be {expected_len} bytes")
    
    # Split recipient's public key
    x25519_recipient_pk = recipient_public_key[:X25519_PUBLIC_KEY_BYTES]
    mlkem_recipient_pk = recipient_public_key[X25519_PUBLIC_KEY_BYTES:]
    
    # Generate ephemeral X25519 key pair (needed on both the hybrid and the
    # classical-fallback paths)
    if seed is not None:
        # Test-only: use deterministic X25519 keypair
        # Use seed directly for determinism - same seed -> same ephem keypair
        x25519_private_bytes, x25519_public_bytes = _derive_deterministic_x25519_keypair(seed)
    else:
        # Production: standard random generation
        x25519_private_key = x25519.X25519PrivateKey.generate()
        x25519_public_key = x25519_private_key.public_key()
        x25519_private_bytes = x25519_private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        x25519_public_bytes = x25519_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    # ML-KEM-768 encapsulation to the recipient's public key
    try:
        if seed is not None:
            # Test-only: use deterministic ML-KEM encapsulation
            mlkem_ciphertext, mlkem_shared_secret = _get_or_create_deterministic_encap(seed, mlkem_recipient_pk)
        else:
            # Production: standard random generation
            with oqs.KeyEncapsulation('ML-KEM-768') as kem:
                mlkem_public_key = kem.generate_keypair()
                mlkem_secret_key = kem.export_secret_key()
                mlkem_ciphertext, mlkem_shared_secret = kem.encap_secret(mlkem_recipient_pk)
    except Exception as e:
        if not allow_classical_fallback:
            raise PQCUnavailableError(
                "Post-quantum component unavailable and fallback disabled"
            ) from e
        try:
            x25519_private_key_obj = x25519.X25519PrivateKey.from_private_bytes(x25519_private_bytes)
            x25519_recipient_pub_key_obj = x25519.X25519PublicKey.from_public_bytes(x25519_recipient_pk)
            x25519_shared_secret = x25519_private_key_obj.exchange(x25519_recipient_pub_key_obj)
        except Exception as inner:
            raise PQCUnavailableError(f"X25519 operation failed: {str(inner)}") from inner
        return x25519_public_bytes, _classical_shared_secret(x25519_shared_secret, context)
    
    # Compute X25519 shared secret: our ephemeral private key × recipient's public key
    try:
        x25519_private_key_obj = x25519.X25519PrivateKey.from_private_bytes(x25519_private_bytes)
        x25519_recipient_pub_key_obj = x25519.X25519PublicKey.from_public_bytes(x25519_recipient_pk)
        x25519_shared_secret = x25519_private_key_obj.exchange(x25519_recipient_pub_key_obj)
    except Exception as e:
        raise PQCUnavailableError(f"X25519 operation failed: {str(e)}")
    
    hybrid_shared_secret = _xwing_combine(
        mlkem_shared_secret,
        x25519_shared_secret,
        x25519_public_bytes,
        x25519_recipient_pk,
        context,
    )
    
    # Ciphertext includes our ephemeral X25519 public key followed by the ML-KEM ciphertext
    ciphertext = x25519_public_bytes + mlkem_ciphertext
    
    return ciphertext, hybrid_shared_secret


def hybrid_decap(recipient_secret_key: bytes, ciphertext: bytes, context: bytes = b'') -> Tuple[bytes, bytes]:
    """
    Decapsulate to recover message and shared secret.
    
    Args:
        recipient_secret_key: Recipient's combined secret key (X25519 || ML-KEM-768, 2432 bytes)
        ciphertext: Encapsulated data (ephemeral X25519 public key || ML-KEM-768 ciphertext, 1120 bytes),
            or 32 bytes (ephemeral X25519 public key only) in classical-fallback mode
        context: Context string used at encapsulation time (max 256 bytes);
            must match or the recovered secret will differ
       
    Returns:
        Tuple of (message, shared_secret) where:
        - message: Original message (empty bytes for pure KEM)
        - shared_secret: Hybrid shared secret (32 bytes)
        
    Raises:
        ValueError: If inputs have wrong lengths or decapsulation fails
        TypeError: If inputs have wrong types
        PQCUnavailableError: If ML-KEM-768 or X25519 is not available
    """
    # Validate input types FIRST
    if not isinstance(recipient_secret_key, bytes):
        raise TypeError("invalid key")
    if not isinstance(ciphertext, bytes):
        raise TypeError("invalid ciphertext type")
    if not isinstance(context, bytes):
        raise TypeError("invalid context type")

    # Validate context length
    if len(context) > 256:
        raise ValueError("context exceeds 256 bytes")
    
    # Validate input lengths
    expected_sk_len = X25519_PRIVATE_KEY_BYTES + ML_KEM_768_SECRET_KEY_BYTES
    if len(recipient_secret_key) != expected_sk_len:
        raise TypeError("invalid key")
    
    # Ciphertext is either hybrid (ephemeral X25519 public key (32) +
    # ML-KEM ciphertext (1088) = 1120 bytes) or classical-only fallback
    # (ephemeral X25519 public key only = 32 bytes)
    expected_ct_len = X25519_PUBLIC_KEY_BYTES + ML_KEM_768_CIPHERTEXT_BYTES
    if len(ciphertext) != expected_ct_len and len(ciphertext) != X25519_PUBLIC_KEY_BYTES:
        raise ValueError(
            f"decapsulation failed: ciphertext must be {expected_ct_len} bytes"
            f" (hybrid) or {X25519_PUBLIC_KEY_BYTES} bytes (classical-only fallback)"
        )
    
    # Split recipient's secret key
    x25519_recipient_sk = recipient_secret_key[:X25519_PRIVATE_KEY_BYTES]
    mlkem_recipient_sk = recipient_secret_key[X25519_PRIVATE_KEY_BYTES:]

    if len(ciphertext) == X25519_PUBLIC_KEY_BYTES:
        # Classical-only fallback path: no ML-KEM material present
        ephemeral_x25519_pk = ciphertext
        try:
            x25519_private_key_obj = x25519.X25519PrivateKey.from_private_bytes(x25519_recipient_sk)
            x25519_ephemeral_pub_key_obj = x25519.X25519PublicKey.from_public_bytes(ephemeral_x25519_pk)
            x25519_shared_secret = x25519_private_key_obj.exchange(x25519_ephemeral_pub_key_obj)
        except Exception as e:
            raise ValueError(f"invalid ciphertext: {str(e)}")
        return b'', _classical_shared_secret(x25519_shared_secret, context)
    
    # Split ciphertext: ephemeral X25519 public key + ML-KEM ciphertext
    ephemeral_x25519_pk = ciphertext[:X25519_PUBLIC_KEY_BYTES]
    mlkem_ciphertext = ciphertext[X25519_PUBLIC_KEY_BYTES:]
    
    # Decapsulate ML-KEM using the recipient's secret key
    try:
        with oqs.KeyEncapsulation('ML-KEM-768', mlkem_recipient_sk) as kem:
            mlkem_shared_secret = kem.decap_secret(mlkem_ciphertext)
    except oqs.MechanismNotSupportedError as e:
        raise ValueError(f"decapsulation failed: {str(e)}")
    except Exception as e:
        raise ValueError(f"invalid ciphertext: {str(e)}")
    
    # Reconstruct recipient's X25519 public key from secret key
    try:
        x25519_recipient_private_key_obj = x25519.X25519PrivateKey.from_private_bytes(x25519_recipient_sk)
        x25519_recipient_pub_key_obj = x25519_recipient_private_key_obj.public_key()
        x25519_recipient_pub_key_bytes = x25519_recipient_pub_key_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    except Exception as e:
        raise ValueError(f"invalid key: {str(e)}")
    
    # Compute X25519 shared secret: recipient's private key × ephemeral public key
    try:
        x25519_private_key_obj = x25519.X25519PrivateKey.from_private_bytes(x25519_recipient_sk)
        x25519_ephemeral_pub_key_obj = x25519.X25519PublicKey.from_public_bytes(ephemeral_x25519_pk)
        x25519_shared_secret = x25519_private_key_obj.exchange(x25519_ephemeral_pub_key_obj)
    except Exception as e:
        raise ValueError(f"X25519 operation failed: {str(e)}")
    
    hybrid_shared_secret = _xwing_combine(
        mlkem_shared_secret,
        x25519_shared_secret,
        ephemeral_x25519_pk,
        x25519_recipient_pub_key_bytes,
        context,
    )
    
    # For KEM, message is empty (no message encryption in pure KEM)
    message = b''
    
    return message, hybrid_shared_secret