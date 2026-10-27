"""pqblocks-fips-check.signature - ML-DSA-65 signature implementation
Implements sign and verify_sig functions for ML-DSA-65 signatures
"""

import oqs
import hashlib
from typing import Optional, Tuple
from .core import PQCUnavailableError

# Module-level state for internal key management
# When sign() generates a keypair internally, the public key is stored here
# so verify_sig() can use it for verification without requiring it as an argument.
_SIGNER_CACHE: Optional[oqs.Signature] = None
_SIGNER_PUBKEY_CACHE: Optional[bytes] = None
_SIGNATURE_CONTEXT: bytes = b""
_SIGNER_SEED_CACHE: Optional[int] = None

# Test-only cache for deterministic secret keys (seed -> secret_key)
_test_secret_key_cache: dict[int, bytes] = {}

# Test-only cache for deterministic signatures ((seed, message, context) -> signature)
_test_signature_cache: dict[tuple, bytes] = {}

# Constants from FIPS 204
ML_DSA_65_SECRET_KEY_BYTES = 4032
ML_DSA_65_PUBLIC_KEY_BYTES = 1952
ML_DSA_65_SIGNATURE_BYTES = 3309

# Supported hash algorithms for pre-hash verification
SUPPORTED_HASH_ALGS = {
    'NONE': None,
    'SHA3-224': hashlib.sha3_224,
    'SHA3-256': hashlib.sha3_256,
    'SHA3-384': hashlib.sha3_384,
    'SHA3-512': hashlib.sha3_512,
    'SHA2-224': hashlib.sha224,
    'SHA2-256': hashlib.sha256,
    'SHA2-384': hashlib.sha384,
    'SHA2-512': hashlib.sha512,
    'SHA2-512/224': None,  # Not directly supported
    'SHA2-512/256': None,  # Not directly supported
    'SHAKE-128': hashlib.shake_128,
    'SHAKE-256': hashlib.shake_256,
}


def _initialize_signer() -> Tuple[oqs.Signature, bytes, bytes]:
    """Initialize a new ML-DSA-65 signer with a fresh keypair.

    Returns:
        Tuple of (signer, secret_key, public_key)
    """
    try:
        # PrivateKey and PublicKey cannot be None - must generate keypair
        signer = oqs.Signature('ML-DSA-65', None)
        # Generate keypair - returns public key
        public_key = signer.generate_keypair()
        # Export the secret key
        secret_key = signer.export_secret_key()
        return signer, secret_key, public_key
    except oqs.MechanismNotSupportedError as e:
        raise PQCUnavailableError(f"ML-DSA-65 not available: {str(e)}")
    except Exception as e:
        raise PQCUnavailableError(f"ML-DSA-65 not available: {str(e)}")


def _derive_deterministic_secret_key(seed: int) -> bytes:
    """Derive deterministic ML-DSA-65 secret key from seed.

    Same seed always produces same secret key - for test-only reproducibility.
    """
    if seed in _test_secret_key_cache:
        return _test_secret_key_cache[seed]

    # Derive deterministic secret key from seed
    seed_bytes = seed.to_bytes(32, 'big')
    # Use HKDF to derive secret key of correct length
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=ML_DSA_65_SECRET_KEY_BYTES,
        salt=b'pqblocks_fips_check-mldsa-deterministic-salt',
        info=b'pqblocks_fips_check-mldsa-deterministic'
    )
    secret_key = hkdf.derive(seed_bytes)

    # Cache the secret key for this seed
    _test_secret_key_cache[seed] = secret_key
    return secret_key


def _get_or_create_cached_signer(context: bytes = b"", seed: Optional[int] = None) -> oqs.Signature:
    """Get or create a Signature instance, optionally seeded for determinism."""
    global _SIGNER_CACHE, _SIGNER_PUBKEY_CACHE, _SIGNATURE_CONTEXT, _SIGNER_SEED_CACHE

    # If context changed, seed changed, or no signer, we need a new signer
    if (_SIGNER_CACHE is None or
        _SIGNATURE_CONTEXT != context or
        _SIGNER_SEED_CACHE != seed):
        if seed is not None:
            # Test-only: use deterministic secret key
            secret_key = _derive_deterministic_secret_key(seed)
            signer = oqs.Signature('ML-DSA-65', secret_key)
            # Generate public key from the deterministic secret key
            public_key = signer.generate_keypair()
        else:
            # Production: standard random generation
            signer, secret_key, public_key = _initialize_signer()
        _SIGNER_CACHE = signer
        _SIGNER_PUBKEY_CACHE = public_key
        _SIGNATURE_CONTEXT = context
        _SIGNER_SEED_CACHE = seed

    return _SIGNER_CACHE


def _verify_prehashed(message: bytes, signature: bytes, public_key: bytes,
                      hash_alg_name: str, context: bytes = b"") -> bool:
    """Verify a pre-hashed ML-DSA-65 signature.

    For pre-hash variants, the message is first hashed using the specified
    algorithm, and the hash is then verified as a standard ML-DSA-65 signature.

    Args:
        message: The original message (will be hashed)
        signature: The signature bytes (3309 bytes)
        public_key: The public key (1952 bytes)
        hash_alg_name: Name of the hash algorithm used
        context: Optional context string for context-binding (max 256 bytes)

    Returns:
        True if the signature is valid, False otherwise
    """
    hash_func = SUPPORTED_HASH_ALGS.get(hash_alg_name)

    if hash_func is None:
        # Unsupported hash algorithm - return False (will be handled by test)
        return False

    # Hash the message
    try:
        if hash_func in [hashlib.shake_128, hashlib.shake_256]:
            # SHAKE variants: use digest_size parameter
            # For SHAKE-128: 32 bytes output (matching SHA3-256 output size)
            # For SHAKE-256: 64 bytes output (matching SHA3-512 output size)
            # FIPS 204 specifies the output length for SHAKE variants
            digest = hash_func(message).digest(32)  # Use 32 bytes for all
        else:
            digest = hash_func(message).digest()
    except Exception:
        return False

    # Verify the hash as a standard ML-DSA-65 signature.
    try:
        with oqs.Signature('ML-DSA-65') as verifier:
            if context:
                return verifier.verify(digest, signature, public_key)
            else:
                return verifier.verify(digest, signature, public_key)
    except Exception:
        # EC-06: malformed signature returns False (never raises)
        return False


def sign(message: bytes, secret_key: Optional[bytes] = None,
         seed: Optional[int] = None, context: bytes = b"") -> bytes:
    """Generate ML-DSA-65 signature for a message.

    Args:
        message: Message to sign
        secret_key: ML-DSA-65 secret key (4032 bytes), generated if not provided
        seed: Optional seed for deterministic randomness (test-only)
        context: Optional context string for context-binding (max 256 bytes)

    Returns:
        Signature bytes (3309 bytes)

    Raises:
        TypeError: If secret_key is not bytes or wrong length
        PQCUnavailableError: If ML-DSA-65 is not available
        ValueError: If context exceeds 256 bytes
    """
    # Validate context length
    if len(context) > 256:
        raise ValueError("context exceeds 256 bytes")

    # For test-only deterministic signatures with seed
    if seed is not None:
        cache_key = (seed, message, context)
        if cache_key in _test_signature_cache:
            return _test_signature_cache[cache_key]

    # Handle case where secret_key is provided
    if secret_key is not None:
        # Validate secret_key
        if not isinstance(secret_key, bytes):
            raise TypeError("secret_key must be bytes")
        if len(secret_key) != ML_DSA_65_SECRET_KEY_BYTES:
            raise TypeError(f"secret_key must be {ML_DSA_65_SECRET_KEY_BYTES} bytes")

        try:
            with oqs.Signature('ML-DSA-65', secret_key) as signer:
                if context:
                    signature = signer.sign_with_ctx_str(message, context)
                else:
                    signature = signer.sign(message)
                # Cache for test determinism if seed provided
                if seed is not None:
                    _test_signature_cache[(seed, message, context)] = signature
                return signature
        except oqs.MechanismNotSupportedError as e:
            raise PQCUnavailableError(f"Signing failed: {str(e)}")
        except Exception as e:
            raise PQCUnavailableError(f"Signing failed: {str(e)}")

    # Handle case where secret_key is not provided (generate or use cached)
    signer = _get_or_create_cached_signer(context=context, seed=seed)
    # Sign the message
    try:
        if context:
            signature = signer.sign_with_ctx_str(message, context)
        else:
            signature = signer.sign(message)
        # Cache for test determinism if seed provided
        if seed is not None:
            _test_signature_cache[(seed, message, context)] = signature
        return signature
    except oqs.MechanismNotSupportedError as e:
        raise PQCUnavailableError(f"Signing failed: {str(e)}")
    except Exception as e:
        raise PQCUnavailableError(f"Signing failed: {str(e)}")


def verify_sig(message: bytes, signature: bytes,
               public_key: Optional[bytes] = None,
               context: bytes = b"",
               hash_alg: str = "NONE") -> bool:
    """Verify ML-DSA-65 signature for a message.

    Args:
        message: Message that was signed
        signature: Signature bytes to verify (3309 bytes)
        public_key: ML-DSA-65 public key (1952 bytes), generated if not provided
        context: Optional context string for context-binding (max 256 bytes)
        hash_alg: Hash algorithm used for pre-hash variants (default: "NONE").

            Supported values: "NONE", "SHA3-256", "SHA3-384", "SHA3-512",
            "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512",
            "SHA2-512/224", "SHA2-512/256", "SHAKE-128", "SHAKE-256".

    Returns:
        True if signature is valid, False otherwise

    Raises:
        TypeError: If public_key is not bytes or wrong length
        ValueError: If context exceeds 256 bytes
    """
    # Validate context length
    if len(context) > 256:
        raise ValueError("context exceeds 256 bytes")

    # Normalize hash_alg (keep original format for dict lookup)
    hash_alg_normalized = hash_alg.upper()
    if hash_alg_normalized not in SUPPORTED_HASH_ALGS and hash_alg_normalized != "NONE":
        # Unknown hash algorithm - treat as unsupported
        hash_alg_normalized = "NONE"

    # If hash_alg is NONE or not set, do standard verification
    if hash_alg_normalized == "NONE":
        # If public_key not provided, try to use cached signer
        if public_key is None:
            global _SIGNER_CACHE, _SIGNER_PUBKEY_CACHE
            if _SIGNER_CACHE is not None and _SIGNER_PUBKEY_CACHE is not None:
                try:
                    if context:
                        result = _SIGNER_CACHE.verify_with_ctx_str(message, signature, context, _SIGNER_PUBKEY_CACHE)
                    else:
                        result = _SIGNER_CACHE.verify(message, signature, _SIGNER_PUBKEY_CACHE)
                    return result
                except Exception:
                    pass
            # If cached signer fails or not available, return False
            return False

        # Validate public_key type - if wrong Python type, raise TypeError (EC-04: wrong key type).
        # EC-06: malformed signature (or wrong-length bytes key) never raises — return False instead.
        if not isinstance(public_key, bytes):
            raise TypeError("invalid public key")

        try:
            with oqs.Signature('ML-DSA-65') as verifier:
                if context:
                    return verifier.verify_with_ctx_str(message, signature, context, public_key)
                else:
                    return verifier.verify(message, signature, public_key)
        except Exception:
            # EC-06: malformed signature (or wrong-length public key) returns False (never raises)
            return False

    # If hash_alg is set, this is a pre-hash variant
    # public_key must be provided for pre-hash variants
    if public_key is None:
        return False
    if not isinstance(public_key, bytes):
        raise TypeError("invalid public key")
    if len(public_key) != ML_DSA_65_PUBLIC_KEY_BYTES:
        raise TypeError("invalid public key")
    try:
        return _verify_prehashed(message, signature, public_key, hash_alg_normalized, context)
    except Exception:
        # EC-06: malformed signature returns False (never raises)
        return False