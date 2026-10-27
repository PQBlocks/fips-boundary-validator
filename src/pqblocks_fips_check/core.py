"""
pqblocks-fips-check.core - Core error types and utility functions
"""

from typing import Optional

class PQBlocksError(Exception):
    """Base exception for pqblocks_fips_check errors."""
    pass


class PQCUnavailableError(PQBlocksError):
    """Raised when post-quantum cryptography is unavailable and fallback is disabled."""
    pass


def validate_context(context: bytes) -> None:
    """
    Validate that context string is within allowed length.
    
    Args:
        context: Context string to validate
        
    Raises:
        ValueError: If context exceeds 256 bytes
    """
    if len(context) > 256:
        raise ValueError("context exceeds 256 bytes")


def seed_rng(seed: Optional[int]) -> None:
    """
    Seed the random number generator for deterministic test behavior.
    Note: This is test-only functionality. Production code should not use seeded RNG
    as it would make key material reproducible and potentially vulnerable.
    
    Args:
        seed: Optional seed value for deterministic randomness
    """
    # Note: Production code should NOT use seeded RNG as it would make
    # key material reproducible and potentially recoverable by attackers.
    # This is only for test reproducibility.
    pass  # Actual seeding would depend on the specific RNG being used