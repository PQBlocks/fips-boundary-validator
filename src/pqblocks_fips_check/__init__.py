"""
pqblocks-fips-check - Post-quantum cryptographic SDK

Hybrid key exchange (X25519 + ML-KEM-768) + ML-DSA-65 signatures + CBOM generation.
"""

__version__ = "0.1.0"

from .hybrid import hybrid_encap, hybrid_decap
from .signature import sign, verify_sig
from .cbom import generate_cbom
from .core import PQCUnavailableError, PQBlocksError

__all__ = [
    "hybrid_encap",
    "hybrid_decap",
    "sign",
    "verify_sig",
    "generate_cbom",
    "PQCUnavailableError",
    "PQBlocksError",
]
