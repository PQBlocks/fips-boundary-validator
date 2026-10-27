# pqblocks-fips-check

> FIPS 203/204 boundary validator and hybrid post-quantum key exchange (X25519 + ML-KEM-768) with ML-DSA-65 signatures and CBOM reporting.

[![CI](https://github.com/PQBlocks/fips-boundary-validator/actions/workflows/ci.yml/badge.svg)](https://github.com/PQBlocks/fips-boundary-validator/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## Overview

`pqblocks-fips-check` is a post-quantum cryptographic SDK and boundary validator implementing:
- **Hybrid Key Exchange**: Combines classical X25519 with NIST FIPS 203 ML-KEM-768 (X-Wing style combiner with HKDF-SHA256 fallback).
- **Digital Signatures**: NIST FIPS 204 ML-DSA-65 with strict context binding.
- **CBOM Reporting**: Generates composite bills of materials in SPDX 2.2 format with NIST algorithm OIDs and NSA CNSA 2.0 grading annotations.
- **Boundary Validation**: Enforces strict cryptographic boundary compliance, throwing `PQCUnavailableError` when post-quantum components are missing or degraded.

### Regulatory & Standards Alignment

- **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM-768).
- **NIST FIPS 204**: Module-Lattice-Based Digital Signature Standard (ML-DSA-65).
- **NSA CNSA 2.0**: Commercial National Security Algorithm Suite 2.0 mandates.
- **SPDX 2.2**: Software Package Data Exchange Specification with Cryptographic Asset Extensions.

> [!WARNING]
> **Regulatory Disclaimer**: `pqblocks-fips-check` is an independent open-source library. This software has **not** been certified under FIPS 140-3 and has **not** been submitted to NIST's Cryptographic Module Validation Program (CMVP).

---

## Installation

```bash
pip install pqblocks-fips-check
```

### System Dependencies

`pqblocks-fips-check` delegates low-level lattice operations to `liboqs` (C reference library) and elliptic curve operations to `cryptography` (OpenSSL-backed):

```bash
# Ubuntu/Debian
sudo apt-get install liboqs-dev

# macOS (Homebrew)
brew install liboqs
```

---

## Quickstart

```python
from pqblocks_fips_check import (
    hybrid_encap,
    hybrid_decap,
    sign,
    verify_sig,
    generate_cbom,
    PQCUnavailableError,
)
from pqblocks_fips_check.hybrid import hybrid_keygen

# 1. Hybrid key exchange (X25519 + ML-KEM-768)
alice_pk, alice_sk = hybrid_keygen()
bob_pk, bob_sk = hybrid_keygen()

# Alice encapsulates shared secret for Bob
ct, ss_alice = hybrid_encap(bob_pk, b"session-context")

# Bob decapsulates the ciphertext
_, ss_bob = hybrid_decap(bob_sk, ct)
assert ss_alice == ss_bob

# 2. ML-DSA-65 signature with context binding
sig = sign(b"Critical message payload", context=b"audit-auth")
assert verify_sig(b"Critical message payload", sig, context=b"audit-auth")

# 3. Export SPDX CBOM
cbom_json = generate_cbom()
assert "ML-KEM-768" in cbom_json and "ML-DSA-65" in cbom_json
```

---

## Performance Summary

Measured on Linux x86_64 across 500 timed runs per operation:

| Operation | Algorithm | Median Latency | P99 Latency | Throughput |
|---|---|---|---|---|
| Key Generation | X25519 + ML-KEM-768 | 0.076 ms | 0.096 ms | ~12,980 ops/sec |
| Encapsulation | X25519 + ML-KEM-768 | 0.172 ms | 0.252 ms | ~5,670 ops/sec |
| Decapsulation | X25519 + ML-KEM-768 | 0.148 ms | 0.172 ms | ~6,680 ops/sec |
| Sign | ML-DSA-65 | 0.098 ms | 0.345 ms | ~8,760 ops/sec |
| Verify | ML-DSA-65 | 0.044 ms | 0.058 ms | ~22,550 ops/sec |
| CBOM Generation | SPDX 2.2 JSON Export | 0.033 ms | 0.049 ms | ~29,460 ops/sec |

For complete benchmark methodology and profiling charts, see [BENCHMARKS.md](BENCHMARKS.md).

---

## Security & Verification

- **Official ACVP & Wycheproof Test Vectors**: Tested against official NIST ACVP server test vectors for ML-DSA-65 (`ML-DSA-sigVer-FIPS204`), ML-KEM-768 (`ML-KEM-encapDecap-FIPS203`), and Google Wycheproof vectors (`mldsa_65_verify`).
- **Cryptographic Boundary Protection**: Boundary errors are surfaced explicitly via `PQCUnavailableError` with zero silent downgrade to insecure classical fallbacks.
- **Constant-Time Primitives**: Underlying lattice operations are delegated to `liboqs` constant-time implementations.

For in-depth analysis and security considerations, see [SECURITY_NOTES.md](SECURITY_NOTES.md) and [TESTING.md](TESTING.md).

---

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
