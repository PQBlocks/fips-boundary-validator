# Testing & Test Suite: pqblocks-fips-check

This document outlines the testing strategy, test coverage, and execution instructions for `pqblocks-fips-check`.

---

## Test Organization

The test suite comprises 8 test modules covering 87 unit, integration, edge case, and vector tests:

| Module | Description | Test Count |
|---|---|---|
| `test_cbom.py` | SPDX 2.2 schema compliance, OID validation, CNSA 2.0 grade mapping, and deterministic generation | 7 |
| `test_core.py` | Exception hierarchy, `PQCUnavailableError`, context validation, seed determinism | 20 |
| `test_edge_cases.py` | Context boundary conditions, invalid key lengths, malformed encap payloads | 8 |
| `test_hybrid.py` | Hybrid key exchange (X25519 + ML-KEM-768), encapsulation/decapsulation roundtrips | 14 |
| `test_official_vectors.py` | NIST ACVP FIPS 203 & 204 vectors, Google Wycheproof ML-DSA-65 vector verification | 4 |
| `test_signature.py` | ML-DSA-65 key generation, signing, and verification | 10 |
| `test_signature_edge_cases.py` | Signature corruptions, truncated context, invalid public keys, invalid parameter sets | 14 |
| `test_sizes.py` | Strict byte size constants compliance with NIST FIPS 203 and 204 specifications | 10 |

**Total Tests**: 87 passing.

---

## Code Coverage

Measured across CPython 3.14:

| Module | Statements | Missing | Coverage |
|---|---|---|---|
| `src/pqblocks_fips_check/__init__.py` | 6 | 0 | 100% |
| `src/pqblocks_fips_check/cbom.py` | 32 | 1 | 97% |
| `src/pqblocks_fips_check/core.py` | 10 | 0 | 100% |
| `src/pqblocks_fips_check/hybrid.py` | 164 | 5 | 97% |
| `src/pqblocks_fips_check/signature.py` | 135 | 21 | 84% |
| **TOTAL** | **347** | **27** | **92%** |

---

## Official Vectors Verification

The package vendors and tests against official NIST and industry KAT corpora:

1. **NIST ACVP `ML-DSA-sigVer-FIPS204`**: Message-form ML-DSA-65 signatures with `pure` pre-hashing and `external` interface.
2. **NIST ACVP `ML-KEM-encapDecap-FIPS203`**: Parameter set ML-KEM-768 decapsulation test vectors.
3. **Google Wycheproof `mldsa_65_verify`**: Strict boundary checks, non-canonical encodings, and edge cases.

---

## Running Tests

### Standard Test Execution

```bash
pytest tests/
```

### With Coverage Measurement

```bash
pytest --cov=pqblocks_fips_check --cov-report=term-missing tests/
```
