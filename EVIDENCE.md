# Verification Evidence: pqblocks-fips-check

This document records the empirical verification evidence for `pqblocks-fips-check` (v0.1.0).

---

## Environment & Build Metadata

- **Package**: `pqblocks-fips-check`
- **Version**: `0.1.0`
- **Build Backend**: `setuptools>=77`
- **Wheel Artifact**: `pqblocks_fips_check-0.1.0-py3-none-any.whl`
- **Sdist Artifact**: `pqblocks_fips_check-0.1.0.tar.gz`
- **Date Verified**: 2026-10-26

---

## Test Execution Summary

Executed in isolated virtual environments across target Python versions:

```
platform linux -- Python 3.14.8, pytest-9.1.1, pluggy-1.6.0
rootdir: <repo>/packages/pqblocks-fips-check
configfile: pyproject.toml
testpaths: tests
plugins: hypothesis-6.168.0, cov-7.1.0, anyio-4.15.1
collected 87 items

tests/test_cbom.py .......                                               [  8%]
tests/test_core.py ....................                                  [ 31%]
tests/test_edge_cases.py ........                                        [ 40%]
tests/test_hybrid.py ..............                                      [ 56%]
tests/test_official_vectors.py ....                                      [ 60%]
tests/test_signature.py ..........                                       [ 72%]
tests/test_signature_edge_cases.py ..............                        [ 88%]
tests/test_sizes.py ..........                                           [100%]

======================= 87 passed, 24 warnings in 0.40s ========================
```

- **Python 3.11**: 87 passed in 0.42s
- **Python 3.12**: 87 passed in 0.41s
- **Python 3.13**: 87 passed in 0.42s
- **Python 3.14**: 87 passed in 0.40s

---

## FIPS 203/204 Sizing Assertions

All key and ciphertext sizes comply strictly with NIST specifications:

| Parameter | FIPS Standard | Expected Bytes | Verified Bytes | Status |
|---|---|---|---|---|
| ML-KEM-768 Public Key | FIPS 203 | 1184 | 1184 | PASS |
| ML-KEM-768 Secret Key | FIPS 203 | 2400 | 2400 | PASS |
| ML-KEM-768 Ciphertext | FIPS 203 | 1088 | 1088 | PASS |
| ML-KEM-768 Shared Secret | FIPS 203 | 32 | 32 | PASS |
| X25519 Public Key | RFC 7748 | 32 | 32 | PASS |
| X25519 Private Key | RFC 7748 | 32 | 32 | PASS |
| ML-DSA-65 Public Key | FIPS 204 | 1952 | 1952 | PASS |
| ML-DSA-65 Secret Key | FIPS 204 | 4032 | 4032 | PASS |
| ML-DSA-65 Signature | FIPS 204 | 3309 | 3309 | PASS |

---

## Package Integrity & Security Audit

- **`twine check --strict`**: PASSED (description and metadata valid).
- **Leak Gate Audit**: 28 files scanned, 0 hits (zero internal tokens, rules, or environment leaks).
- **Supply Chain**: Built with standard dependencies (`cryptography`, `liboqs-python`).
