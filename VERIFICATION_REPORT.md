# Verification Report: pqblocks-fips-check (v0.1.0)

**Date**: 2026-10-26  
**Auditor**: PQBlocks Independent Release Pipeline  
**Target**: `pqblocks-fips-check` (FIPS 203/204 Boundary Validator and Hybrid Key Exchange SDK)

---

## 1. Executive Summary

`pqblocks-fips-check` (v0.1.0) has passed all release verification gates:
- **Build & Packaging**: Clean sdist and wheel built; `twine check --strict` passed.
- **Cross-Version Runtime**: Verified across Python 3.11, 3.12, 3.13, and 3.14.
- **Test Integrity**: 87 of 87 tests passed across all target Python versions.
- **Examples**: Both `quickstart.py` and `02_fips_boundary_check.py` executed successfully.
- **Public Hygiene**: Zero leakage of internal tokens, paths, or development artifacts.

---

## 2. Gate Verification Details

| Gate / Check | Target | Result | Evidence |
|---|---|---|---|
| Build Artifacts | `dist/*.whl`, `dist/*.tar.gz` | PASS | `Successfully built dist/pqblocks_fips_check-0.1.0-py3-none-any.whl` |
| PyPI Metadata | `twine check --strict` | PASS | Strict metadata check PASSED |
| Python 3.11 Test Suite | 87 tests | PASS | 87 passed in 0.42s |
| Python 3.12 Test Suite | 87 tests | PASS | 87 passed in 0.41s |
| Python 3.13 Test Suite | 87 tests | PASS | 87 passed in 0.42s |
| Python 3.14 Test Suite | 87 tests | PASS | 87 passed in 0.40s |
| Python 3.11 Example 1 | `quickstart.py` | PASS | Exit code 0 |
| Python 3.11 Example 2 | `02_fips_boundary_check.py` | PASS | Exit code 0 |
| Python 3.12 Example 1 | `quickstart.py` | PASS | Exit code 0 |
| Python 3.12 Example 2 | `02_fips_boundary_check.py` | PASS | Exit code 0 |
| Python 3.13 Example 1 | `quickstart.py` | PASS | Exit code 0 |
| Python 3.13 Example 2 | `02_fips_boundary_check.py` | PASS | Exit code 0 |
| Python 3.14 Example 1 | `quickstart.py` | PASS | Exit code 0 |
| Python 3.14 Example 2 | `02_fips_boundary_check.py` | PASS | Exit code 0 |
| Leak Gate | Package directory, wheel, sdist | PASS | 0 leak hits across 28 files |
| Required Files | Governance, CI, legal, docs | PASS | All 18 standard files present |

---

## 3. Scope & Non-Claims

1. **Non-FIPS 140-3 Validation**: This software is not itself a FIPS 140-3 validated cryptographic module and has not undergone CMVP evaluation.
2. **Standard Primitive Delegation**: Underlying primitives delegate to `liboqs` and `cryptography` (OpenSSL 3.0+). No custom mathematical lattice implementations are contained within this Python layer.
3. **No Unauthenticated Downgrades**: Boundary validation strictly enforces that if post-quantum key encapsulation or signing fails, `PQCUnavailableError` is raised rather than silently degrading security.

---

## 4. Release Recommendation

**VERIFIED FOR RELEASE**: Meets all functional, performance, security, and documentation standards.
