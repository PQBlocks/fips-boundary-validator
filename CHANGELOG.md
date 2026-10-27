# Changelog: pqblocks-fips-check

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-10-26

### Added
- Hybrid key encapsulation combining X25519 (RFC 7748) and ML-KEM-768 (NIST FIPS 203).
- X-Wing dual PRF combiner with HKDF-SHA256 and context string binding.
- Digital signature operations using ML-DSA-65 (NIST FIPS 204) with context enforcement.
- Cryptographic Bill of Materials (CBOM) generator producing SPDX 2.2 documents with CNSA 2.0 grading.
- `PQCUnavailableError` exception hierarchy for strict cryptographic boundary enforcement.
- Comprehensive test suite with 87 passing tests covering unit logic, edge cases, and sizing constraints.
- Official test vector verification against NIST ACVP server and Google Wycheproof KAT corpora.
- Multi-version support across Python 3.11, 3.12, 3.13, and 3.14.
