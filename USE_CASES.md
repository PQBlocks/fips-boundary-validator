# Use Cases & Integration Patterns: pqblocks-fips-check

This document describes primary integration architectures and practical patterns for `pqblocks-fips-check`.

---

## 1. Enterprise Post-Quantum Hybrid TLS & API Gateways

### Challenge
Enterprises must migrate public and internal API endpoints to quantum-safe cryptography while maintaining backwards compatibility and protecting against "Harvest Now, Decrypt Later" (HNDL) adversaries.

### Solution
Use `hybrid_keygen()`, `hybrid_encap()`, and `hybrid_decap()` to establish a hybrid session key combining classical X25519 (for current security guarantees) and ML-KEM-768 (for quantum resistance). If either component remains unbroken, the shared secret remains confidential.

```python
from pqblocks_fips_check import hybrid_encap, hybrid_decap
from pqblocks_fips_check.hybrid import hybrid_keygen

# Server generates long-term or ephemeral hybrid keypair
server_pk, server_sk = hybrid_keygen()

# Client encapsulates session key
ciphertext, client_shared_secret = hybrid_encap(server_pk, context=b"api-gateway-v1")

# Server decapsulates session key
_, server_shared_secret = hybrid_decap(server_sk, ciphertext)

# Both parties use derived 256-bit key for AES-256-GCM transport encryption
assert client_shared_secret == server_shared_secret
```

---

## 2. Cryptographic Boundary Validation & Enforcement

### Challenge
Security policies often mandate that post-quantum cryptography is actively enforced and never silently downgraded when dependencies or hardware modules fail.

### Solution
`pqblocks-fips-check` enforces strict boundary rules. When underlying PQC support is absent, it throws `PQCUnavailableError` instead of transparently degrading to classical-only crypto.

```python
from pqblocks_fips_check import PQCUnavailableError, hybrid_encap

try:
    ciphertext, shared_secret = hybrid_encap(peer_pk, context=b"regulated-zone")
except PQCUnavailableError as e:
    # Explicitly alert security orchestration; prevent classical fallback
    log.critical(f"PQC Boundary Violation: {e}")
    terminate_session(status=403)
```

---

## 3. Automated Cryptographic Bill of Materials (CBOM) Generation

### Challenge
Federal procurement guidelines (such as OMB M-23-02 and NSA CNSA 2.0) require transparent inventorying of all cryptographic algorithms and dependencies within microservices.

### Solution
Use `generate_cbom()` to produce machine-readable SPDX 2.2 documents containing exact algorithm parameter sets, CNSA 2.0 migration grades, and NIST OIDs.

```python
from pqblocks_fips_check import generate_cbom

# Automated CI pipeline step
spdx_cbom = generate_cbom()

with open("dist/crypto_inventory.spdx.json", "w") as f:
    f.write(spdx_cbom)
```
