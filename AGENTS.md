# AI & Automation Guide: pqblocks-fips-check

This guide provides operational patterns and constraints for AI agents interacting with or generating code using `pqblocks-fips-check`.

---

## Package Overview & Imports

```python
from pqblocks_fips_check import (
    hybrid_encap,
    hybrid_decap,
    sign,
    verify_sig,
    generate_cbom,
    PQCUnavailableError,
    PQBlocksError,
)
from pqblocks_fips_check.hybrid import hybrid_keygen
```

---

## Safe Coding Patterns

### 1. Generating Hybrid Keypairs
Always unpack into public and secret keys:
```python
pk, sk = hybrid_keygen()
# len(pk) == 1216 bytes (32 bytes X25519 + 1184 bytes ML-KEM-768)
# len(sk) == 2432 bytes (32 bytes X25519 + 2400 bytes ML-KEM-768)
```

### 2. Encapsulation & Decapsulation
Always provide a domain-specific context string:
```python
ciphertext, shared_secret = hybrid_encap(peer_pk, context=b"unique-protocol-domain")
# len(ciphertext) == 1120 bytes (32 bytes X25519 + 1088 bytes ML-KEM-768)
# len(shared_secret) == 32 bytes (256-bit key for AES-GCM)

_, recovered_ss = hybrid_decap(sk, ciphertext)
assert shared_secret == recovered_ss
```

### 3. Signing & Verification
Always bind signatures to explicit context strings where available:
```python
signature = sign(data, secret_key=signer_sk, context=b"doc-approval")
# len(signature) == 3309 bytes (FIPS 204 ML-DSA-65)

is_valid = verify_sig(data, signature, public_key=signer_pk, context=b"doc-approval")
```

### 4. Exception Handling
Always catch `PQCUnavailableError` explicitly when handling boundary compliance:
```python
try:
    ct, ss = hybrid_encap(peer_pk)
except PQCUnavailableError:
    # Log and handle missing PQC subsystem gracefully
    handle_pqc_failure()
```

---

## Prohibited Patterns

1. **Do NOT Hand-Roll Hybrid Combiners**: Never concatenate shared secrets or use simple XOR without a cryptographic KDF. Always use `hybrid_encap`/`hybrid_decap`.
2. **Do NOT Silence Boundary Exceptions**: Never catch `PQCUnavailableError` and fall back silently to unauthenticated classical crypto without alerting security policy.
3. **Do NOT Pass Contexts > 255 Bytes**: FIPS 204 restricts signature context strings to 255 bytes max.
