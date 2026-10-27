# Security Notes: pqblocks-fips-check

This document describes the security posture, assumptions, and architectural properties of `pqblocks-fips-check`.

---

## 1. Cryptographic Primitive Delegation

`pqblocks-fips-check` deliberately avoids implementing mathematical lattice algorithms in pure Python. All primitive operations are delegated to established C libraries:
- **ML-KEM-768 & ML-DSA-65**: Delegated to Open Quantum Safe (`liboqs`), which provides constant-time, vector-optimized C implementations tested extensively against NIST reference KATs.
- **X25519 & HKDF-SHA256**: Delegated to `cryptography`, backed by OpenSSL 3.0+.

---

## 2. Hybrid Combiner Construction (X-Wing Pattern)

The hybrid KEM combines ML-KEM-768 and X25519 using an X-Wing style KDF construction:
```
shared_secret = HKDF-SHA256(
    salt = 0x00 * 32,
    ikm = mlkem_ss || x25519_ss || ephemeral_x25519_pk || recipient_x25519_pk,
    info = b"pqblocks_fips_check-hybrid-v1" || context
)
```
- **Dual PRF Security**: The shared secret is secure if *either* ML-KEM-768 or X25519 remains unbroken.
- **Context Binding**: The `context` string is folded into the HKDF `info` field, preventing cross-protocol key reuse and replay attacks across differing application domains.

---

## 3. Boundary Failure Model & Anti-Downgrade

- **Strict Boundary**: If the underlying PQC subsystem is missing or raises an unexpected fault, `pqblocks-fips-check` raises `PQCUnavailableError`.
- **No Insecure Fallback**: Classical fallback is strictly opt-in and handled explicitly by the application architecture, ensuring compliance with NSA CNSA 2.0 requirements.

---

## 4. Key Management & In-Memory Handling

- **Key Zeroization**: Python's garbage collection model does not guarantee immediate memory wiping. Highly sensitive environments requiring explicit key zeroization should use dedicated HSM/KMS hardware tokens.
- **Context Length**: Signatures enforce a maximum context length of 255 bytes per NIST FIPS 204 specification.

---

## 5. Non-FIPS Validation Notice

> [!IMPORTANT]
> `pqblocks-fips-check` is not validated under FIPS 140-3 and has not been submitted to the NIST CMVP program. It is designed for migration testing, research, and non-FIPS cryptographic agility.
