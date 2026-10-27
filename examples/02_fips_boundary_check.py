"""Demonstrate FIPS 203/204 hybrid key exchange and boundary validation."""
import json
from pqblocks_fips_check import (
    hybrid_encap,
    hybrid_decap,
    sign,
    verify_sig,
    generate_cbom,
    PQCUnavailableError,
)
from pqblocks_fips_check.hybrid import hybrid_keygen

def main():
    print("1. Generating hybrid key pairs (X25519 + ML-KEM-768)...")
    alice_pk, alice_sk = hybrid_keygen()
    bob_pk, bob_sk = hybrid_keygen()
    print(f"   Alice PK size: {len(alice_pk)} bytes")
    print(f"   Bob PK size: {len(bob_pk)} bytes")

    print("\n2. Encapsulating to Bob...")
    ct, ss_alice = hybrid_encap(bob_pk, b"context-bound-hybrid-session-2026")
    print(f"   Ciphertext size: {len(ct)} bytes")
    print(f"   Derived shared secret (Alice): {ss_alice.hex()[:32]}...")

    print("\n3. Decapsulating by Bob...")
    _, ss_bob = hybrid_decap(bob_sk, ct)
    print(f"   Derived shared secret (Bob):   {ss_bob.hex()[:32]}...")
    assert ss_alice == ss_bob, "Shared secret mismatch!"
    print("   -> Shared secrets match perfectly!")

    print("\n4. ML-DSA-65 Digital Signature with context binding...")
    message = b"FIPS 204 Authorization Token"
    ctx = b"audit-log-service"
    sig = sign(message, context=ctx)
    valid = verify_sig(message, sig, context=ctx)
    print(f"   Signature verified: {valid}")
    assert valid, "Signature verification failed!"

    print("\n5. CBOM SPDX Export...")
    cbom_str = generate_cbom()
    cbom = json.loads(cbom_str)
    print(f"   SPDX document: {cbom.get('name')}")
    print(f"   External refs (crypto properties): {len(cbom.get('externalRefs', []))}")
    print("FIPS boundary check completed successfully.")

if __name__ == "__main__":
    main()
