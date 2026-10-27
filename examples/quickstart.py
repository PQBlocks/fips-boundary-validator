from pqblocks_fips_check import hybrid_encap, hybrid_decap, sign, verify_sig, generate_cbom
from pqblocks_fips_check.hybrid import hybrid_keygen

# Hybrid key exchange: X25519 + ML-KEM-768
alice_pk, alice_sk = hybrid_keygen()  # Alice's key pair
bob_pk, bob_sk = hybrid_keygen()      # Bob's key pair

# Encapsulate to Bob
ct, ss = hybrid_encap(bob_pk, b"Hybrid shared secret for AES-GCM")
# Decapsulate by Bob
msg, ss_recipient = hybrid_decap(bob_sk, ct)
assert ss == ss_recipient  # Shared secret matches

# ML-DSA-65 signature (auto-generates keypair when secret_key is not supplied)
signature = sign(b"Message to sign")
assert verify_sig(b"Message to sign", signature)  # Valid signature

# CBOM generation
cbom_json = generate_cbom()
assert '"ML-KEM-768"' in cbom_json and '"ML-DSA-65"' in cbom_json
