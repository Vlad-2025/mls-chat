import os
from operator import truediv

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# 1. Key generation

# X25519 for Key Exchange
alice_x_priv = X25519PrivateKey.generate()
alice_x_pub = alice_x_priv.public_key()

bob_x_priv = X25519PrivateKey.generate()
bob_x_pub = bob_x_priv.public_key()

# Ed25519 for signing (identity/authenticity)
alice_ed_priv = Ed25519PrivateKey.generate()
alice_ed_pub = alice_ed_priv.public_key()

print("Keys generated")

# 2. ECDH Key Exchange -> Elliptic Curve Diffie-Hellman:
# both sides compute the same shared secret without sending it over the network

alice_shared = alice_x_priv.exchange(bob_x_pub)
bob_shared = bob_x_priv.exchange(alice_x_pub)

assert alice_shared == bob_shared
print(f"Shared secret matches: {alice_shared.hex()[:16]}...")

# 3. HKDF -> HMAC-based Key Derivation Formula:
# raw shared secret isnt safe to use directly as an AES key -> HKDF cleans it

def derive_key(shared_secret: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info
    ).derive(shared_secret)

aes_key = derive_key(alice_shared, info=b"mls-chat-v1")
print(f"Derived AES key: {aes_key.hex()[:16]}...")

# 4. AES-256-GCM encryption

def encrypt(key: bytes, plaintext:str, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), associated_data)

    return nonce, ciphertext

def decrypt(key:bytes, nonce:bytes, ciphertext:bytes, associated_data: bytes = b"") -> str:
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)

    return plaintext.decode()

message = "hello bob"

nonce, ciphertext = encrypt(aes_key, message)
decrypted = decrypt(aes_key, nonce, ciphertext)

assert message == decrypted
print(f"Encrypted: {ciphertext.hex()[16:]} -> Decrypted: {decrypted}")

# 5. Signing and verification
# It validates that the sender really is the one who sent it

def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    return private_key.sign(data)

def verify(public_key, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(signature, data)
        return True

    except Exception:
        return False

signature = sign(alice_ed_priv, ciphertext) # sign with private key
valid = verify(alice_ed_pub, signature, ciphertext)

assert valid
print(f"Signature valid: {valid}")

# tamper check
tampered = verify(alice_ed_pub, signature, ciphertext + b"x")
print(f"Tempered signature, valid: {tampered}")

# 6. Serializing public keys: need to be sent over the network as bytes and reconstructed on the other side

pub_bytes = alice_x_pub.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

reconstructed = X25519PublicKey.from_public_bytes(pub_bytes)

# Verify they produce the same shared secret
shared_from_reconstructed = bob_x_priv.exchange(reconstructed)

assert shared_from_reconstructed == bob_shared # from the beginning

print(f"Key serialization works: {pub_bytes.hex()[:16]}...")

print("\nAll assertions passed - crypto primitives working")