# crypto_utils.py
import os
import json
import base64
import zlib
from typing import Tuple, Dict, Any

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- Key generation and serialization ----------

def gen_signing_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    return sk, pk

def gen_x25519_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key()
    return sk, pk

def pubkey_bytes(obj) -> bytes:
    # returns raw public bytes for both ed25519 and x25519 public key objects
    return obj.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

# For compatibility we will use simple base64 text exports:
def serialize_public_key(pub) -> str:
    return base64.b64encode(pubkey_bytes(pub)).decode()

def deserialize_public_key_ed25519(b64: str) -> ed25519.Ed25519PublicKey:
    raw = base64.b64decode(b64)
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)

def deserialize_public_key_x25519(b64: str) -> x25519.X25519PublicKey:
    raw = base64.b64decode(b64)
    return x25519.X25519PublicKey.from_public_bytes(raw)

# ---------- Compression helper ----------

def compress_data(data: bytes) -> bytes:
    return zlib.compress(data)

def decompress_data(data: bytes) -> bytes:
    return zlib.decompress(data)

# ---------- Hybrid encryption (X25519 ephemeral -> AES-GCM) ----------

def derive_shared_key(eph_priv: x25519.X25519PrivateKey, recipient_pub: x25519.X25519PublicKey, info: bytes = b"secure-chat") -> bytes:
    shared = eph_priv.exchange(recipient_pub)  # raw 32 bytes
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared)  # AES-256 key

def aes_gcm_encrypt(aes_key: bytes, plaintext: bytes, aad: bytes = None) -> Tuple[bytes, bytes]:
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    # AESGCM returns ciphertext||tag. We'll package nonce and ct.
    return nonce, ct

def aes_gcm_decrypt(aes_key: bytes, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes = None) -> bytes:
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext_and_tag, aad)

# ---------- Signing helpers (Ed25519) ----------

def sign_bytes(priv: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    return priv.sign(data)

def verify_signature(pub: ed25519.Ed25519PublicKey, data: bytes, signature: bytes) -> bool:
    try:
        pub.verify(signature, data)
        return True
    except Exception:
        return False

# ---------- Package creation (serialize everything to JSON, base64-encoded) ----------

def package_message(eph_pub: x25519.X25519PublicKey, nonce: bytes, ciphertext_and_tag: bytes, signature: bytes, metadata: Dict[str, Any]) -> bytes:
    """Return bytes (UTF-8) of JSON containing base64 fields."""
    obj = {
        "eph_pub": base64.b64encode(pubkey_bytes(eph_pub)).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext_and_tag).decode(),
        "signature": base64.b64encode(signature).decode(),
        "metadata": metadata
    }
    return json.dumps(obj).encode()

def unpack_message(package_bytes: bytes) -> Dict[str, Any]:
    obj = json.loads(package_bytes.decode())
    return {
        "eph_pub": x25519.X25519PublicKey.from_public_bytes(base64.b64decode(obj["eph_pub"])),
        "nonce": base64.b64decode(obj["nonce"]),
        "ciphertext": base64.b64decode(obj["ciphertext"]),
        "signature": base64.b64decode(obj["signature"]),
        "metadata": obj["metadata"]
    }

# ---------- High-level send / receive helpers ----------

def sender_prepare_message(sender_sign_sk: ed25519.Ed25519PrivateKey,
                           recipient_x25519_pk: x25519.X25519PublicKey,
                           plaintext: bytes,
                           metadata: Dict[str, Any]) -> bytes:
    """
    Returns final package bytes (JSON base64 encoded) that will be embedded into an image.
    Steps: compress -> ECDH(ephemeral) -> derive AES key -> AES-GCM encrypt -> sign(ciphertext || metadata) -> package
    """
    # 1. compress plaintext
    compressed = compress_data(plaintext)

    # 2. ephemeral X25519 key and derive AES key
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key()
    aes_key = derive_shared_key(eph_priv, recipient_x25519_pk)

    # 3. AES-GCM encrypt compressed data (use metadata as AAD)
    aad = json.dumps(metadata).encode()
    nonce, ciphertext_and_tag = aes_gcm_encrypt(aes_key, compressed, aad=aad)

    # 4. Sign SHA256(ciphertext||aad) to authenticate sender and integrity
    sign_input = hashes_sha256(ciphertext_and_tag + aad)
    signature = sign_bytes(sender_sign_sk, sign_input)

    # 5. package fields (base64 JSON)
    package = package_message(eph_pub, nonce, ciphertext_and_tag, signature, metadata)
    return package

def recipient_process_package(recipient_x25519_sk: x25519.X25519PrivateKey,
                              sender_sign_pk: ed25519.Ed25519PublicKey,
                              package_bytes: bytes) -> bytes:
    """
    Reverse of sender_prepare_message.
    """
    obj = unpack_message(package_bytes)
    eph_pub = obj["eph_pub"]
    nonce = obj["nonce"]
    ciphertext_and_tag = obj["ciphertext"]
    signature = obj["signature"]
    metadata = obj["metadata"]
    aad = json.dumps(metadata).encode()

    # Verify signature first
    sign_input = hashes_sha256(ciphertext_and_tag + aad)
    if not verify_signature(sender_sign_pk, sign_input, signature):
        raise ValueError("Signature verification failed")

    # derive AES key via ECDH
    aes_key = derive_shared_key(recipient_x25519_sk, eph_pub)

    # decrypt
    compressed = aes_gcm_decrypt(aes_key, nonce, ciphertext_and_tag, aad=aad)

    # decompress
    plaintext = decompress_data(compressed)
    return plaintext

# ---------- small helpers ----------

def hashes_sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()
