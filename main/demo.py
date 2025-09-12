# demo.py
import os
import time
import base64
import hashlib
import uuid
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization

from crypto_utils import (
    gen_signing_keypair, gen_x25519_keypair,
    sender_prepare_message, recipient_process_package,
)
from stego import embed_bytes_into_png, extract_bytes_from_png
import storage

# --- small helpers to export/import public keys (base64) ---
def pubkey_to_b64(pub):
    # Works for both X25519PublicKey and Ed25519PublicKey
    return base64.b64encode(pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()

def pubkey_from_b64_x25519(b64: str):
    raw = base64.b64decode(b64.encode())
    return x25519.X25519PublicKey.from_public_bytes(raw)

def pubkey_from_b64_ed25519(b64: str):
    raw = base64.b64decode(b64.encode())
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)

# A tiny demo sending and receiving a message
def run_demo():
    storage.init_db()

    # --- generate keys for Alice (sender) and Bob (recipient) ---
    alice_sign_sk, alice_sign_pk = gen_signing_keypair()
    alice_x_sk, alice_x_pk = gen_x25519_keypair()

    bob_sign_sk, bob_sign_pk = gen_signing_keypair()
    bob_x_sk, bob_x_pk = gen_x25519_keypair()

    # share public keys (in real system they'd be in directory)
    alice_sign_pub_b64 = pubkey_to_b64(alice_sign_pk)
    alice_x_pub_b64 = pubkey_to_b64(alice_x_pk)
    bob_sign_pub_b64 = pubkey_to_b64(bob_sign_pk)
    bob_x_pub_b64 = pubkey_to_b64(bob_x_pk)

    # load cover image bytes (must be a PNG with enough size). Put a file "cover.png" in the same folder.
    cover_path = Path("cover.png")
    if not cover_path.exists():
        print("ERROR: put a PNG image named cover.png in the working directory (enough resolution).")
        return
    cover_bytes = cover_path.read_bytes()

    # --- Alice sends a message to Bob ---
    plaintext = b"Hello Bob, this is Alice. Confidential corporate message."
    metadata = {
        "sender": "alice",
        "recipient": "bob",
        "timestamp": int(time.time())
    }

    # seed for pseudo-random embedding: derive from message id
    msg_id = str(uuid.uuid4())
    seed = int.from_bytes(hashlib.sha256(msg_id.encode()).digest()[:8], "big")  # 64-bit int

    # Prepare package (compress -> ECDH(ephemeral) -> AES-GCM -> sign -> package JSON)
    bob_x_pub = bob_x_pk
    package_bytes = sender_prepare_message(alice_sign_sk, bob_x_pub, plaintext, metadata)

    # Embed into cover image (LSB)
    stego_png = embed_bytes_into_png(cover_bytes, package_bytes, seed=seed)

    # --- NEW: compress the stego PNG BEFORE storing/transferring ---
    compressed_stego = zlib.compress(stego_png)

    # Store in DB (we store the seed for extraction)
    storage.store_message_blob(msg_id, "alice", "bob", int(time.time()), seed, compressed_stego)
    print(f"Message stored with id {msg_id}")

    # --- Bob receives the message ---
    rec = storage.fetch_message_blob(msg_id)
    if not rec:
        print("message not found")
        return

    # rec["blob"] is compressed stego bytes; decompress before extraction
    compressed_blob = rec["blob"]
    try:
        stored_stego_png = zlib.decompress(compressed_blob)
    except Exception as e:
        print("Failed to decompress stored blob:", e)
        return

    stored_seed = rec["seed"]

    # Extract package bytes from stego (PNG)
    extracted_pkg = extract_bytes_from_png(stored_stego_png, seed=stored_seed)

    # Bob reconstructs sender public key (in real world, verify from directory)
    alice_sign_pub = alice_sign_pk

    # Process package: verify signature -> derive AES key -> decrypt -> decompress
    decrypted = recipient_process_package(bob_x_sk, alice_sign_pub, extracted_pkg)
    print("Decrypted plaintext:", decrypted.decode())

if __name__ == "__main__":
    run_demo()
