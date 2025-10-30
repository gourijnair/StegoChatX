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
    print("=" * 80)
    print("SECURE CHAT APPLICATION - STEP BY STEP DEMONSTRATION")
    print("=" * 80)
    print("\nThis application demonstrates:")
    print("1. Text Encryption (X25519 + AES-GCM)")
    print("2. Data Compression (zlib)")
    print("3. Steganography (LSB in PNG images)")
    print("4. Digital Signatures (Ed25519)")
    print("5. Database Storage (SQLite)")
    print("=" * 80)
    
    print("\n[STEP 1] Initializing Database...")
    storage.init_db()
    print("✓ Database initialized successfully")

    # --- generate keys for Alice (sender) and Bob (recipient) ---
    print("\n[STEP 2] Generating Cryptographic Keys...")
    print("-" * 50)
    
    print("\n🔑 Generating keys for ALICE (Sender):")
    alice_sign_sk, alice_sign_pk = gen_signing_keypair()
    print(f"  • Ed25519 Signing Private Key: {alice_sign_sk}")
    print(f"  • Ed25519 Signing Public Key: {alice_sign_pk}")
    
    alice_x_sk, alice_x_pk = gen_x25519_keypair()
    print(f"  • X25519 Private Key: {alice_x_sk}")
    print(f"  • X25519 Public Key: {alice_x_pk}")

    print("\n🔑 Generating keys for BOB (Recipient):")
    bob_sign_sk, bob_sign_pk = gen_signing_keypair()
    print(f"  • Ed25519 Signing Private Key: {bob_sign_sk}")
    print(f"  • Ed25519 Signing Public Key: {bob_sign_pk}")
    
    bob_x_sk, bob_x_pk = gen_x25519_keypair()
    print(f"  • X25519 Private Key: {bob_x_sk}")
    print(f"  • X25519 Public Key: {bob_x_pk}")
    print("✓ All cryptographic keys generated successfully")


    # share public keys (in real system they'd be in directory)
    print("\n[STEP 3] Converting Public Keys to Base64 for Exchange...")
    print("-" * 50)
    alice_sign_pub_b64 = pubkey_to_b64(alice_sign_pk)
    alice_x_pub_b64 = pubkey_to_b64(alice_x_pk)
    bob_sign_pub_b64 = pubkey_to_b64(bob_sign_pk)
    bob_x_pub_b64 = pubkey_to_b64(bob_x_pk)

    print(f"  • Alice's Ed25519 Public Key (Base64): {alice_sign_pub_b64}")
    print(f"  • Alice's X25519 Public Key (Base64): {alice_x_pub_b64}")
    print(f"  • Bob's Ed25519 Public Key (Base64): {bob_sign_pub_b64}")
    print(f"  • Bob's X25519 Public Key (Base64): {bob_x_pub_b64}")
    print("✓ Public keys converted to Base64 format for exchange")

    # load cover image bytes (must be a PNG with enough size). Put a file "cover.png" in the same folder.
    print("\n[STEP 4] Loading Cover Image for Steganography...")
    print("-" * 50)
    cover_path = Path("cover.png")
    import matplotlib.pyplot as plt

    if not cover_path.exists():
        print("❌ ERROR: Please place a PNG image named 'cover.png' in the working directory")
        print("   The image should have sufficient resolution to embed the message")
        return
    
    print(f"  • Cover image found: {cover_path}")
    cover_bytes = cover_path.read_bytes()
    print(f"  • Cover image size: {len(cover_bytes)} bytes")
    
    # Display the cover image
    img = plt.imread(cover_path)
    plt.figure(figsize=(8, 6))
    plt.imshow(img)
    plt.title("Cover Image (Before Steganography)")
    plt.axis('off')
    plt.show()
    print("✓ Cover image loaded and displayed successfully")

    # --- Alice sends a message to Bob ---
    print("\n[STEP 5] Message Preparation and Encryption...")
    print("-" * 50)
    plaintext = input("\n💬 Enter a message to send: ")
    plaintext_bytes = plaintext.encode('utf-8')  # Converts string to bytes
    print(f"  • Original message: '{plaintext}'")
    print(f"  • Message as bytes: {plaintext_bytes}")
    print(f"  • Message size: {len(plaintext_bytes)} bytes")
    
    metadata = {
        "sender": "alice",
        "recipient": "bob",
        "timestamp": int(time.time())
    }
    print(f"  • Message metadata: {metadata}")

    # seed for pseudo-random embedding: derive from message id
    msg_id = str(uuid.uuid4())
    seed = int.from_bytes(hashlib.sha256(msg_id.encode()).digest()[:8], "big")  # 64-bit int
    print(f"  • Message ID: {msg_id}")
    print(f"  • Steganography seed: {seed}")

    # Prepare package (compress -> ECDH(ephemeral) -> AES-GCM -> sign -> package JSON)
    print("\n[STEP 6] Encrypting Message...")
    print("-" * 50)
    bob_x_pub = bob_x_pk
    package_bytes = sender_prepare_message(alice_sign_sk, bob_x_pub, plaintext_bytes, metadata)
    print(f"  • Encrypted package size: {len(package_bytes)} bytes")

    # Embed into cover image (LSB)
    print("\n[STEP 7] Embedding Encrypted Message into Image...")
    print("-" * 50)
    stego_png = embed_bytes_into_png(cover_bytes, package_bytes, seed=seed)
    print(f"  • Stego image size: {len(stego_png)} bytes")
    print(f"  • Size increase: {len(stego_png) - len(cover_bytes)} bytes")

    # --- NEW: compress the stego PNG BEFORE storing/transferring ---
    print("\n[STEP 8] Compressing Stego Image...")
    print("-" * 50)
    compressed_stego = zlib.compress(stego_png)
    print(f"  • Compressed stego size: {len(compressed_stego)} bytes")
    compression_ratio = (1 - len(compressed_stego) / len(stego_png)) * 100
    print(f"  • Compression ratio: {compression_ratio:.2f}%")

    # Store in DB (we store the seed for extraction)
    print("\n[STEP 9] Storing Message in Database...")
    print("-" * 50)
    storage.store_message_blob(msg_id, "alice", "bob", int(time.time()), seed, compressed_stego)
    print(f"  • Message stored with ID: {msg_id}")
    print("✓ Message successfully stored in database")

    # --- Bob receives the message ---
    print("\n[STEP 10] Bob Retrieving Message from Database...")
    print("-" * 50)
    rec = storage.fetch_message_blob(msg_id)
    if not rec:
        print("❌ ERROR: Message not found in database")
        return
    
    print(f"  • Retrieved message ID: {msg_id}")
    print(f"  • Sender: {rec['sender_id']}")
    print(f"  • Recipient: {rec['recipient_id']}")
    print(f"  • Timestamp: {rec['timestamp']}")
    print(f"  • Seed: {rec['seed']}")
    print(f"  • Compressed blob size: {len(rec['blob'])} bytes")

    # rec["blob"] is compressed stego bytes; decompress before extraction
    print("\n[STEP 11] Decompressing Stored Message...")
    print("-" * 50)
    compressed_blob = rec["blob"]
    try:
        stored_stego_png = zlib.decompress(compressed_blob)
        print(f"  • Decompressed stego size: {len(stored_stego_png)} bytes")
        print("✓ Message decompressed successfully")
    except Exception as e:
        print(f"❌ ERROR: Failed to decompress stored blob: {e}")
        return

    stored_seed = rec["seed"]

    # Extract package bytes from stego (PNG)
    print("\n[STEP 12] Extracting Message from Stego Image...")
    print("-" * 50)
    extracted_pkg = extract_bytes_from_png(stored_stego_png, seed=stored_seed)
    print(f"  • Extracted package size: {len(extracted_pkg)} bytes")
    print("✓ Message extracted from stego image successfully")

    # Bob reconstructs sender public key (in real world, verify from directory)
    print("\n[STEP 13] Bob Decrypting and Verifying Message...")
    print("-" * 50)
    alice_sign_pub = alice_sign_pk

    # Process package: verify signature -> derive AES key -> decrypt -> decompress
    decrypted = recipient_process_package(bob_x_sk, alice_sign_pub, extracted_pkg)
    print(f"  • Decrypted plaintext: {decrypted.decode()}")
    print("✓ Message decrypted and verified successfully")
    
    print("\n" + "=" * 80)
    print("🎉 SECURE MESSAGE TRANSMISSION COMPLETED SUCCESSFULLY! 🎉")
    print("=" * 80)
    print(f"Final Message: '{decrypted.decode()}'")
    print("=" * 80)

if __name__ == "__main__":
    run_demo()
