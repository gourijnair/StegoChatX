# StegoChatX
A real-time platform for enhanced privacy and security in corporate messaging.

Our goal here is to create a secure yet simple communication system using the power of AES enhanced with ECC key exchange and user authentication and steganography.
In this system, when commmunication is going in between two users, the messages will be ecjcrypted using the AES and the keys will be exchanged using ECC which will also verify or authenticate the user i.e the client.

This encryoted message will now be compressed and integrated in an image which will be stored in the database and thus the actual transaction of the communication will be hidden.


Here’s a **README.md** you can drop into your project root (`secure_chat/`).
It explains the methodology, dependencies, usage, and workflow clearly.

---

```markdown
# Secure Corporate Communication System

This project is a prototype implementation of a **secure corporate communication system** using:

- **AES-256-GCM** for message encryption (confidentiality & integrity).
- **X25519** for key exchange (forward secrecy).
- **Ed25519** for sender authentication (digital signatures).
- **Steganography (LSB in PNG)** to hide the encrypted package inside an image.
- **Compression (zlib)** for both plaintext messages and stego-images before storage.
- **SQLite3 database** for storing compressed stego-images (blobs) with metadata.

⚡ The goal is to demonstrate the **methodology**, not to build a production-ready WhatsApp clone.

---

## 📌 Workflow

### Sender
1. User types a plaintext message.
2. Message is **compressed** (zlib).
3. Sender generates an **ephemeral X25519 keypair**.
4. Derives a shared AES key with recipient's X25519 public key (ECDH + HKDF).
5. Encrypts the compressed message using **AES-256-GCM** (nonce + ciphertext + tag).
6. Signs the hash of `(ciphertext || metadata)` using sender’s **Ed25519 private key**.
7. Packages everything into a JSON object.
8. Embeds the JSON package into a PNG **cover image** using steganography.
9. Compresses the stego-image (zlib).
10. Stores the compressed blob + metadata in the database.

### Receiver
1. Fetches the compressed stego-image blob from the database.
2. **Decompresses** it to recover the stego-image.
3. Extracts the JSON package from the image.
4. Verifies the **Ed25519 signature** (authentic sender, integrity).
5. Derives the AES key using recipient’s X25519 private key + sender’s ephemeral pubkey.
6. Decrypts the ciphertext using **AES-GCM**.
7. **Decompresses** the plaintext.
8. Displays the final message.

---

## 📂 Project Structure

```

secure\_chat/
│
├── crypto\_utils.py   # AES, X25519, Ed25519, hybrid crypto, compression
├── stego.py          # LSB image steganography (embed/extract)
├── storage.py        # SQLite3 database for storing compressed blobs
├── demo.py           # Demo pipeline (send → store → fetch → receive)
├── messages.db       # SQLite DB (auto-created)
└── README.md         # Project documentation

````

---

## ⚙️ Dependencies

Install dependencies with:

```bash
pip install cryptography pillow
````

* **cryptography** → AES-GCM, X25519, Ed25519
* **Pillow** → image handling (PNG stego)
* **SQLite3** → Python built-in (no extra install needed)

---

## ▶️ Running the Demo

1. Make sure dependencies are installed.
2. Run the demo script:

```bash
python demo.py
```

3. Expected flow:

   * Generates keys for Alice (sender) and Bob (recipient).
   * Encrypts + embeds Alice’s message in a PNG.
   * Compresses and stores the stego-image in `messages.db`.
   * Fetches the blob back.
   * Decompresses, extracts, verifies, decrypts, and prints Bob’s received message.

Sample output:

```
Message stored with id cad3bdee-fff7-4a62-b1ba-44904a602278
Bob received message: Hello Bob, this is a secure test message!
```

---

## 🛠 Database Schema

The `messages` table:

```sql
CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    sender_id TEXT,
    recipient_id TEXT,
    timestamp TEXT,
    seed TEXT,
    blob BLOB
);
```

* **id** → unique UUID for each message
* **sender\_id / recipient\_id** → user identifiers
* **timestamp** → message creation time (stringified int)
* **seed** → pseudo-random seed used in stego embedding
* **blob** → compressed PNG stego-image

---

## 🔒 Security Notes

* Each message uses a **new ephemeral X25519 keypair** → ensures **forward secrecy**.
* AES-GCM ensures **confidentiality + integrity**.
* Ed25519 ensures **authenticity** of sender.
* Steganography hides the presence of communication.
* Compression reduces storage/transmission overhead.
* Database stores only **compressed stego-images**, not plaintext or ciphertext.

---

## 🚀 Future Enhancements

* Use **more advanced stego** (edge-adaptive, matrix encoding).
* Replace zlib with **zstd** or **brotli** for better compression.
* Add message **chunking** for larger texts.
* Add **key revocation** and PKI for managing user keys.
* Add **web/API layer** for multi-user messaging.

---

## 👨‍💻 Authors

* **
Anurag Paul
Abdur
* ** – 7th Sem Cyber Security Project
