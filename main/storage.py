# storage.py
import sqlite3
from typing import Optional

DB_FILE = "messages.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # Check if table exists
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'")
    if cur.fetchone():
        # Inspect schema
        cur.execute("PRAGMA table_info(messages)")
        columns = cur.fetchall()
        col_types = {col[1]: col[2].upper() for col in columns}

        # If timestamp or seed are INTEGER, recreate table as TEXT
        if col_types.get("timestamp") == "INTEGER" or col_types.get("seed") == "INTEGER":
            print("[storage] Found old schema with INTEGER fields. Recreating table...")
            cur.execute("ALTER TABLE messages RENAME TO old_messages")
            conn.commit()

            # Create new schema with TEXT for timestamp and seed
            cur.execute("""
            CREATE TABLE messages (
                id TEXT PRIMARY KEY,
                sender_id TEXT,
                recipient_id TEXT,
                timestamp TEXT,
                seed TEXT,
                blob BLOB
            )
            """)

            # Copy over old rows, casting timestamp+seed to TEXT
            cur.execute("""
            INSERT INTO messages (id, sender_id, recipient_id, timestamp, seed, blob)
            SELECT id, sender_id, recipient_id, CAST(timestamp AS TEXT), CAST(seed AS TEXT), blob
            FROM old_messages
            """)
            conn.commit()
            cur.execute("DROP TABLE old_messages")
            conn.commit()
    else:
        # Fresh DB
        cur.execute("""
        CREATE TABLE messages (
            id TEXT PRIMARY KEY,
            sender_id TEXT,
            recipient_id TEXT,
            timestamp TEXT,
            seed TEXT,
            blob BLOB
        )
        """)
        conn.commit()

    conn.close()


def store_message_blob(msg_id: str, sender_id: str, recipient_id: str,
                       timestamp, seed: int, blob: bytes):
    """Store message; force timestamp and seed to TEXT to avoid overflow."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO messages (id, sender_id, recipient_id, timestamp, seed, blob) VALUES (?, ?, ?, ?, ?, ?)",
        (msg_id, sender_id, recipient_id, str(timestamp), str(seed), blob)
    )
    conn.commit()
    conn.close()


def fetch_message_blob(msg_id: str) -> Optional[dict]:
    """Fetch message and auto-convert timestamp and seed back to int if possible."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT sender_id, recipient_id, timestamp, seed, blob FROM messages WHERE id=?", (msg_id,))
    row = cur.fetchone()
    conn.close()

    if row:
        sender_id, recipient_id, timestamp, seed, blob = row
        try:
            timestamp = int(timestamp)
        except (ValueError, TypeError):
            pass
        try:
            seed = int(seed)
        except (ValueError, TypeError):
            pass
        return {
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "timestamp": timestamp,
            "seed": seed,
            "blob": blob
        }
    return None
