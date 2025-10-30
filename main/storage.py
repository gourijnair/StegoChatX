# storage.py
import sqlite3
from typing import Optional

DB_FILE = "messages.db"

def init_db():
    print("    💾 DATABASE - INITIALIZATION PROCESS")
    print("    " + "=" * 45)
    
    print("    [5.1] Connecting to SQLite database...")
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    print(f"        • Database file: {DB_FILE}")
    print("        ✓ Database connection established")

    # Check if table exists
    print("\n    [5.2] Checking for existing messages table...")
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'")
    table_exists = cur.fetchone()
    
    if table_exists:
        print("        • Messages table found")
        print("\n    [5.3] Inspecting table schema...")
        # Inspect schema
        cur.execute("PRAGMA table_info(messages)")
        columns = cur.fetchall()
        col_types = {col[1]: col[2].upper() for col in columns}
        print(f"        • Table columns: {list(col_types.keys())}")
        print(f"        • Column types: {col_types}")

        # If timestamp or seed are INTEGER, recreate table as TEXT
        if col_types.get("timestamp") == "INTEGER" or col_types.get("seed") == "INTEGER":
            print("\n    [5.4] Updating schema (converting INTEGER to TEXT)...")
            print("        • Found old schema with INTEGER fields")
            print("        • Recreating table with TEXT fields for better compatibility")
            
            cur.execute("ALTER TABLE messages RENAME TO old_messages")
            conn.commit()
            print("        • Old table renamed to 'old_messages'")

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
            print("        • New table schema created")

            # Copy over old rows, casting timestamp+seed to TEXT
            cur.execute("""
            INSERT INTO messages (id, sender_id, recipient_id, timestamp, seed, blob)
            SELECT id, sender_id, recipient_id, CAST(timestamp AS TEXT), CAST(seed AS TEXT), blob
            FROM old_messages
            """)
            conn.commit()
            print("        • Data migrated from old table")
            
            cur.execute("DROP TABLE old_messages")
            conn.commit()
            print("        • Old table dropped")
            print("        ✓ Schema updated successfully")
        else:
            print("        • Schema is already up-to-date")
    else:
        print("        • No existing messages table found")
        print("\n    [5.3] Creating new messages table...")
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
        print("        • Table schema:")
        print("          - id: TEXT PRIMARY KEY")
        print("          - sender_id: TEXT")
        print("          - recipient_id: TEXT")
        print("          - timestamp: TEXT")
        print("          - seed: TEXT")
        print("          - blob: BLOB")
        print("        ✓ New table created successfully")

    conn.close()
    print("\n    ✓ Database initialization completed successfully")


def store_message_blob(msg_id: str, sender_id: str, recipient_id: str,
                       timestamp, seed: int, blob: bytes):
    """Store message; force timestamp and seed to TEXT to avoid overflow."""
    print("    💾 DATABASE - STORING MESSAGE")
    print("    " + "=" * 45)
    
    print("    [6.1] Preparing message for storage...")
    print(f"        • Message ID: {msg_id}")
    print(f"        • Sender: {sender_id}")
    print(f"        • Recipient: {recipient_id}")
    print(f"        • Timestamp: {timestamp}")
    print(f"        • Seed: {seed}")
    print(f"        • Blob size: {len(blob)} bytes")
    
    print("\n    [6.2] Connecting to database...")
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    print("        ✓ Database connection established")
    
    print("\n    [6.3] Inserting message into database...")
    cur.execute(
        "INSERT INTO messages (id, sender_id, recipient_id, timestamp, seed, blob) VALUES (?, ?, ?, ?, ?, ?)",
        (msg_id, sender_id, recipient_id, str(timestamp), str(seed), blob)
    )
    conn.commit()
    print("        • Message inserted successfully")
    print("        • Transaction committed")
    
    print("\n    [6.4] Verifying storage...")
    cur.execute("SELECT COUNT(*) FROM messages WHERE id = ?", (msg_id,))
    count = cur.fetchone()[0]
    if count > 0:
        print("        ✓ Message verified in database")
    else:
        print("        ❌ Message not found in database")
    
    conn.close()
    print("        ✓ Database connection closed")
    print("    ✓ Message stored successfully in database")


def fetch_message_blob(msg_id: str) -> Optional[dict]:
    """Fetch message and auto-convert timestamp and seed back to int if possible."""
    print("    💾 DATABASE - RETRIEVING MESSAGE")
    print("    " + "=" * 45)
    
    print("    [7.1] Preparing to fetch message...")
    print(f"        • Message ID: {msg_id}")
    
    print("\n    [7.2] Connecting to database...")
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    print("        ✓ Database connection established")
    
    print("\n    [7.3] Querying database...")
    cur.execute("SELECT sender_id, recipient_id, timestamp, seed, blob FROM messages WHERE id=?", (msg_id,))
    row = cur.fetchone()
    
    if row:
        print("        • Message found in database")
        sender_id, recipient_id, timestamp, seed, blob = row
        print(f"        • Raw data retrieved:")
        print(f"          - Sender: {sender_id}")
        print(f"          - Recipient: {recipient_id}")
        print(f"          - Timestamp: {timestamp}")
        print(f"          - Seed: {seed}")
        print(f"          - Blob size: {len(blob)} bytes")
        
        print("\n    [7.4] Converting data types...")
        try:
            timestamp = int(timestamp)
            print(f"        • Timestamp converted to int: {timestamp}")
        except (ValueError, TypeError):
            print(f"        • Timestamp kept as string: {timestamp}")
        
        try:
            seed = int(seed)
            print(f"        • Seed converted to int: {seed}")
        except (ValueError, TypeError):
            print(f"        • Seed kept as string: {seed}")
        
        result = {
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "timestamp": timestamp,
            "seed": seed,
            "blob": blob
        }
        print("        ✓ Data type conversion completed")
    else:
        print("        ❌ Message not found in database")
        result = None
    
    conn.close()
    print("        ✓ Database connection closed")
    
    if result:
        print("    ✓ Message retrieved successfully from database")
    else:
        print("    ❌ Message retrieval failed")
    
    return result
