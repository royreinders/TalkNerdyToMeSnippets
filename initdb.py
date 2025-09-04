# init_db.py
import sqlite3

DB_PATH = "mcp.sqlite"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Table for scheduled commands
    c.execute("""
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            implant_uid TEXT,
            command TEXT,
            executed INTEGER DEFAULT 0
        )
    """)

    # Table for active implants
    c.execute("""
        CREATE TABLE IF NOT EXISTS active_implants (
            implant_uid TEXT PRIMARY KEY,
            username TEXT,
            hostname TEXT,
            os TEXT,
            arch TEXT,
            pid INTEGER,
            proc_name TEXT,
            first_seen TEXT,
            last_checkin TEXT
        )
    """)

    conn.commit()
    conn.close()
    print(f"SQLite database initialized at '{DB_PATH}'.")

if __name__ == "__main__":
    init_db()
