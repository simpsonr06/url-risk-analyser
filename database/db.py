import sqlite3
import os
from typing import Optional
from config import settings

def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Establish and return a connection to the SQLite database.
    Supports custom db_path for tests and ensures parent directories exist.
    """
    target_path = db_path or settings.DATABASE_PATH
    
    # Ensure directory exists if not an in-memory database
    if target_path != ":memory:":
        parent_dir = os.path.dirname(os.path.abspath(target_path))
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
            
    conn = sqlite3.connect(target_path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    
    # Enable WAL mode for better concurrency if on disk
    if target_path != ":memory:":
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
        except Exception:
            pass
            
    return conn

def init_db(db_path: Optional[str] = None):
    """Initialize the database schema if tables do not already exist."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            classification TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            creation_date TEXT,
            expiration_date TEXT,
            registrar TEXT
        )
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (timestamp DESC);
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_scans_classification ON scans (classification);
    ''')
    conn.commit()
    conn.close()

# Auto-initialize only if not in testing mode
if settings.ENV != "testing":
    init_db()
