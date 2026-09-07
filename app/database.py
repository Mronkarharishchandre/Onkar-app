"""
StorageOS Database Layer
SQLite schema definition and parameterized data access layer.
"""

import os
import sqlite3
from contextlib import contextmanager

# Determine DB location from environment or default path
DEFAULT_DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.environ.get("STORAGEOS_DATABASE_PATH", os.path.join(DEFAULT_DB_DIR, "storageos.db"))


def get_db_path():
    """Return the absolute path to the database file, ensuring directory exists."""
    try:
        from flask import current_app, has_app_context
        if has_app_context() and current_app.config.get("DATABASE_PATH"):
            path = os.path.abspath(current_app.config["DATABASE_PATH"])
            os.makedirs(os.path.dirname(path), exist_ok=True)
            return path
    except ImportError:
        pass

    path = os.path.abspath(os.environ.get("STORAGEOS_DATABASE_PATH", DB_PATH))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path


def get_db_connection():
    """Establish and return an SQLite connection with Row factory and foreign keys enabled."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


# Convenient alias
get_db = get_db_connection


@contextmanager
def db_session():
    """Context manager for safe database transactions."""
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Initialize database tables according to StorageOS specifications."""
    with db_session() as conn:
        cursor = conn.cursor()

        # Users table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        # Folders table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                folder_name TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """
        )

        # Shares table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                shared_with_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                permission TEXT NOT NULL CHECK(permission IN ('viewer', 'editor')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (shared_with_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """
        )

        # Trash table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS trash (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                original_path TEXT NOT NULL,
                deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """
        )

        # Activity logs table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                filename TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """
        )

        # Indexing for high-performance lookup
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_shares_owner ON shares(owner_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_shares_shared_with ON shares(shared_with_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_trash_user ON trash(user_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_logs(user_id, created_at DESC);")


# --- Activity Logging ---
def log_activity(user_id: int, action: str, filename: str = None, details: str = None):
    """Record an audit trail activity log."""
    with db_session() as conn:
        conn.execute(
            """
            INSERT INTO activity_logs (user_id, action, filename, details)
            VALUES (?, ?, ?, ?);
            """,
            (user_id, action, filename, details),
        )


def get_user_activity(user_id: int, limit: int = 50):
    """Retrieve the recent activity log for a specific user."""
    with db_session() as conn:
        cursor = conn.execute(
            """
            SELECT id, action, filename, details, created_at
            FROM activity_logs
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?;
            """,
            (user_id, limit),
        )
        return [dict(row) for row in cursor.fetchall()]


# --- User Queries ---
def create_user(username: str, password_hash: str) -> int:
    """Create a new user and return their ID."""
    with db_session() as conn:
        cursor = conn.execute(
            """
            INSERT INTO users (username, password_hash)
            VALUES (?, ?);
            """,
            (username.strip(), password_hash),
        )
        return cursor.lastrowid


def get_user_by_username(username: str):
    """Retrieve user record by username."""
    with db_session() as conn:
        cursor = conn.execute(
            """
            SELECT id, username, password_hash, created_at
            FROM users
            WHERE username = ?;
            """,
            (username.strip(),),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int):
    """Retrieve user record by user ID."""
    with db_session() as conn:
        cursor = conn.execute(
            """
            SELECT id, username, password_hash, created_at
            FROM users
            WHERE id = ?;
            """,
            (user_id,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def list_all_other_usernames(current_user_id: int):
    """List available usernames for sharing dropdown (excluding current user)."""
    with db_session() as conn:
        cursor = conn.execute(
            """
            SELECT id, username
            FROM users
            WHERE id != ?
            ORDER BY username ASC;
            """,
            (current_user_id,),
        )
        return [dict(row) for row in cursor.fetchall()]
