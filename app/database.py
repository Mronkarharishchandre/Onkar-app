"""
StorageOS Database Layer
SQLite schema definition and parameterized data access layer.
"""

import os
import sqlite3
from contextlib import contextmanager

# Determine DB location from environment or default path
DEFAULT_DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DEFAULT_DB_FILE = os.path.join(DEFAULT_DB_DIR, "storageos.db")
DB_PATH = DEFAULT_DB_FILE


def get_db_path():
    """Return the absolute path to the database file, ensuring directory exists and is a valid file path."""
    try:
        from flask import current_app, has_app_context
        if has_app_context() and current_app.config.get("DATABASE_PATH"):
            cfg_path = os.path.abspath(current_app.config["DATABASE_PATH"])
            if os.path.isdir(cfg_path):
                cfg_path = os.path.join(cfg_path, "storageos.db")
            os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
            return cfg_path
    except (ImportError, Exception):
        pass

    raw_env = os.environ.get("STORAGEOS_DATABASE_PATH", "").strip()
    # Guard against invalid artifact values like '6', numbers, or empty values
    if raw_env and not raw_env.isdigit() and raw_env.lower() not in ("6", "true", "false", "default", "none"):
        path = os.path.abspath(raw_env)
        if os.path.isdir(path):
            path = os.path.join(path, "storageos.db")
    else:
        path = DEFAULT_DB_FILE

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

        # Public / Tokenized Share links table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS share_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                password_hash TEXT,
                expires_at TIMESTAMP,
                views INTEGER DEFAULT 0,
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
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_share_links_token ON share_links(token);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_share_links_user ON share_links(user_id);")

        # Schema migrations for users table (extend existing schema non-destructively)
        user_cols = [
            ("email", "TEXT"),
            ("google_id", "TEXT"),
            ("display_name", "TEXT"),
            ("avatar_url", "TEXT"),
            ("theme", "TEXT DEFAULT 'system'"),
            ("language", "TEXT DEFAULT 'en'"),
            ("file_view", "TEXT DEFAULT 'list'"),
            ("sort_preference", "TEXT DEFAULT 'name_asc'"),
            ("confirm_delete", "INTEGER DEFAULT 1"),
            ("session_version", "INTEGER DEFAULT 1"),
        ]
        for col_name, col_def in user_cols:
            try:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def};")
            except Exception:
                # Column already exists
                pass


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
    """Retrieve full user record by username."""
    with db_session() as conn:
        cursor = conn.execute(
            """
            SELECT *
            FROM users
            WHERE username = ? COLLATE NOCASE;
            """,
            (username.strip(),),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int):
    """Retrieve full user record by user ID."""
    with db_session() as conn:
        cursor = conn.execute(
            """
            SELECT *
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
            SELECT id, username, display_name
            FROM users
            WHERE id != ?
            ORDER BY username ASC;
            """,
            (current_user_id,),
        )
        return [dict(row) for row in cursor.fetchall()]


def get_user_by_google_id(google_id: str):
    """Retrieve user record by Google ID."""
    with db_session() as conn:
        cursor = conn.execute(
            "SELECT * FROM users WHERE google_id = ?;",
            (google_id,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def get_user_by_email(email: str):
    """Retrieve user record by email address."""
    with db_session() as conn:
        cursor = conn.execute(
            "SELECT * FROM users WHERE email = ? COLLATE NOCASE;",
            (email.strip(),),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def update_user_preferences(
    user_id: int,
    theme: str = None,
    language: str = None,
    display_name: str = None,
    email: str = None,
    file_view: str = None,
    sort_preference: str = None,
    confirm_delete: int = None,
):
    """Update user appearance, localization, account profile, and file preferences."""
    with db_session() as conn:
        fields = []
        params = []
        if theme is not None:
            fields.append("theme = ?")
            params.append(theme)
        if language is not None:
            fields.append("language = ?")
            params.append(language)
        if display_name is not None:
            fields.append("display_name = ?")
            params.append(display_name.strip())
        if email is not None:
            fields.append("email = ?")
            params.append(email.strip())
        if file_view is not None:
            fields.append("file_view = ?")
            params.append(file_view.strip().lower())
        if sort_preference is not None:
            fields.append("sort_preference = ?")
            params.append(sort_preference.strip())
        if confirm_delete is not None:
            fields.append("confirm_delete = ?")
            params.append(1 if confirm_delete else 0)

        if fields:
            params.append(user_id)
            conn.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?;", params)


def increment_user_session_version(user_id: int):
    """Increment the session version to invalidate all active sessions across devices."""
    with db_session() as conn:
        conn.execute(
            "UPDATE users SET session_version = COALESCE(session_version, 1) + 1 WHERE id = ?;",
            (user_id,),
        )


def update_user_password(user_id: int, password_hash: str):
    """Update password hash for existing user."""
    with db_session() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?;", (password_hash, user_id))


def create_or_link_google_user(email: str, google_id: str, display_name: str = None, avatar_url: str = None):
    """Find existing user by google_id or email, or create a new user provisioned for Google login."""
    import secrets
    from app.security import hash_password

    with db_session() as conn:
        # Check by google_id
        cursor = conn.execute("SELECT * FROM users WHERE google_id = ?;", (google_id,))
        user = cursor.fetchone()
        if user:
            # Update display_name or avatar if available
            conn.execute(
                "UPDATE users SET display_name = COALESCE(?, display_name), avatar_url = COALESCE(?, avatar_url) WHERE id = ?;",
                (display_name, avatar_url, user["id"]),
            )
            return dict(user)

        # Check by email
        cursor = conn.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE;", (email.strip(),))
        user = cursor.fetchone()
        if user:
            # Link google_id
            conn.execute(
                "UPDATE users SET google_id = ?, display_name = COALESCE(?, display_name), avatar_url = COALESCE(?, avatar_url) WHERE id = ?;",
                (google_id, display_name, avatar_url, user["id"]),
            )
            return dict(user)

        # Generate unique username from email
        base_username = email.split("@")[0].lower()
        base_username = "".join(c for c in base_username if c.isalnum() or c == "_")[:20]
        if not base_username:
            base_username = "user"
        
        username = base_username
        counter = 1
        while True:
            cursor = conn.execute("SELECT id FROM users WHERE username = ? COLLATE NOCASE;", (username,))
            if not cursor.fetchone():
                break
            username = f"{base_username}_{counter}"
            counter += 1

        # Secure random password for Google-provisioned account
        rand_pwd = secrets.token_urlsafe(32)
        pwd_hash = hash_password(rand_pwd)

        cursor = conn.execute(
            """
            INSERT INTO users (username, password_hash, email, google_id, display_name, avatar_url)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (username, pwd_hash, email.strip(), google_id, display_name or username, avatar_url),
        )
        new_id = cursor.lastrowid
        cursor = conn.execute("SELECT * FROM users WHERE id = ?;", (new_id,))
        return dict(cursor.fetchone())


# --- Public / Tokenized Share Links ---
def create_share_link(user_id: int, relative_path: str, filename: str, password_hash: str = None, expires_hours: int = None) -> str:
    """Create a new secure share token and record in share_links."""
    import secrets
    from datetime import datetime, timedelta

    token = secrets.token_urlsafe(24)
    expires_at = None
    if expires_hours and expires_hours > 0:
        expires_at = (datetime.utcnow() + timedelta(hours=expires_hours)).strftime("%Y-%m-%d %H:%M:%S")

    with db_session() as conn:
        conn.execute(
            """
            INSERT INTO share_links (user_id, token, filename, relative_path, password_hash, expires_at)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (user_id, token, filename, relative_path, password_hash, expires_at),
        )
    return token


def get_share_link_by_token(token: str):
    """Retrieve active share link record with owner details."""
    from datetime import datetime
    with db_session() as conn:
        cursor = conn.execute(
            """
            SELECT sl.*, u.username as owner_username, u.display_name as owner_display_name
            FROM share_links sl
            JOIN users u ON sl.user_id = u.id
            WHERE sl.token = ?;
            """,
            (token,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        record = dict(row)

        # Check expiration
        if record["expires_at"]:
            try:
                exp_dt = datetime.strptime(record["expires_at"], "%Y-%m-%d %H:%M:%S")
                if datetime.utcnow() > exp_dt:
                    return None  # Expired
            except Exception:
                pass
        return record


def increment_share_link_views(token: str):
    """Increment the view counter for a public share link."""
    with db_session() as conn:
        conn.execute("UPDATE share_links SET views = views + 1 WHERE token = ?;", (token,))


def revoke_share_link(link_id: int, user_id: int):
    """Revoke/delete a share link if owned by the user."""
    with db_session() as conn:
        conn.execute("DELETE FROM share_links WHERE id = ? AND user_id = ?;", (link_id, user_id))


def list_user_share_links(user_id: int):
    """List all public share links created by the user."""
    with db_session() as conn:
        cursor = conn.execute(
            """
            SELECT id, token, filename, relative_path, password_hash IS NOT NULL as has_password, expires_at, views, created_at
            FROM share_links
            WHERE user_id = ?
            ORDER BY created_at DESC;
            """,
            (user_id,),
        )
        return [dict(row) for row in cursor.fetchall()]

