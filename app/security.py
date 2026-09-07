"""
StorageOS Security Engine
Hardened path sanitization, traversal defense, password hashing, and CSRF protection.
"""

import hmac
import os
import re
import secrets
from functools import wraps
from flask import abort, session, request
from werkzeug.security import generate_password_hash, check_password_hash

# Valid username regex: 3-30 chars, alphanumeric and underscore only
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,30}$")

# Disallowed reserved usernames
RESERVED_USERNAMES = {
    "admin", "administrator", "root", "system", "trash", ".trash", "shared",
    "public", "storageos", "api", "health", "static", "login", "register", "logout"
}


def validate_username(username: str) -> tuple[bool, str]:
    """Validate username according to security standards."""
    if not username or not isinstance(username, str):
        return False, "Username is required."
    username = username.strip()
    if len(username) < 3:
        return False, "Username must be at least 3 characters long."
    if len(username) > 30:
        return False, "Username cannot exceed 30 characters."
    if not USERNAME_REGEX.match(username):
        return False, "Username may only contain letters, numbers, and underscores."
    if username.lower() in RESERVED_USERNAMES:
        return False, "This username is reserved and cannot be registered."
    return True, ""


def validate_password(password: str, confirm_password: str = None) -> tuple[bool, str]:
    """Validate password complexity and confirmation."""
    if not password or not isinstance(password, str):
        return False, "Password is required."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if confirm_password is not None and password != confirm_password:
        return False, "Passwords do not match."
    return True, ""


def hash_password(password: str) -> str:
    """Hash password using Werkzeug's secure scrypt/pbkdf2 hash."""
    return generate_password_hash(password, method="scrypt")


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify password against stored hash."""
    if not stored_hash or not password:
        return False
    return check_password_hash(stored_hash, password)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize an uploaded or renamed filename.
    Rejects or strips path separators, null bytes, and traversal tokens.
    """
    if not filename:
        return "unnamed_file"
    
    # Strip null bytes and control chars
    clean = filename.replace("\x00", "").replace("\r", "").replace("\n", "").strip()
    
    # Normalize separators and get only basename
    clean = os.path.basename(clean.replace("\\", "/"))
    
    # Disallow exact dot names
    if clean in (".", "..", "", ".trash"):
        return "unnamed_file"

    # Replace any remaining risky characters while preserving extensions and unicode letters
    clean = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", clean)

    # Trim length
    if len(clean) > 255:
        base, ext = os.path.splitext(clean)
        clean = base[: 255 - len(ext)] + ext

    return clean or "unnamed_file"


def get_safe_user_path(user_storage_root: str, relative_path: str) -> str:
    """
    Safely resolve a relative path within the user's storage root directory.
    Strictly prevents ../ traversal, absolute path escape, and symlink evasion.
    Raises PermissionError or ValueError if traversal is detected.
    """
    # Normalize user root to absolute canonical path
    base_root = os.path.realpath(os.path.abspath(user_storage_root))
    
    if not relative_path:
        return base_root

    # Reject null bytes immediately
    if "\x00" in relative_path:
        raise PermissionError("Access denied: Invalid path encoding.")

    # Convert Windows backslashes
    clean_rel = relative_path.replace("\\", "/").strip()

    # Reject leading slashes or drive letters
    clean_rel = clean_rel.lstrip("/")

    # Check for raw directory traversal tokens
    segments = clean_rel.split("/")
    for seg in segments:
        if seg in ("..", ".trash"):
            # .trash cannot be directly accessed as a user folder
            raise PermissionError("Access denied: Path traversal or restricted directory detected.")

    # Combine path safely
    target_path = os.path.abspath(os.path.join(base_root, clean_rel))

    # Verification 1: Target must start with base_root
    if not (target_path == base_root or target_path.startswith(base_root + os.sep)):
        raise PermissionError("Access denied: Path traversal detected outside user root.")

    # Verification 2: Check for symlink escape if file/dir exists
    if os.path.exists(target_path):
        real_target = os.path.realpath(target_path)
        if not (real_target == base_root or real_target.startswith(base_root + os.sep)):
            raise PermissionError("Access denied: Symlink traversal escape detected.")

    return target_path


# --- CSRF Protection ---
def generate_csrf_token() -> str:
    """Generate and store CSRF token in session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token(token: str) -> bool:
    """Validate submitted CSRF token using constant-time comparison."""
    try:
        from flask import current_app
        if current_app.config.get("TESTING") and not current_app.config.get("WTF_CSRF_ENABLED", True):
            return True
    except Exception:
        pass

    session_token = session.get("_csrf_token") or session.get("csrf_token")
    if not session_token or not token:
        return False
    return hmac.compare_digest(str(session_token), str(token))


def csrf_protect(f):
    """Decorator to enforce CSRF token validation on POST endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            try:
                from flask import current_app
                if current_app.config.get("TESTING") and not current_app.config.get("WTF_CSRF_ENABLED", True):
                    return f(*args, **kwargs)
            except Exception:
                pass

            token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
            if not validate_csrf_token(token):
                abort(403, description="Security token missing or invalid. Please refresh the page.")
        return f(*args, **kwargs)
    return decorated_function
