"""
StorageOS Storage Engine
User-isolated filesystem operations, quota calculations, trash management, and recursive search.
"""

import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from app.database import db_session, log_activity
from app.security import get_safe_user_path, sanitize_filename

# Default base storage root.
# In Podman/Docker, this maps to persistent volume /storage.
# If /storage is not writable in development, falls back to ./storage or app/data/storage.
def get_base_storage_dir() -> str:
    try:
        from flask import current_app, has_app_context
        if has_app_context() and current_app.config.get("STORAGE_PATH"):
            path = os.path.abspath(current_app.config["STORAGE_PATH"])
            os.makedirs(path, exist_ok=True)
            return path
    except ImportError:
        pass

    env_root = os.environ.get("STORAGEOS_STORAGE_ROOT")
    if env_root:
        os.makedirs(env_root, exist_ok=True)
        return os.path.abspath(env_root)

    # Check if /storage is accessible and writable
    if os.path.exists("/storage"):
        if os.access("/storage", os.W_OK):
            return "/storage"
    else:
        try:
            os.makedirs("/storage", exist_ok=True)
            return "/storage"
        except (PermissionError, OSError):
            pass

    # Fallback to project root storage
    local_storage = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "storage"))
    os.makedirs(local_storage, exist_ok=True)
    return local_storage


# Default quota: 1 GB (1,073,741,824 bytes)
DEFAULT_QUOTA_BYTES = 1024 * 1024 * 1024


def get_user_quota_limit() -> int:
    """Read quota from STORAGEOS_QUOTA env var, Flask config, or fallback to 1GB."""
    try:
        from flask import current_app, has_app_context
        if has_app_context() and current_app.config.get("STORAGEOS_QUOTA"):
            return int(current_app.config["STORAGEOS_QUOTA"])
    except (ImportError, ValueError, TypeError):
        pass

    quota_val = os.environ.get("STORAGEOS_QUOTA")
    if quota_val:
        try:
            return int(quota_val)
        except ValueError:
            pass
    return DEFAULT_QUOTA_BYTES


def get_user_storage_path(username: str) -> str:
    """Return the absolute path to a user's isolated storage root directory."""
    clean_user = username.strip().lower()
    base = get_base_storage_dir()
    user_dir = os.path.join(base, "users", clean_user)
    os.makedirs(user_dir, mode=0o700, exist_ok=True)
    
    # Also ensure isolated .trash folder exists
    trash_dir = os.path.join(user_dir, ".trash")
    os.makedirs(trash_dir, mode=0o700, exist_ok=True)
    
    return os.path.realpath(user_dir)


def get_user_trash_path(username: str) -> str:
    """Return the absolute path to a user's trash folder."""
    user_root = get_user_storage_path(username)
    trash_dir = os.path.join(user_root, ".trash")
    os.makedirs(trash_dir, mode=0o700, exist_ok=True)
    return os.path.realpath(trash_dir)


def calculate_user_storage_used(username: str) -> int:
    """Calculate recursive disk usage in bytes for a user, strictly excluding .trash."""
    user_root = get_user_storage_path(username)
    total_bytes = 0
    trash_path = os.path.realpath(os.path.join(user_root, ".trash"))

    for dirpath, dirnames, filenames in os.walk(user_root, followlinks=False):
        # Exclude .trash from walking
        real_dir = os.path.realpath(dirpath)
        if real_dir == trash_path or real_dir.startswith(trash_path + os.sep):
            continue
        
        # Don't descend into .trash
        if ".trash" in dirnames:
            dirnames.remove(".trash")

        for f in filenames:
            file_path = os.path.join(dirpath, f)
            try:
                # Use lstat to avoid following symlinks
                stat = os.lstat(file_path)
                total_bytes += stat.st_size
            except (OSError, FileNotFoundError):
                continue

    return total_bytes


def format_bytes(size: float) -> str:
    """Format bytes into readable units: B, KB, MB, GB."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{size:.1f} PB"


def get_user_quota_info(username: str) -> dict:
    """Return storage quota statistics for the user."""
    used_bytes = calculate_user_storage_used(username)
    total_bytes = get_user_quota_limit()
    avail_bytes = max(0, total_bytes - used_bytes)
    percentage = min(100.0, round((used_bytes / total_bytes) * 100, 1)) if total_bytes > 0 else 100.0

    return {
        "used_bytes": used_bytes,
        "total_bytes": total_bytes,
        "available_bytes": avail_bytes,
        "used_formatted": format_bytes(used_bytes),
        "total_formatted": format_bytes(total_bytes),
        "available_formatted": format_bytes(avail_bytes),
        "percentage": percentage,
        "is_exceeded": used_bytes >= total_bytes,
    }


def get_file_type_and_icon(filename: str, is_dir: bool = False) -> tuple[str, str]:
    """Return category name and UI icon identifier based on extension."""
    if is_dir:
        return "Folder", "folder"

    ext = os.path.splitext(filename)[1].lower()
    if ext in (".pdf",):
        return "PDF Document", "file-text"
    elif ext in (".doc", ".docx", ".odt", ".rtf", ".txt", ".md"):
        return "Document", "file-text"
    elif ext in (".xls", ".xlsx", ".csv"):
        return "Spreadsheet", "table"
    elif ext in (".ppt", ".pptx"):
        return "Presentation", "presentation"
    elif ext in (".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".bmp"):
        return "Image", "image"
    elif ext in (".mp4", ".mkv", ".mov", ".avi", ".webm"):
        return "Video", "video"
    elif ext in (".mp3", ".wav", ".ogg", ".flac", ".m4a"):
        return "Audio", "music"
    elif ext in (".zip", ".tar", ".gz", ".bz2", ".7z", ".rar"):
        return "Archive", "archive"
    elif ext in (".py", ".js", ".ts", ".html", ".css", ".json", ".sql", ".sh", ".yml", ".yaml"):
        return "Code", "code"
    return "File", "file"


def list_user_files(username: str, relative_folder: str = "") -> dict:
    """
    List folders and files in a user's relative path with rich metadata.
    Strictly isolated and protected against path traversal.
    """
    user_root = get_user_storage_path(username)
    safe_target = get_safe_user_path(user_root, relative_folder)

    if not os.path.exists(safe_target) or not os.path.isdir(safe_target):
        return {"folders": [], "files": [], "breadcrumbs": []}

    # Breadcrumbs calculation
    norm_rel = os.path.relpath(safe_target, user_root)
    breadcrumbs = [{"name": "My Files", "path": ""}]
    if norm_rel != ".":
        parts = norm_rel.split(os.sep)
        accum = []
        for p in parts:
            accum.append(p)
            breadcrumbs.append({"name": p, "path": "/".join(accum)})

    folders = []
    files = []

    try:
        entries = os.listdir(safe_target)
    except OSError:
        return {"folders": [], "files": [], "breadcrumbs": breadcrumbs}

    for entry in sorted(entries, key=lambda s: s.lower()):
        # Hide .trash and system dotfiles
        if entry.startswith("."):
            continue

        full_entry_path = os.path.join(safe_target, entry)
        try:
            stat = os.stat(full_entry_path)
        except OSError:
            continue

        entry_rel = os.path.relpath(full_entry_path, user_root).replace("\\", "/")
        mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")

        if os.path.isdir(full_entry_path):
            # Count items in folder
            try:
                sub_count = len([x for x in os.listdir(full_entry_path) if not x.startswith(".")])
            except OSError:
                sub_count = 0

            folders.append({
                "name": entry,
                "relative_path": entry_rel,
                "item_count": sub_count,
                "modified": mtime,
                "icon": "folder",
                "type": "Folder"
            })
        elif os.path.isfile(full_entry_path):
            ftype, icon = get_file_type_and_icon(entry)
            files.append({
                "name": entry,
                "relative_path": entry_rel,
                "size_bytes": stat.st_size,
                "size_formatted": format_bytes(stat.st_size),
                "modified": mtime,
                "icon": icon,
                "type": ftype
            })

    return {
        "current_path": norm_rel if norm_rel != "." else "",
        "breadcrumbs": breadcrumbs,
        "folders": folders,
        "files": files,
    }


def create_user_folder(username: str, parent_rel_path: str, folder_name: str) -> str:
    """Create a new folder safely inside the user's storage."""
    safe_name = sanitize_filename(folder_name)
    if not safe_name or safe_name in (".", "..", ".trash"):
        raise ValueError("Invalid folder name.")

    user_root = get_user_storage_path(username)
    parent_path = get_safe_user_path(user_root, parent_rel_path)
    new_dir_path = os.path.join(parent_path, safe_name)

    # Validate again to ensure no traversal
    safe_new_dir = get_safe_user_path(user_root, os.path.relpath(new_dir_path, user_root))
    
    if os.path.exists(safe_new_dir):
        raise FileExistsError(f"A folder or file named '{safe_name}' already exists.")

    os.makedirs(safe_new_dir, mode=0o700, exist_ok=False)
    rel_result = os.path.relpath(safe_new_dir, user_root).replace("\\", "/")

    # Also register in DB folders table
    with db_session() as conn:
        cursor = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_row = cursor.fetchone()
        if user_row:
            conn.execute(
                "INSERT INTO folders (user_id, folder_name, relative_path) VALUES (?, ?, ?)",
                (user_row["id"], safe_name, rel_result),
            )

    return rel_result


def rename_user_item(username: str, old_rel_path: str, new_name: str) -> str:
    """Rename a file or folder safely within user storage."""
    safe_new_name = sanitize_filename(new_name)
    if not safe_new_name or safe_new_name in (".", "..", ".trash"):
        raise ValueError("Invalid new name specified.")

    user_root = get_user_storage_path(username)
    safe_old_path = get_safe_user_path(user_root, old_rel_path)

    if not os.path.exists(safe_old_path):
        raise FileNotFoundError("The target item does not exist.")

    parent_dir = os.path.dirname(safe_old_path)
    new_target_path = os.path.join(parent_dir, safe_new_name)
    safe_new_path = get_safe_user_path(user_root, os.path.relpath(new_target_path, user_root))

    if os.path.exists(safe_new_path):
        raise FileExistsError(f"An item named '{safe_new_name}' already exists in this folder.")

    os.rename(safe_old_path, safe_new_path)
    return os.path.relpath(safe_new_path, user_root).replace("\\", "/")


def move_file_to_trash(username: str, user_id: int, relative_path: str) -> int:
    """
    Move a file or folder to .trash and create an entry in the trash table.
    Does NOT permanently delete.
    """
    user_root = get_user_storage_path(username)
    safe_file_path = get_safe_user_path(user_root, relative_path)

    if not os.path.exists(safe_file_path):
        raise FileNotFoundError("The requested file does not exist.")

    trash_root = get_user_trash_path(username)
    filename = os.path.basename(safe_file_path)

    # Save to SQLite trash table with original clean filename
    with db_session() as conn:
        cursor = conn.execute(
            """
            INSERT INTO trash (user_id, filename, original_path)
            VALUES (?, ?, ?);
            """,
            (user_id, filename, relative_path),
        )
        trash_id = cursor.lastrowid

    trash_filename = f"{trash_id}_{filename}"
    trash_target_path = os.path.join(trash_root, trash_filename)
    shutil.move(safe_file_path, trash_target_path)

    log_activity(user_id, "DELETE", filename, f"Moved {relative_path} to Trash")
    return trash_id


def restore_file_from_trash(username: str, user_id: int, trash_id: int) -> str:
    """
    Restore a file from .trash back to its original location.
    Recreates parent directories if needed and defends against traversal.
    """
    with db_session() as conn:
        cursor = conn.execute(
            "SELECT id, filename, original_path FROM trash WHERE id = ? AND user_id = ?",
            (trash_id, user_id),
        )
        record = cursor.fetchone()
        if not record:
            raise FileNotFoundError("Trash record not found.")

        orig_filename = record["filename"]
        original_rel_path = record["original_path"]

    user_root = get_user_storage_path(username)
    trash_root = get_user_trash_path(username)
    
    # Try prefixed filename first, then plain filename
    source_trash_file = os.path.join(trash_root, f"{trash_id}_{orig_filename}")
    if not os.path.exists(source_trash_file):
        source_trash_file = os.path.join(trash_root, orig_filename)

    if not os.path.exists(source_trash_file):
        raise FileNotFoundError("Deleted item no longer exists in trash storage.")

    # Validate destination original path safely
    safe_destination = get_safe_user_path(user_root, original_rel_path)

    # Check if target file already exists at original path, auto-rename if collision
    dest_dir = os.path.dirname(safe_destination)
    os.makedirs(dest_dir, exist_ok=True)

    if os.path.exists(safe_destination):
        base, ext = os.path.splitext(safe_destination)
        safe_destination = f"{base}_restored_{int(time.time())}{ext}"

    # Move from trash back to active storage
    shutil.move(source_trash_file, safe_destination)

    # Remove trash DB record
    with db_session() as conn:
        conn.execute("DELETE FROM trash WHERE id = ? AND user_id = ?", (trash_id, user_id))

    display_name = os.path.basename(safe_destination)
    log_activity(user_id, "RESTORE", display_name, f"Restored from trash to {original_rel_path}")
    return os.path.relpath(safe_destination, user_root).replace("\\", "/")


def permanently_delete_from_trash(username: str, user_id: int, trash_id: int):
    """Permanently delete an item from .trash and remove its DB record."""
    with db_session() as conn:
        cursor = conn.execute(
            "SELECT id, filename, original_path FROM trash WHERE id = ? AND user_id = ?",
            (trash_id, user_id),
        )
        record = cursor.fetchone()
        if not record:
            raise FileNotFoundError("Trash record not found.")

        orig_filename = record["filename"]
        original_path = record["original_path"]

    user_root = get_user_storage_path(username)
    trash_root = get_user_trash_path(username)
    
    source_trash_file = os.path.join(trash_root, f"{trash_id}_{orig_filename}")
    if not os.path.exists(source_trash_file):
        source_trash_file = os.path.join(trash_root, orig_filename)

    if os.path.exists(source_trash_file):
        if os.path.isdir(source_trash_file):
            shutil.rmtree(source_trash_file, ignore_errors=True)
        else:
            os.remove(source_trash_file)

    with db_session() as conn:
        conn.execute("DELETE FROM trash WHERE id = ? AND user_id = ?", (trash_id, user_id))

    display_name = os.path.basename(original_path)
    log_activity(user_id, "PERMANENT_DELETE", display_name, f"Permanently purged {original_path}")


def empty_user_trash(username: str, user_id: int):
    """Empty all items in the user's trash."""
    with db_session() as conn:
        cursor = conn.execute(
            "SELECT id, filename FROM trash WHERE user_id = ?", (user_id,)
        )
        records = cursor.fetchall()
        conn.execute("DELETE FROM trash WHERE user_id = ?", (user_id,))

    trash_root = get_user_trash_path(username)
    for record in records:
        fpath = os.path.join(trash_root, record["filename"])
        if os.path.exists(fpath):
            if os.path.isdir(fpath):
                shutil.rmtree(fpath, ignore_errors=True)
            else:
                try:
                    os.remove(fpath)
                except OSError:
                    pass

    log_activity(user_id, "PERMANENT_DELETE", "Trash", "Emptied all items in trash")


def list_user_trash(user_id: int) -> list[dict]:
    """Retrieve list of trash items for a user."""
    with db_session() as conn:
        cursor = conn.execute(
            """
            SELECT id, filename, original_path, deleted_at
            FROM trash
            WHERE user_id = ?
            ORDER BY deleted_at DESC;
            """,
            (user_id,),
        )
        results = []
        for row in cursor.fetchall():
            orig_name = os.path.basename(row["original_path"])
            results.append({
                "id": row["id"],
                "filename": orig_name,
                "original_path": row["original_path"],
                "deleted_at": row["deleted_at"],
            })
        return results


def recursive_search_files(username: str, query: str) -> list[dict]:
    """
    Search recursively inside the user's storage directory.
    Strictly excludes .trash.
    Returns: Filename, relative path, file size, download link data.
    """
    if not query or not query.strip():
        return []

    q = query.strip().lower()
    user_root = get_user_storage_path(username)
    trash_root = os.path.realpath(os.path.join(user_root, ".trash"))
    results = []

    for dirpath, dirnames, filenames in os.walk(user_root, followlinks=False):
        real_dir = os.path.realpath(dirpath)
        if real_dir == trash_root or real_dir.startswith(trash_root + os.sep):
            continue

        if ".trash" in dirnames:
            dirnames.remove(".trash")

        for f in filenames:
            if q in f.lower():
                full_path = os.path.join(dirpath, f)
                try:
                    stat = os.stat(full_path)
                    rel_path = os.path.relpath(full_path, user_root).replace("\\", "/")
                    ftype, icon = get_file_type_and_icon(f)
                    results.append({
                        "filename": f,
                        "relative_path": rel_path,
                        "size_bytes": stat.st_size,
                        "size_formatted": format_bytes(stat.st_size),
                        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                        "type": ftype,
                        "icon": icon,
                    })
                except OSError:
                    continue

    return results


def secrets_hex(n: int) -> str:
    import secrets
    return secrets.token_hex(n)
