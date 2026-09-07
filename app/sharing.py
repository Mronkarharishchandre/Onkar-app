"""
StorageOS Sharing Engine
Role-based file sharing (Viewer vs. Editor), authorization enforcement, and access controls.
"""

import os
from app.database import db_session, log_activity, get_user_by_username
from app.security import get_safe_user_path
from app.storage import get_user_storage_path, format_bytes, get_file_type_and_icon


def create_share(owner_id: int, owner_username: str, target_username: str, relative_path: str, permission: str = "viewer") -> dict:
    """
    Share a file with another registered user with viewer or editor permissions.
    Validates that:
    - Target user exists
    - User cannot share with themselves
    - File exists in owner's storage
    - Permission is either 'viewer' or 'editor'
    """
    target_clean = target_username.strip()
    if target_clean.lower() == owner_username.lower():
        raise ValueError("You cannot share a file with yourself.")

    target_user = get_user_by_username(target_clean)
    if not target_user:
        raise ValueError(f"User '{target_clean}' does not exist.")

    perm = permission.strip().lower()
    if perm not in ("viewer", "editor"):
        raise ValueError("Invalid permission level. Allowed values: viewer, editor.")

    owner_root = get_user_storage_path(owner_username)
    safe_path = get_safe_user_path(owner_root, relative_path)

    if not os.path.exists(safe_path) or not os.path.isfile(safe_path):
        raise FileNotFoundError("The file to share does not exist.")

    filename = os.path.basename(safe_path)

    with db_session() as conn:
        # Check if already shared with this user
        cursor = conn.execute(
            """
            SELECT id, permission FROM shares
            WHERE owner_id = ? AND shared_with_id = ? AND relative_path = ?;
            """,
            (owner_id, target_user["id"], relative_path),
        )
        existing = cursor.fetchone()
        if existing:
            # Update existing permission
            conn.execute(
                """
                UPDATE shares SET permission = ? WHERE id = ?;
                """,
                (perm, existing["id"]),
            )
            share_id = existing["id"]
            action = "UPDATE_SHARE"
            details = f"Updated share permission to '{perm}' for {target_clean}"
        else:
            cursor = conn.execute(
                """
                INSERT INTO shares (owner_id, shared_with_id, filename, relative_path, permission)
                VALUES (?, ?, ?, ?, ?);
                """,
                (owner_id, target_user["id"], filename, relative_path, perm),
            )
            share_id = cursor.lastrowid
            action = "SHARE"
            details = f"Shared '{filename}' with {target_clean} as {perm}"

    log_activity(owner_id, action, filename, details)

    return {
        "share_id": share_id,
        "filename": filename,
        "shared_with": target_clean,
        "permission": perm,
    }


def list_files_shared_with_user(user_id: int) -> list[dict]:
    """Retrieve all files shared with the current user."""
    with db_session() as conn:
        cursor = conn.execute(
            """
            SELECT s.id, s.owner_id, s.filename, s.relative_path, s.permission, s.created_at,
                   u.username as owner_username
            FROM shares s
            JOIN users u ON s.owner_id = u.id
            WHERE s.shared_with_id = ?
            ORDER BY s.created_at DESC;
            """,
            (user_id,),
        )
        results = []
        for row in cursor.fetchall():
            owner_root = get_user_storage_path(row["owner_username"])
            try:
                safe_path = get_safe_user_path(owner_root, row["relative_path"])
                if os.path.exists(safe_path) and os.path.isfile(safe_path):
                    stat = os.stat(safe_path)
                    ftype, icon = get_file_type_and_icon(row["filename"])
                    results.append({
                        "id": row["id"],
                        "filename": row["filename"],
                        "relative_path": row["relative_path"],
                        "owner_username": row["owner_username"],
                        "permission": row["permission"],
                        "created_at": row["created_at"],
                        "size_formatted": format_bytes(stat.st_size),
                        "type": ftype,
                        "icon": icon,
                        "available": True,
                    })
                else:
                    results.append({
                        "id": row["id"],
                        "filename": row["filename"],
                        "relative_path": row["relative_path"],
                        "owner_username": row["owner_username"],
                        "permission": row["permission"],
                        "created_at": row["created_at"],
                        "size_formatted": "Unavailable",
                        "type": "Missing",
                        "icon": "file-x",
                        "available": False,
                    })
            except Exception:
                continue

        return results


def list_files_shared_by_user(user_id: int) -> list[dict]:
    """Retrieve all shares created by the user."""
    with db_session() as conn:
        cursor = conn.execute(
            """
            SELECT s.id, s.filename, s.relative_path, s.permission, s.created_at,
                   u.username as shared_with_username
            FROM shares s
            JOIN users u ON s.shared_with_id = u.id
            WHERE s.owner_id = ?
            ORDER BY s.created_at DESC;
            """,
            (user_id,),
        )
        return [dict(row) for row in cursor.fetchall()]


def get_share_record_for_user(share_id: int, user_id: int):
    """Retrieve share record and check if user has access (either as receiver or owner)."""
    with db_session() as conn:
        cursor = conn.execute(
            """
            SELECT s.id, s.owner_id, s.shared_with_id, s.filename, s.relative_path, s.permission,
                   u_owner.username as owner_username,
                   u_target.username as target_username
            FROM shares s
            JOIN users u_owner ON s.owner_id = u_owner.id
            JOIN users u_target ON s.shared_with_id = u_target.id
            WHERE s.id = ? AND (s.shared_with_id = ? OR s.owner_id = ?);
            """,
            (share_id, user_id, user_id),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def revoke_share(share_id: int, owner_id: int):
    """Revoke a share by the owner."""
    with db_session() as conn:
        cursor = conn.execute(
            "SELECT filename FROM shares WHERE id = ? AND owner_id = ?",
            (share_id, owner_id),
        )
        row = cursor.fetchone()
        if not row:
            raise PermissionError("Share not found or unauthorized.")

        conn.execute("DELETE FROM shares WHERE id = ? AND owner_id = ?", (share_id, owner_id))

    log_activity(owner_id, "REVOKE_SHARE", row["filename"], f"Revoked share ID {share_id}")
