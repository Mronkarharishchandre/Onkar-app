"""
StorageOS Core Application Server
Main entry point, routes, handlers, health check, and error pages.
"""

import os
import secrets
from flask import (
    Flask,
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    send_file,
    flash,
    session,
    jsonify,
    abort,
)
from werkzeug.exceptions import RequestEntityTooLarge

from app.database import (
    init_db,
    get_user_by_id,
    get_user_activity,
    log_activity,
    list_all_other_usernames,
    get_db_connection,
)
from app.auth import auth_bp, login_required
from app.security import (
    get_safe_user_path,
    sanitize_filename,
    generate_csrf_token,
    csrf_protect,
)
from app.storage import (
    get_user_storage_path,
    get_base_storage_dir,
    list_user_files,
    create_user_folder,
    rename_user_item,
    move_file_to_trash,
    restore_file_from_trash,
    permanently_delete_from_trash,
    empty_user_trash,
    list_user_trash,
    recursive_search_files,
    get_user_quota_info,
    format_bytes,
)
from app.sharing import (
    create_share,
    list_files_shared_with_user,
    list_files_shared_by_user,
    get_share_record_for_user,
    revoke_share,
)

main_bp = Blueprint("main", __name__)


def create_app(test_config=None):
    """Application factory for StorageOS."""
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # Load configuration
    secret_key = os.environ.get("STORAGEOS_SECRET_KEY")
    if not secret_key:
        secret_key = secrets.token_hex(32)
        print("Warning: STORAGEOS_SECRET_KEY not set. Using temporary ephemeral key.")
    
    app.config.from_mapping(
        SECRET_KEY=secret_key,
        MAX_CONTENT_LENGTH=100 * 1024 * 1024,  # 100 MB max upload
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1"),
    )

    if test_config:
        app.config.update(test_config)

    # Initialize SQLite database
    init_db()

    # Context processors for template rendering
    @app.context_processor
    def inject_globals():
        user = None
        quota_info = None
        if "user_id" in session and "username" in session:
            user = {"id": session["user_id"], "username": session["username"]}
            try:
                quota_info = get_user_quota_info(session["username"])
            except Exception:
                pass
        return {
            "current_user": user,
            "csrf_token": generate_csrf_token(),
            "global_quota": quota_info,
        }

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    # Custom error handlers
    @app.errorhandler(400)
    def bad_request_error(e):
        return render_template("error.html", code=400, title="Bad Request", message=str(e.description if hasattr(e, "description") else "Invalid request.")), 400

    @app.errorhandler(401)
    def unauthorized_error(e):
        return render_template("error.html", code=401, title="Unauthorized", message="Authentication is required to access this resource."), 401

    @app.errorhandler(403)
    def forbidden_error(e):
        return render_template("error.html", code=403, title="Forbidden", message=str(e.description if hasattr(e, "description") else "Access denied.")), 403

    @app.errorhandler(404)
    def not_found_error(e):
        return render_template("error.html", code=404, title="Not Found", message="The requested resource was not found on this server."), 404

    @app.errorhandler(413)
    @app.errorhandler(RequestEntityTooLarge)
    def payload_too_large_error(e):
        return render_template("error.html", code=413, title="Payload Too Large", message="File exceeds maximum allowed upload size of 100 MB."), 413

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("error.html", code=500, title="Internal Server Error", message="An unexpected error occurred. Please try again later."), 500

    return app


# ==========================================
# Main Routes
# ==========================================

@main_bp.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("auth.login"))


@main_bp.route("/dashboard")
@login_required
def dashboard():
    username = session["username"]
    user_id = session["user_id"]

    quota = get_user_quota_info(username)
    activity = get_user_activity(user_id, limit=8)
    
    # Get recent files
    root_listing = list_user_files(username, "")
    recent_files = root_listing["files"][:8]

    # Other users count for sharing
    other_users = list_all_other_usernames(user_id)

    return render_template(
        "dashboard.html",
        quota=quota,
        recent_files=recent_files,
        activity=activity,
        other_users=other_users,
    )


@main_bp.route("/files")
@main_bp.route("/files/")
@main_bp.route("/files/<path:subpath>")
@login_required
def files(subpath=""):
    username = session["username"]
    user_id = session["user_id"]

    try:
        data = list_user_files(username, subpath)
    except PermissionError:
        flash("Security violation: Path traversal detected.", "danger")
        return redirect(url_for("main.files"))

    quota = get_user_quota_info(username)
    other_users = list_all_other_usernames(user_id)

    return render_template(
        "files.html",
        current_path=data["current_path"],
        breadcrumbs=data["breadcrumbs"],
        folders=data["folders"],
        files=data["files"],
        quota=quota,
        other_users=other_users,
    )


def redirect_to_files(current_path=""):
    """Redirect cleanly without generating trailing slashes when at root."""
    if current_path and current_path.strip("/"):
        return redirect(url_for("main.files", subpath=current_path.strip("/")))
    return redirect(url_for("main.files"))


@main_bp.route("/upload", methods=["POST"])
@main_bp.route("/files/upload", methods=["POST"])
@login_required
@csrf_protect
def upload_file():
    username = session["username"]
    user_id = session["user_id"]
    current_path = request.form.get("current_path", "").strip()

    if "file" not in request.files:
        flash("No file was selected for upload.", "warning")
        return redirect_to_files(current_path)

    file = request.files["file"]
    if file.filename == "":
        flash("No file was selected.", "warning")
        return redirect_to_files(current_path)

    # Sanitize filename
    safe_name = sanitize_filename(file.filename)
    if not safe_name or safe_name in (".", "..", ".trash"):
        flash("Invalid filename provided.", "danger")
        return redirect_to_files(current_path)

    # Check incoming file size against quota
    file.seek(0, os.SEEK_END)
    file_length = file.tell()
    file.seek(0)

    quota = get_user_quota_info(username)
    if quota["used_bytes"] + file_length > quota["total_bytes"]:
        flash(f"Upload rejected: Insufficient storage quota. File size ({format_bytes(file_length)}) exceeds remaining space ({quota['available_formatted']}). Quota exceeded.", "danger")
        return redirect_to_files(current_path)

    try:
        user_root = get_user_storage_path(username)
        target_dir = get_safe_user_path(user_root, current_path)
        os.makedirs(target_dir, exist_ok=True)
        
        destination = os.path.join(target_dir, safe_name)
        # Check traversal
        safe_destination = get_safe_user_path(user_root, os.path.relpath(destination, user_root))
        
        file.save(safe_destination)
        rel_saved = os.path.relpath(safe_destination, user_root).replace("\\", "/")

        log_activity(user_id, "UPLOAD", safe_name, f"Uploaded {safe_name} ({format_bytes(file_length)}) to {rel_saved}")
        flash(f"File '{safe_name}' uploaded successfully.", "success")
    except PermissionError:
        flash("Security violation: Attempted path escape during upload.", "danger")
    except Exception as e:
        flash(f"Upload failed: {str(e)}", "danger")

    return redirect_to_files(current_path)


@main_bp.route("/create-folder", methods=["POST"])
@main_bp.route("/files/create-folder", methods=["POST"])
@login_required
@csrf_protect
def create_folder():
    username = session["username"]
    user_id = session["user_id"]
    current_path = request.form.get("current_path", "").strip()
    folder_name = request.form.get("folder_name", "").strip()

    if not folder_name:
        flash("Folder name cannot be empty.", "warning")
        return redirect_to_files(current_path)

    try:
        rel_created = create_user_folder(username, current_path, folder_name)
        log_activity(user_id, "CREATE_FOLDER", folder_name, f"Created folder {rel_created}")
        flash(f"Folder '{folder_name}' created successfully.", "success")
    except FileExistsError as e:
        flash(str(e), "warning")
    except PermissionError:
        flash("Security violation: Path traversal prevented.", "danger")
    except Exception as e:
        flash(f"Failed to create folder: {str(e)}", "danger")

    return redirect_to_files(current_path)


@main_bp.route("/rename", methods=["POST"])
@main_bp.route("/files/rename", methods=["POST"])
@login_required
@csrf_protect
def rename_item():
    username = session["username"]
    user_id = session["user_id"]
    old_rel_path = request.form.get("relative_path", "").strip()
    new_name = request.form.get("new_name", "").strip()
    item_type = request.form.get("item_type", "file").strip()
    current_path = request.form.get("current_path", "").strip()

    if not old_rel_path or not new_name:
        flash("Path and new name are required.", "warning")
        return redirect_to_files(current_path)

    try:
        new_rel = rename_user_item(username, old_rel_path, new_name)
        action_name = "RENAME_FOLDER" if item_type == "folder" else "RENAME"
        log_activity(user_id, action_name, new_name, f"Renamed {old_rel_path} to {new_rel}")
        flash(f"Renamed successfully to '{new_name}'.", "success")
    except FileExistsError as e:
        flash(str(e), "warning")
    except PermissionError:
        flash("Security violation: Path traversal prevented.", "danger")
    except Exception as e:
        flash(f"Rename failed: {str(e)}", "danger")

    return redirect_to_files(current_path)


@main_bp.route("/delete", methods=["POST"])
@main_bp.route("/files/delete", methods=["POST"])
@login_required
@csrf_protect
def delete_item():
    username = session["username"]
    user_id = session["user_id"]
    rel_path = request.form.get("relative_path", "").strip()
    current_path = request.form.get("current_path", "").strip()

    if not rel_path:
        flash("File path is required.", "warning")
        return redirect_to_files(current_path)

    try:
        move_file_to_trash(username, user_id, rel_path)
        flash(f"Moved to trash: '{os.path.basename(rel_path)}'. You can restore it anytime from Trash.", "info")
    except PermissionError:
        flash("Security violation: Path traversal prevented.", "danger")
    except Exception as e:
        flash(f"Delete failed: {str(e)}", "danger")

    return redirect_to_files(current_path)


@main_bp.route("/download")
@main_bp.route("/download/<path:rel_path>")
@main_bp.route("/files/download")
@main_bp.route("/files/download/<path:rel_path>")
@login_required
def download_file(rel_path=""):
    username = session["username"]
    user_id = session["user_id"]
    if not rel_path:
        rel_path = request.args.get("rel_path", "").strip()

    if not rel_path:
        abort(400, description="File path parameter required.")

    try:
        user_root = get_user_storage_path(username)
        safe_path = get_safe_user_path(user_root, rel_path)

        if not os.path.exists(safe_path) or not os.path.isfile(safe_path):
            abort(404, description="Requested file not found in storage.")

        filename = os.path.basename(safe_path)
        log_activity(user_id, "DOWNLOAD", filename, f"Downloaded {rel_path}")
        return send_file(safe_path, as_attachment=True, download_name=filename)
    except PermissionError:
        abort(403, description="Access denied: Path traversal or restricted access.")


# ==========================================
# Sharing Routes
# ==========================================

@main_bp.route("/shared")
@login_required
def shared():
    user_id = session["user_id"]
    shared_with_me = list_files_shared_with_user(user_id)
    shared_by_me = list_files_shared_by_user(user_id)
    return render_template(
        "shared.html",
        shared_with_me=shared_with_me,
        shared_by_me=shared_by_me,
    )


@main_bp.route("/share", methods=["POST"])
@main_bp.route("/files/share", methods=["POST"])
@login_required
@csrf_protect
def share_file():
    user_id = session["user_id"]
    owner_username = session["username"]
    target_username = request.form.get("target_username", "").strip()
    relative_path = request.form.get("relative_path", "").strip()
    permission = request.form.get("permission", "viewer").strip().lower()
    current_path = request.form.get("current_path", "").strip()

    if not target_username or not relative_path:
        flash("Target user and file must be specified.", "warning")
        return redirect_to_files(current_path)

    try:
        create_share(user_id, owner_username, target_username, relative_path, permission)
        flash(f"Successfully shared '{os.path.basename(relative_path)}' with {target_username} as {permission.upper()}.", "success")
    except ValueError as e:
        flash(str(e), "warning")
    except PermissionError:
        flash("Security violation: Path traversal prevented.", "danger")
    except Exception as e:
        flash(f"Sharing failed: {str(e)}", "danger")

    return redirect_to_files(current_path)


@main_bp.route("/share/revoke/<int:share_id>", methods=["POST"])
@login_required
@csrf_protect
def revoke_user_share(share_id):
    user_id = session["user_id"]
    try:
        revoke_share(share_id, user_id)
        flash("Share access has been revoked.", "info")
    except Exception as e:
        flash(f"Revocation failed: {str(e)}", "danger")
    return redirect(url_for("main.shared"))


@main_bp.route("/shared/download/<int:share_id>")
@login_required
def download_shared_file(share_id):
    user_id = session["user_id"]
    record = get_share_record_for_user(share_id, user_id)

    if not record:
        abort(404, description="Shared file record not found or unauthorized.")

    owner_username = record["owner_username"]
    owner_root = get_user_storage_path(owner_username)

    try:
        safe_path = get_safe_user_path(owner_root, record["relative_path"])
        if not os.path.exists(safe_path) or not os.path.isfile(safe_path):
            abort(404, description="The shared file was removed or moved by its owner.")

        filename = os.path.basename(safe_path)
        log_activity(user_id, "DOWNLOAD", filename, f"Downloaded shared file from {owner_username} (Share ID {share_id})")
        return send_file(safe_path, as_attachment=True, download_name=filename)
    except PermissionError:
        abort(403, description="Access denied: Restricted file path.")


@main_bp.route("/shared/rename/<int:share_id>", methods=["POST"])
@login_required
@csrf_protect
def rename_shared_file(share_id):
    user_id = session["user_id"]
    record = get_share_record_for_user(share_id, user_id)

    if not record:
        abort(404, description="Shared record not found.")

    # Authorization check: only EDITOR can rename
    if record["permission"] != "editor":
        abort(403, description="Permission denied: Viewer role cannot rename shared files.")

    new_name = request.form.get("new_name", "").strip()
    if not new_name:
        flash("New filename is required.", "warning")
        return redirect(url_for("main.shared"))

    owner_username = record["owner_username"]
    try:
        new_rel = rename_user_item(owner_username, record["relative_path"], new_name)
        # Update share record in DB
        from app.database import db_session
        with db_session() as conn:
            conn.execute(
                "UPDATE shares SET filename = ?, relative_path = ? WHERE id = ?",
                (sanitize_filename(new_name), new_rel, share_id),
            )
        log_activity(user_id, "RENAME", new_name, f"Editor renamed shared file {record['filename']} to {new_name}")
        flash(f"Renamed shared file to '{new_name}' successfully.", "success")
    except Exception as e:
        flash(f"Failed to rename shared file: {str(e)}", "danger")

    return redirect(url_for("main.shared"))


@main_bp.route("/shared/delete/<int:share_id>", methods=["POST"])
@login_required
@csrf_protect
def delete_shared_file(share_id):
    user_id = session["user_id"]
    record = get_share_record_for_user(share_id, user_id)

    if not record:
        abort(404, description="Shared record not found.")

    # Authorization check: only EDITOR can delete
    if record["permission"] != "editor":
        abort(403, description="Permission denied: Viewer role cannot delete shared files.")

    owner_username = record["owner_username"]
    try:
        move_file_to_trash(owner_username, record["owner_id"], record["relative_path"])
        # Remove share record as file is now in trash
        from app.database import db_session
        with db_session() as conn:
            conn.execute("DELETE FROM shares WHERE id = ?", (share_id,))
        log_activity(user_id, "DELETE", record["filename"], f"Editor moved shared file {record['filename']} to owner trash")
        flash(f"Shared file '{record['filename']}' moved to owner's trash.", "info")
    except Exception as e:
        flash(f"Failed to delete shared file: {str(e)}", "danger")

    return redirect(url_for("main.shared"))


# ==========================================
# Search & Trash & Quota & Activity
# ==========================================

@main_bp.route("/search")
@login_required
def search():
    username = session["username"]
    query = request.args.get("q", "").strip()
    results = []
    if query:
        results = recursive_search_files(username, query)
    return render_template("search.html", query=query, results=results)


@main_bp.route("/trash")
@login_required
def trash():
    user_id = session["user_id"]
    items = list_user_trash(user_id)
    return render_template("trash.html", items=items)


@main_bp.route("/trash/restore/<int:trash_id>", methods=["POST"])
@login_required
@csrf_protect
def restore_trash_item(trash_id):
    username = session["username"]
    user_id = session["user_id"]

    try:
        dest_path = restore_file_from_trash(username, user_id, trash_id)
        flash(f"Item restored successfully to '{dest_path}'.", "success")
    except FileNotFoundError:
        flash("Trash record not found or file missing.", "warning")
    except PermissionError:
        flash("Security violation: Path traversal prevented during restore.", "danger")
    except Exception as e:
        flash(f"Restore failed: {str(e)}", "danger")

    return redirect(url_for("main.trash"))


@main_bp.route("/trash/delete/<int:trash_id>", methods=["POST"])
@login_required
@csrf_protect
def delete_trash_item(trash_id):
    username = session["username"]
    user_id = session["user_id"]

    try:
        permanently_delete_from_trash(username, user_id, trash_id)
        flash("Permanently deleted item from storage.", "info")
    except Exception as e:
        flash(f"Permanent deletion failed: {str(e)}", "danger")

    return redirect(url_for("main.trash"))


@main_bp.route("/trash/empty", methods=["POST"])
@login_required
@csrf_protect
def empty_trash():
    username = session["username"]
    user_id = session["user_id"]

    try:
        empty_user_trash(username, user_id)
        flash("Trash has been completely emptied.", "info")
    except Exception as e:
        flash(f"Failed to empty trash: {str(e)}", "danger")

    return redirect(url_for("main.trash"))


@main_bp.route("/quota")
@login_required
def quota():
    username = session["username"]
    quota_info = get_user_quota_info(username)
    return render_template("quota.html", quota=quota_info)


@main_bp.route("/activity")
@login_required
def activity():
    user_id = session["user_id"]
    logs = get_user_activity(user_id, limit=100)
    return render_template("activity.html", logs=logs)


# ==========================================
# Health Endpoint
# ==========================================

@main_bp.route("/health")
def health():
    """
    Health check monitoring endpoint.
    Verifies application runtime, SQLite database read/write, and filesystem storage.
    """
    db_ok = False
    storage_ok = False
    details = {}

    # Check Database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1;")
        result = cursor.fetchone()
        conn.close()
        db_ok = (result is not None)
        details["database"] = "ok" if db_ok else "failed"
    except Exception as e:
        details["database"] = f"error: {str(e)}"

    # Check Storage Filesystem
    try:
        base_dir = get_base_storage_dir()
        test_file = os.path.join(base_dir, ".health_check_test")
        with open(test_file, "w") as f:
            f.write("health_ok")
        if os.path.exists(test_file):
            with open(test_file, "r") as f:
                content = f.read()
            os.remove(test_file)
            storage_ok = (content == "health_ok")
        details["storage"] = "ok" if storage_ok else "failed"
        details["storage_path"] = base_dir
    except Exception as e:
        details["storage"] = f"error: {str(e)}"

    status = "ok" if (db_ok and storage_ok) else "degraded"
    status_code = 200 if status == "ok" else 503

    return jsonify({
        "status": status,
        "database": "connected" if db_ok else "failed",
        "filesystem": "writable" if storage_ok else "failed",
        "app": "StorageOS",
        "version": "1.0.0",
        "checks": details,
    }), status_code


# Entry point when run directly
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
