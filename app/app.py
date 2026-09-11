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
from werkzeug.middleware.proxy_fix import ProxyFix
from flask.sessions import SecureCookieSessionInterface
from app.security import get_or_create_secret_key

from app.database import (
    init_db,
    get_user_by_id,
    get_user_activity,
    log_activity,
    list_all_other_usernames,
    get_db_connection,
    create_share_link,
    get_share_link_by_token,
    increment_share_link_views,
    revoke_share_link,
    list_user_share_links,
    update_user_preferences,
    update_user_password,
    increment_user_session_version,
)
from app.auth import auth_bp, login_required
from app.security import (
    get_safe_user_path,
    sanitize_filename,
    generate_csrf_token,
    csrf_protect,
    hash_password,
    verify_password,
    validate_password,
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
from app.i18n import get_translation, SUPPORTED_LANGUAGES, TRANSLATIONS

main_bp = Blueprint("main", __name__)


class DynamicSecureSessionInterface(SecureCookieSessionInterface):
    """
    Session interface optimized for both standard web browsing and embedded iframe previews.
    Ensures cookies work reliably in:
    1. Cross-origin HTTPS iframes (e.g. AI Studio preview) using SameSite=None; Secure; Partitioned
    2. Direct HTTPS tab access using Secure cookies
    3. Local development and test environments over plain HTTP
    """
    def _is_secure_context(self, app) -> bool:
        # Check explicit configuration, ignoring placeholder artifacts like '6'
        config_val = app.config.get("SESSION_COOKIE_SECURE")
        if config_val is not None and str(config_val).lower() not in ("auto", "", "6", "none"):
            return bool(config_val)

        try:
            # 1. Check Flask request is_secure
            if getattr(request, "is_secure", False):
                return True
            # 2. Check WSGI url scheme
            if request.environ.get("wsgi.url_scheme") == "https":
                return True
            # 3. Check X-Forwarded-Proto header
            fwd_proto = request.headers.get("X-Forwarded-Proto", "").lower()
            if "https" in fwd_proto:
                return True
            # 4. Check if host indicates Cloud Run preview domain
            host = request.headers.get("X-Forwarded-Host", "") or request.host or ""
            if ".run.app" in host.lower():
                return True
        except Exception:
            pass
        return False

    def get_cookie_secure(self, app):
        return self._is_secure_context(app)

    def get_cookie_samesite(self, app):
        # If explicitly set to a valid SameSite value, respect it
        config_val = app.config.get("SESSION_COOKIE_SAMESITE")
        if config_val and str(config_val).lower() not in ("auto", "", "6", "default"):
            return config_val

        # In HTTPS / Cloud Run / preview environments, SameSite MUST be 'None'
        # so browsers do not drop or block cookies inside preview iframes
        if self._is_secure_context(app):
            return "None"

        return "Lax"

    def save_session(self, app, session, response):
        super().save_session(app, session, response)

        # In secure contexts, ensure the session cookie has Secure, SameSite=None, and CHIPS Partitioned
        # This enables full compatibility with modern browsers (Chrome 115+) inside embedded iframes
        if self._is_secure_context(app):
            set_cookies = response.headers.getlist("Set-Cookie")
            if set_cookies:
                cookie_name = self.get_cookie_name(app)
                new_cookies = []
                for c in set_cookies:
                    if c.startswith(cookie_name + "=") or f"; {cookie_name}=" in c:
                        if "Secure" not in c:
                            c = c + "; Secure"
                        if "SameSite" not in c:
                            c = c + "; SameSite=None"
                        elif "SameSite=None" in c and "Partitioned" not in c:
                            c = c + "; Partitioned"
                    new_cookies.append(c)
                del response.headers["Set-Cookie"]
                for nc in new_cookies:
                    response.headers.add("Set-Cookie", nc)


def create_app(test_config=None):
    """Application factory for StorageOS."""
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # Load configuration with stable persistent secret key
    secret_key = get_or_create_secret_key()

    # Session cookie security configuration
    session_cookie_secure_env = os.environ.get("SESSION_COOKIE_SECURE", "").strip()
    if session_cookie_secure_env and session_cookie_secure_env.lower() in ("true", "1", "yes"):
        cookie_secure_val = True
    elif session_cookie_secure_env and session_cookie_secure_env.lower() in ("false", "0", "no"):
        cookie_secure_val = False
    else:
        cookie_secure_val = None  # Auto-detect via DynamicSecureSessionInterface

    session_cookie_samesite_env = os.environ.get("SESSION_COOKIE_SAMESITE", "").strip()
    if session_cookie_samesite_env and session_cookie_samesite_env.lower() in ("none", "lax", "strict"):
        session_cookie_samesite = session_cookie_samesite_env
    else:
        session_cookie_samesite = None  # Auto-detect via DynamicSecureSessionInterface

    app.config.from_mapping(
        SECRET_KEY=secret_key,
        MAX_CONTENT_LENGTH=100 * 1024 * 1024,  # 100 MB max upload
        SESSION_COOKIE_NAME="storageos_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=session_cookie_samesite,
        SESSION_COOKIE_SECURE=cookie_secure_val,
    )
    app.session_interface = DynamicSecureSessionInterface()

    if test_config:
        app.config.update(test_config)

    # Initialize SQLite database
    init_db()

    # Context processors for template rendering
    @app.context_processor
    def inject_globals():
        user = None
        quota_info = None
        current_lang = session.get("lang", "en")
        current_theme = session.get("theme", "system")

        if "user_id" in session and "username" in session:
            try:
                db_user = get_user_by_id(session["user_id"])
                if db_user:
                    user = {
                        "id": db_user["id"],
                        "username": db_user["username"],
                        "display_name": db_user.get("display_name") or db_user["username"],
                        "email": db_user.get("email"),
                        "avatar_url": db_user.get("avatar_url"),
                        "theme": db_user.get("theme") or current_theme,
                        "language": db_user.get("language") or current_lang,
                        "created_at": db_user.get("created_at"),
                    }
                    if "lang" not in session and db_user.get("language"):
                        session["lang"] = db_user["language"]
                        current_lang = db_user["language"]
                    if "theme" not in session and db_user.get("theme"):
                        session["theme"] = db_user["theme"]
                        current_theme = db_user["theme"]
                else:
                    user = {"id": session["user_id"], "username": session["username"]}
            except Exception:
                user = {"id": session["user_id"], "username": session["username"]}

            try:
                quota_info = get_user_quota_info(session["username"])
            except Exception:
                pass

        def translate(key, default=None):
            return get_translation(key, lang=session.get("lang", "en"), default=default)

        return {
            "current_user": user,
            "csrf_token": generate_csrf_token(),
            "global_quota": quota_info,
            "current_lang": session.get("lang", "en"),
            "current_theme": session.get("theme", "system"),
            "supported_languages": SUPPORTED_LANGUAGES,
            "translations": TRANSLATIONS,
            "t": translate,
            "google_login_enabled": bool(os.environ.get("GOOGLE_CLIENT_ID")),
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

    # Configure ProxyFix for reverse proxies (Nginx, Node gateway, Cloud Run)
    # Allows Flask to detect X-Forwarded-Proto (https/http), X-Forwarded-Host, and client IP
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1,
        x_port=1,
        x_prefix=1,
    )

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

    db_user = get_user_by_id(user_id) or {}
    sort_pref = db_user.get("sort_preference", "name_asc") or "name_asc"
    file_view = db_user.get("file_view", "list") or "list"
    confirm_del = db_user.get("confirm_delete", 1)
    if confirm_del is None:
        confirm_del = 1

    # Apply user sorting preference
    folders = data["folders"]
    files_list = data["files"]
    if sort_pref == "name_desc":
        folders.sort(key=lambda f: f["name"].lower(), reverse=True)
        files_list.sort(key=lambda f: f["name"].lower(), reverse=True)
    elif sort_pref == "date_desc":
        folders.sort(key=lambda f: f.get("modified", ""), reverse=True)
        files_list.sort(key=lambda f: f.get("modified", ""), reverse=True)
    elif sort_pref == "date_asc":
        folders.sort(key=lambda f: f.get("modified", ""))
        files_list.sort(key=lambda f: f.get("modified", ""))
    elif sort_pref == "size_desc":
        files_list.sort(key=lambda f: f.get("size_bytes", 0), reverse=True)
    elif sort_pref == "size_asc":
        files_list.sort(key=lambda f: f.get("size_bytes", 0))
    else:  # name_asc (default)
        folders.sort(key=lambda f: f["name"].lower())
        files_list.sort(key=lambda f: f["name"].lower())

    return render_template(
        "files.html",
        current_path=data["current_path"],
        breadcrumbs=data["breadcrumbs"],
        folders=folders,
        files=files_list,
        quota=quota,
        other_users=other_users,
        file_view=file_view,
        sort_preference=sort_pref,
        confirm_delete=confirm_del,
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
    public_links = list_user_share_links(user_id)
    return render_template(
        "shared.html",
        shared_with_me=shared_with_me,
        shared_by_me=shared_by_me,
        public_links=public_links,
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
        flash(f"Shared '{os.path.basename(relative_path)}' with {target_username} as {permission.upper()} successfully.", "success")
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
# Localization & Theme Switcher
# ==========================================

@main_bp.route("/set-language", methods=["POST"])
def set_language():
    """Update active UI language in session and database."""
    lang = request.form.get("language", "en").strip().lower()
    if lang in SUPPORTED_LANGUAGES:
        session["lang"] = lang
        if "user_id" in session:
            try:
                update_user_preferences(session["user_id"], language=lang)
            except Exception:
                pass
    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json or "application/json" in request.headers.get("Accept", ""):
        return jsonify({"status": "ok", "lang": lang})
    next_url = request.form.get("next") or request.referrer or url_for("main.dashboard")
    return redirect(next_url)


@main_bp.route("/set-theme", methods=["POST"])
def set_theme():
    """Update active UI theme in session and database."""
    theme = request.form.get("theme", "system").strip().lower()
    if theme in ("light", "dark", "system"):
        session["theme"] = theme
        if "user_id" in session:
            try:
                update_user_preferences(session["user_id"], theme=theme)
            except Exception:
                pass
    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json or "application/json" in request.headers.get("Accept", ""):
        return jsonify({"status": "ok", "theme": theme})
    next_url = request.form.get("next") or request.referrer or url_for("main.dashboard")
    return redirect(next_url)


# ==========================================
# File Preview & Streaming
# ==========================================

@main_bp.route("/files/raw/<path:rel_path>")
@login_required
def serve_raw_file(rel_path):
    """Safely stream a file for in-browser preview (images, PDF, audio, video)."""
    username = session["username"]
    user_root = get_user_storage_path(username)
    try:
        safe_path = get_safe_user_path(user_root, rel_path)
        if not os.path.exists(safe_path) or not os.path.isfile(safe_path):
            abort(404, description="File not found")
        return send_file(safe_path, as_attachment=False)
    except PermissionError:
        abort(403, description="Path traversal prevented")


@main_bp.route("/api/preview-info")
@login_required
def preview_info():
    """Retrieve file metadata and text preview if applicable for the modal previewer."""
    username = session["username"]
    rel_path = request.args.get("rel_path", "").strip()
    if not rel_path:
        return jsonify({"error": "No path provided"}), 400

    user_root = get_user_storage_path(username)
    try:
        safe_path = get_safe_user_path(user_root, rel_path)
        if not os.path.exists(safe_path) or not os.path.isfile(safe_path):
            return jsonify({"error": "File not found"}), 404

        filename = os.path.basename(safe_path)
        ext = os.path.splitext(filename)[1].lower()
        size_bytes = os.path.getsize(safe_path)
        size_str = format_bytes(size_bytes)
        mod_time = os.path.getmtime(safe_path)
        from datetime import datetime
        mod_str = datetime.fromtimestamp(mod_time).strftime("%Y-%m-%d %H:%M")

        img_exts = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp", ".ico"}
        pdf_exts = {".pdf"}
        media_exts = {".mp3", ".wav", ".ogg", ".mp4", ".webm", ".m4a"}
        text_exts = {
            ".txt", ".md", ".json", ".csv", ".py", ".js", ".html", ".css", ".sh",
            ".yml", ".yaml", ".xml", ".sql", ".ts", ".ini", ".conf", ".log",
            ".dockerfile", ".gitignore", ".env", ".c", ".cpp", ".h", ".rs", ".go"
        }

        category = "binary"
        raw_url = url_for("main.serve_raw_file", rel_path=rel_path)
        download_url = url_for("main.download_file", rel_path=rel_path)
        text_content = None

        if ext in img_exts:
            category = "image"
        elif ext in pdf_exts:
            category = "pdf"
        elif ext in media_exts:
            category = "media"
        elif ext in text_exts or size_bytes < 512 * 1024:
            try:
                with open(safe_path, "r", encoding="utf-8", errors="replace") as f:
                    text_content = f.read(500000)
                category = "text"
            except Exception:
                category = "binary"

        return jsonify({
            "filename": filename,
            "relative_path": rel_path,
            "size_formatted": size_str,
            "size_bytes": size_bytes,
            "modified": mod_str,
            "category": category,
            "raw_url": raw_url,
            "download_url": download_url,
            "text_content": text_content,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==========================================
# Secure Public Share Links (/share/<token>)
# ==========================================

@main_bp.route("/share-link/create", methods=["POST"])
@login_required
@csrf_protect
def create_public_share_link():
    """Create a tokenized public share link with optional password and expiration."""
    user_id = session["user_id"]
    username = session["username"]
    rel_path = request.form.get("relative_path", "").strip()
    password = request.form.get("password", "").strip()
    expires_hours_str = request.form.get("expires_hours", "0").strip()

    if not rel_path:
        return jsonify({"error": "Path is required"}), 400

    user_root = get_user_storage_path(username)
    try:
        safe_path = get_safe_user_path(user_root, rel_path)
        if not os.path.exists(safe_path) or not os.path.isfile(safe_path):
            return jsonify({"error": "File does not exist"}), 404

        filename = os.path.basename(safe_path)
        pwd_hash = hash_password(password) if password else None
        expires_hours = int(expires_hours_str) if expires_hours_str.isdigit() else 0

        token = create_share_link(user_id, rel_path, filename, pwd_hash, expires_hours)
        share_url = url_for("main.view_shared_link", token=token, _external=True)

        log_activity(user_id, "SHARE_LINK", filename, f"Created public share link for {filename}")

        wants_json = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json or "application/json" in request.headers.get("Accept", "")
        if wants_json:
            return jsonify({
                "success": True,
                "token": token,
                "share_url": share_url,
                "filename": filename,
            })

        flash(f"Public share link generated for '{filename}'.", "success")
        return redirect(request.referrer or url_for("main.files"))

    except Exception as e:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
            return jsonify({"error": str(e)}), 500
        flash(f"Failed to create share link: {str(e)}", "danger")
        return redirect(request.referrer or url_for("main.files"))


@main_bp.route("/share/<token>", methods=["GET", "POST"])
def view_shared_link(token):
    """Public viewing and download page for tokenized share links."""
    record = get_share_link_by_token(token)
    if not record:
        return render_template("error.html", code=404, title="Share Link Not Found", message="This share link does not exist or has expired."), 404

    owner_username = record["owner_username"]
    owner_root = get_user_storage_path(owner_username)
    try:
        safe_path = get_safe_user_path(owner_root, record["relative_path"])
        if not os.path.exists(safe_path) or not os.path.isfile(safe_path):
            return render_template("error.html", code=404, title="File Not Found", message="The shared file is no longer available on this server."), 404
    except PermissionError:
        abort(403)

    password_required = bool(record["password_hash"])
    authenticated = not password_required or session.get(f"share_authed_{token}")

    if request.method == "POST" and password_required and not authenticated:
        entered_pwd = request.form.get("password", "")
        if verify_password(record["password_hash"], entered_pwd):
            session[f"share_authed_{token}"] = True
            authenticated = True
        else:
            flash("Incorrect password for this share link.", "danger")

    file_size = os.path.getsize(safe_path)
    ext = os.path.splitext(record["filename"])[1].lower()

    return render_template(
        "share_view.html",
        record=record,
        token=token,
        filename=record["filename"],
        size_formatted=format_bytes(file_size),
        password_required=password_required,
        authenticated=authenticated,
        ext=ext,
    )


@main_bp.route("/share/<token>/download")
def download_shared_token_file(token):
    """Download the file behind a public share link."""
    record = get_share_link_by_token(token)
    if not record:
        abort(404, description="Link invalid or expired.")

    if record["password_hash"] and not session.get(f"share_authed_{token}"):
        abort(403, description="Password authentication required for this download.")

    owner_username = record["owner_username"]
    owner_root = get_user_storage_path(owner_username)
    try:
        safe_path = get_safe_user_path(owner_root, record["relative_path"])
        if not os.path.exists(safe_path) or not os.path.isfile(safe_path):
            abort(404, description="Shared file no longer exists.")

        increment_share_link_views(token)
        return send_file(safe_path, as_attachment=True, download_name=record["filename"])
    except PermissionError:
        abort(403)


@main_bp.route("/share-link/revoke/<int:link_id>", methods=["POST"])
@login_required
@csrf_protect
def revoke_public_share_link(link_id):
    """Revoke a public share link."""
    user_id = session["user_id"]
    try:
        revoke_share_link(link_id, user_id)
        flash("Public share link revoked.", "info")
    except Exception as e:
        flash(f"Failed to revoke share link: {str(e)}", "danger")
    return redirect(url_for("main.shared"))


# ==========================================
# Settings & Profile Routes
# ==========================================

@main_bp.route("/profile")
@main_bp.route("/settings")
@login_required
def settings():
    """Enterprise user profile, appearance, language, security and system settings."""
    user_id = session.get("user_id")
    username = session.get("username", "")

    # Retrieve user record safely
    db_user = None
    try:
        if user_id:
            db_user = get_user_by_id(user_id)
    except Exception:
        db_user = None

    if not db_user:
        db_user = {
            "id": user_id,
            "username": username,
            "display_name": session.get("display_name") or username,
            "email": "",
            "avatar_url": None,
            "theme": session.get("theme", "system"),
            "language": session.get("lang", "en"),
            "file_view": "list",
            "sort_preference": "name_asc",
            "confirm_delete": 1,
        }

    # Retrieve storage quota statistics safely from real StorageOS data
    try:
        quota_info = get_user_quota_info(username) if username else None
    except Exception:
        quota_info = None

    if not quota_info:
        quota_info = {
            "used_bytes": 0,
            "total_bytes": 1024 * 1024 * 1024,
            "available_bytes": 1024 * 1024 * 1024,
            "used_formatted": "0 B",
            "total_formatted": "1.0 GB",
            "quota_formatted": "1.0 GB",
            "available_formatted": "1.0 GB",
            "percentage": 0.0,
            "percent_used": 0.0,
            "is_exceeded": False,
        }

    recent_logs = []
    try:
        if user_id:
            recent_logs = get_user_activity(user_id, limit=5)
    except Exception:
        recent_logs = []

    share_links = []
    try:
        if user_id:
            share_links = list_user_share_links(user_id)
    except Exception:
        share_links = []

    # Health & System Status verification for About StorageOS
    db_ok = False
    storage_ok = False
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1;")
        res = cursor.fetchone()
        conn.close()
        db_ok = (res is not None)
    except Exception:
        db_ok = False

    try:
        base_dir = get_base_storage_dir()
        storage_ok = os.path.exists(base_dir) and os.access(base_dir, os.W_OK)
    except Exception:
        storage_ok = False

    system_status = {
        "version": "1.0.0",
        "edition": "Enterprise Edition",
        "status": "Operational" if (db_ok and storage_ok) else "Degraded",
        "database": "SQLite Enterprise (Connected)" if db_ok else "Database Degraded",
        "storage": "Isolated User Volumes (Active)" if storage_ok else "Storage Degraded",
        "security": "Argon2 / PBKDF2 & CSRF Protected",
        "platform": "StorageOS Cloud Architecture",
    }

    return render_template(
        "settings.html",
        user=db_user,
        quota=quota_info,
        recent_logs=recent_logs,
        share_links=share_links,
        system_status=system_status,
    )


@main_bp.route("/settings/account", methods=["POST"])
@login_required
@csrf_protect
def update_account_settings():
    """Update user display name and email address."""
    user_id = session["user_id"]
    display_name = request.form.get("display_name", "").strip()
    email = request.form.get("email", "").strip()

    update_user_preferences(user_id, display_name=display_name, email=email)
    if display_name:
        session["display_name"] = display_name
    flash("Account details updated successfully.", "success")
    return redirect(url_for("main.settings"))


@main_bp.route("/settings/appearance", methods=["POST"])
@main_bp.route("/settings/preferences", methods=["POST"])
@login_required
@csrf_protect
def update_preferences():
    """Update appearance, localization, and general user preferences."""
    user_id = session["user_id"]
    display_name = request.form.get("display_name")
    email = request.form.get("email")
    theme = request.form.get("theme", "").strip().lower()
    lang = request.form.get("language", "").strip().lower()
    file_view = request.form.get("file_view", "").strip().lower()
    sort_pref = request.form.get("sort_preference", "").strip()
    confirm_del_raw = request.form.get("confirm_delete")

    confirm_del = None
    if "confirm_delete" in request.form or "has_confirm_delete_field" in request.form:
        confirm_del = 1 if confirm_del_raw in ("1", "true", "on", "yes") else 0

    if theme and theme not in ("light", "dark", "system"):
        theme = "system"
    if lang and lang not in SUPPORTED_LANGUAGES:
        lang = "en"

    update_user_preferences(
        user_id,
        theme=theme if theme else None,
        language=lang if lang else None,
        display_name=display_name.strip() if display_name is not None else None,
        email=email.strip() if email is not None else None,
        file_view=file_view if file_view in ("list", "grid") else None,
        sort_preference=sort_pref if sort_pref else None,
        confirm_delete=confirm_del,
    )

    if theme:
        session["theme"] = theme
    if lang:
        session["lang"] = lang
    if display_name:
        session["display_name"] = display_name.strip()

    flash("Preferences updated successfully.", "success")
    return redirect(url_for("main.settings"))


@main_bp.route("/settings/file-preferences", methods=["POST"])
@login_required
@csrf_protect
def update_file_preferences():
    """Update file manager viewing and sorting preferences."""
    user_id = session["user_id"]
    file_view = request.form.get("file_view", "list").strip().lower()
    if file_view not in ("list", "grid"):
        file_view = "list"

    sort_pref = request.form.get("sort_preference", "name_asc").strip()
    valid_sorts = ("name_asc", "name_desc", "date_desc", "date_asc", "size_desc", "size_asc")
    if sort_pref not in valid_sorts:
        sort_pref = "name_asc"

    confirm_del = 1 if request.form.get("confirm_delete") in ("1", "true", "on", "yes") else 0

    update_user_preferences(
        user_id,
        file_view=file_view,
        sort_preference=sort_pref,
        confirm_delete=confirm_del,
    )
    flash("File preferences updated successfully.", "success")
    return redirect(url_for("main.settings"))


@main_bp.route("/api/preferences/view", methods=["POST"])
@login_required
def api_set_view_preference():
    """AJAX endpoint for toggling list/grid view directly in the file browser."""
    data = request.get_json(silent=True) or request.form
    mode = data.get("view", "list").strip().lower()
    if mode in ("list", "grid"):
        update_user_preferences(session["user_id"], file_view=mode)
        return jsonify({"success": True, "file_view": mode})
    return jsonify({"success": False, "error": "Invalid view mode"}), 400


@main_bp.route("/settings/logout-all", methods=["POST"])
@login_required
@csrf_protect
def logout_all_sessions():
    """Terminate and invalidate all active sessions across all devices."""
    user_id = session["user_id"]
    username = session["username"]
    increment_user_session_version(user_id)
    log_activity(user_id, "LOGOUT_ALL", None, f"User {username} signed out from all sessions")
    session.clear()
    flash("You have been signed out from all active devices and sessions.", "info")
    return redirect(url_for("auth.login"))


@main_bp.route("/settings/password", methods=["POST"])
@login_required
@csrf_protect
def update_password_route():
    """Update user password with credential verification."""
    user_id = session["user_id"]
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    user = get_user_by_id(user_id)
    if not user or not verify_password(user["password_hash"], current_password):
        flash("Current password verification failed.", "danger")
        return redirect(url_for("main.settings"))

    valid, err = validate_password(new_password, confirm_password)
    if not valid:
        flash(err, "danger")
        return redirect(url_for("main.settings"))

    new_hash = hash_password(new_password)
    update_user_password(user_id, new_hash)
    log_activity(user_id, "PASSWORD_CHANGE", None, "User changed account password")
    flash("Password updated successfully.", "success")
    return redirect(url_for("main.settings"))


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
