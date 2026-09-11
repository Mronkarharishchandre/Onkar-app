"""
StorageOS Authentication Layer
User registration, credential verification, session handling, and access decorators.
"""

import hmac
import json
import os
import re
import secrets
import urllib.parse
import urllib.request
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from app.database import (
    create_user,
    get_user_by_username,
    get_user_by_email,
    get_user_by_id,
    log_activity,
    create_or_link_google_user,
    create_password_reset_token,
    verify_password_reset_token,
    consume_password_reset_token,
)
from app.security import (
    validate_username,
    validate_password,
    hash_password,
    verify_password,
    generate_csrf_token,
    validate_csrf_token,
)
from app.email_service import send_password_reset_email
from app.storage import get_user_storage_path

auth_bp = Blueprint("auth", __name__)


def login_required(f):
    """Decorator to protect routes requiring an active authenticated session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or "username" not in session:
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        
        # Verify user still exists in DB
        user = get_user_by_id(session["user_id"])
        if not user:
            session.clear()
            flash("Session expired or user not found. Please log in again.", "danger")
            return redirect(url_for("auth.login"))

        # Verify session has not been invalidated via logout-all
        user_session_ver = user.get("session_version", 1) or 1
        curr_session_ver = session.get("session_version", 1) or 1
        if curr_session_ver < user_session_ver:
            session.clear()
            flash("Your session was signed out from all devices. Please sign in again.", "info")
            return redirect(url_for("auth.login"))
            
        return f(*args, **kwargs)
    return decorated_function


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """Handle new user registration with strong validation."""
    if "user_id" in session:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
        if not validate_csrf_token(token):
            flash("Invalid security token. Please try again.", "danger")
            return render_template("register.html", csrf_token=generate_csrf_token())

        csrf_token = generate_csrf_token()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validate username
        u_valid, u_err = validate_username(username)
        if not u_valid:
            flash(u_err, "danger")
            return render_template("register.html", username=username, csrf_token=csrf_token)

        # Check existing user
        if get_user_by_username(username):
            flash(f"Username already exists: '{username}' is already taken. Please choose another.", "danger")
            return render_template("register.html", username=username, csrf_token=csrf_token)

        # Validate password
        p_valid, p_err = validate_password(password, confirm_password)
        if not p_valid:
            flash(p_err, "danger")
            return render_template("register.html", username=username, csrf_token=csrf_token)

        # Hash password and create user in DB
        pwd_hash = hash_password(password)
        user_id = create_user(username, pwd_hash)

        # Initialize user's isolated storage directory automatically
        get_user_storage_path(username)

        # Record activity log
        log_activity(user_id, "REGISTER", None, f"Registered new account: {username}")

        # Automatically log user in
        session.clear()
        session["user_id"] = user_id
        session["username"] = username
        session["session_version"] = 1
        generate_csrf_token()

        flash(f"Welcome to StorageOS, {username}! Your personal storage volume has been provisioned.", "success")
        return redirect(url_for("main.dashboard"))

    return render_template("register.html", csrf_token=generate_csrf_token())


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Handle user login and authentication."""
    if "user_id" in session:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
        if not validate_csrf_token(token):
            flash("Invalid security token. Please try again.", "danger")
            return render_template("login.html", csrf_token=generate_csrf_token())

        csrf_token = generate_csrf_token()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Both username and password are required.", "danger")
            return render_template("login.html", username=username, csrf_token=csrf_token)

        user = get_user_by_username(username)
        if not user or not verify_password(user["password_hash"], password):
            flash("Invalid username or password.", "danger")
            return render_template("login.html", username=username, csrf_token=csrf_token)

        # Successful authentication
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["session_version"] = user.get("session_version", 1) or 1
        generate_csrf_token()

        # Ensure user storage exists
        get_user_storage_path(user["username"])

        log_activity(user["id"], "LOGIN", None, f"Successful login from user {user['username']}")

        next_url = request.args.get("next")
        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)

        return redirect(url_for("main.dashboard"))

    return render_template("login.html", csrf_token=generate_csrf_token())


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    """Handle session termination and log user out."""
    user_id = session.get("user_id")
    username = session.get("username")

    if user_id:
        log_activity(user_id, "LOGOUT", None, f"User {username} logged out")

    session.clear()
    flash("You have been securely signed out.", "info")
    return redirect(url_for("auth.login"))


def get_app_base_url() -> str:
    """Return the application base URL from environment or request headers."""
    base = os.environ.get("APP_BASE_URL") or os.environ.get("APP_URL")
    if base:
        return base.rstrip("/")
    proto = request.headers.get("X-Forwarded-Proto", request.scheme)
    host = request.headers.get("X-Forwarded-Host", request.host)
    return f"{proto}://{host}"


def get_google_redirect_uri() -> str:
    """Return the absolute Google OAuth callback URI."""
    configured = os.environ.get("GOOGLE_REDIRECT_URI")
    if configured:
        return configured
    return f"{get_app_base_url()}/google/callback"


EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


@auth_bp.route("/google")
def google_login():
    """Initiate Google OAuth 2.0 / OIDC login flow."""
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    if not client_id:
        flash(
            "Google Login is currently not configured on this instance. To enable it, specify GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in the environment.",
            "warning",
        )
        return redirect(url_for("auth.login"))

    # Generate state token for CSRF protection
    state = secrets.token_urlsafe(32)
    session["google_oauth_state"] = state

    redirect_uri = get_google_redirect_uri()
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)
    return redirect(auth_url)


@auth_bp.route("/google/url")
def google_auth_url():
    """Return the Google OAuth authorization URL for iframe / popup authentication."""
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    if not client_id:
        return jsonify({
            "configured": False,
            "message": "Google Login is currently not configured on this instance. To enable it, specify GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in the environment.",
        }), 200

    state = secrets.token_urlsafe(32)
    session["google_oauth_state"] = state

    redirect_uri = get_google_redirect_uri()
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)
    return jsonify({
        "configured": True,
        "url": auth_url,
        "redirect_url": url_for("main.dashboard"),
    })


@auth_bp.route("/google/callback", methods=["GET", "POST"])
def google_callback():
    """Handle the OAuth 2.0 callback from Google with ID token verification."""
    error = request.args.get("error") or request.form.get("error")
    if error:
        flash(f"Google authorization was cancelled or failed: {error}", "danger")
        return render_template("oauth_callback.html", success=False, error=f"Google authorization failed: {error}")

    code = request.args.get("code") or request.form.get("code")
    state = request.args.get("state") or request.form.get("state")

    expected_state = session.pop("google_oauth_state", None)
    if not state or not expected_state or not hmac.compare_digest(state, expected_state):
        error_msg = "Google login failed: Invalid or expired OAuth state token."
        flash(error_msg, "danger")
        return render_template("oauth_callback.html", success=False, error=error_msg)

    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    redirect_uri = get_google_redirect_uri()

    if not client_id or not client_secret or not code:
        error_msg = "Google OAuth credentials or authorization code missing."
        flash(error_msg, "danger")
        return render_template("oauth_callback.html", success=False, error=error_msg)

    # Exchange authorization code for tokens
    try:
        token_data = urllib.parse.urlencode({
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://oauth2.googleapis.com/token",
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            token_res = json.loads(resp.read().decode("utf-8"))

        id_token = token_res.get("id_token")
        access_token = token_res.get("access_token")

        if not id_token and not access_token:
            error_msg = "Failed to retrieve tokens from Google."
            flash(error_msg, "danger")
            return render_template("oauth_callback.html", success=False, error=error_msg)

        # Server-side verification of ID token
        email = None
        google_id = None
        display_name = None
        avatar_url = None

        if id_token:
            # Verify ID token using Google tokeninfo endpoint
            verify_req = urllib.request.Request(
                f"https://oauth2.googleapis.com/tokeninfo?id_token={urllib.parse.quote(id_token)}"
            )
            with urllib.request.urlopen(verify_req, timeout=10) as resp:
                tokeninfo = json.loads(resp.read().decode("utf-8"))

            token_aud = tokeninfo.get("aud")
            token_iss = tokeninfo.get("iss")
            email_verified = tokeninfo.get("email_verified")

            # Validate audience matches client_id
            if token_aud != client_id:
                error_msg = "Google token validation failed: Invalid client audience."
                flash(error_msg, "danger")
                return render_template("oauth_callback.html", success=False, error=error_msg)

            # Validate issuer
            if token_iss not in ("accounts.google.com", "https://accounts.google.com"):
                error_msg = "Google token validation failed: Invalid token issuer."
                flash(error_msg, "danger")
                return render_template("oauth_callback.html", success=False, error=error_msg)

            if email_verified not in (True, "true", "True", 1):
                error_msg = "Google account email is not verified."
                flash(error_msg, "danger")
                return render_template("oauth_callback.html", success=False, error=error_msg)

            email = tokeninfo.get("email")
            google_id = tokeninfo.get("sub")
            display_name = tokeninfo.get("name")
            avatar_url = tokeninfo.get("picture")

        elif access_token:
            # Fallback to userinfo endpoint if id_token was absent
            userinfo_req = urllib.request.Request(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            with urllib.request.urlopen(userinfo_req, timeout=10) as resp:
                userinfo = json.loads(resp.read().decode("utf-8"))

            email = userinfo.get("email")
            google_id = userinfo.get("sub")
            display_name = userinfo.get("name")
            avatar_url = userinfo.get("picture")

        if not email or not google_id:
            error_msg = "Google account did not provide a verified email address."
            flash(error_msg, "danger")
            return render_template("oauth_callback.html", success=False, error=error_msg)

        user = create_or_link_google_user(email, google_id, display_name, avatar_url)

        # Initialize storage volume
        get_user_storage_path(user["username"])

        # Authenticate user session
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["display_name"] = user.get("display_name") or user["username"]
        session["avatar_url"] = user.get("avatar_url")
        session["lang"] = user.get("language") or "en"
        session["theme"] = user.get("theme") or "system"
        session["session_version"] = user.get("session_version", 1) or 1
        session["_csrf_token"] = generate_csrf_token()

        log_activity(user["id"], "LOGIN", None, f"Google OAuth login for {user['username']} ({email})")
        flash(f"Signed in successfully with Google. Welcome, {user.get('display_name') or user['username']}!", "success")
        return render_template(
            "oauth_callback.html",
            success=True,
            redirect_url=url_for("main.dashboard"),
        )

    except Exception as e:
        error_msg = f"Google login failed: {str(e)}"
        flash(error_msg, "danger")
        return render_template("oauth_callback.html", success=False, error=error_msg)


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Handle password reset requests and send tokenized email links."""
    if "user_id" in session:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
        if not validate_csrf_token(token):
            flash("Invalid security token. Please try again.", "danger")
            return render_template("forgot_password.html", csrf_token=generate_csrf_token())

        csrf_token = generate_csrf_token()
        email = request.form.get("email", "").strip().lower()

        if not email or not EMAIL_REGEX.match(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("forgot_password.html", email=email, csrf_token=csrf_token)

        # Look up user by email
        user = get_user_by_email(email)
        dev_reset_url = None

        if user:
            # Generate single-use secure reset token (valid for 30 minutes)
            raw_token = create_password_reset_token(user["id"], expires_minutes=30)
            base_url = get_app_base_url()
            reset_url = f"{base_url}/reset-password?token={raw_token}"

            # Deliver reset email or log to console in dev mode
            recipient_name = user.get("display_name") or user.get("username")
            email_result = send_password_reset_email(user["email"], reset_url, username=recipient_name)

            log_activity(user["id"], "PASSWORD_RESET_REQUEST", None, f"Password reset requested for {email}")

            if email_result.get("dev_mode"):
                dev_reset_url = email_result.get("reset_url")

        # Anti-enumeration: Return the exact same message regardless of whether the email exists
        flash("If an account exists for this email, a password reset link has been sent.", "info")
        return render_template("forgot_password.html", csrf_token=csrf_token, dev_reset_url=dev_reset_url)

    return render_template("forgot_password.html", csrf_token=generate_csrf_token())


@auth_bp.route("/reset-password", methods=["GET", "POST"])
@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token=None):
    """Verify reset token and update the user's password."""
    if "user_id" in session:
        return redirect(url_for("main.dashboard"))

    raw_token = token or request.args.get("token") or request.form.get("token", "").strip()

    if not raw_token:
        flash("Password reset token is required. Please request a new link.", "danger")
        return redirect(url_for("auth.forgot_password"))

    # Verify validity of token
    reset_record = verify_password_reset_token(raw_token)
    if not reset_record:
        flash("Invalid or expired password reset link. Please request a new one.", "danger")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        csrf_val = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
        if not validate_csrf_token(csrf_val):
            flash("Invalid security token. Please try again.", "danger")
            return render_template("reset_password.html", token=raw_token, csrf_token=generate_csrf_token())

        csrf_token = generate_csrf_token()
        new_password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validate password strength and confirmation match
        p_valid, p_err = validate_password(new_password, confirm_password)
        if not p_valid:
            flash(p_err, "danger")
            return render_template("reset_password.html", token=raw_token, csrf_token=csrf_token)

        # Hash new password securely with argon2id / werkzeug pbkdf2
        pwd_hash = hash_password(new_password)

        # Atomically update user password, consume token, and invalidate prior sessions
        success = consume_password_reset_token(raw_token, pwd_hash)
        if not success:
            flash("Failed to reset password. The link may have expired or already been used.", "danger")
            return redirect(url_for("auth.forgot_password"))

        log_activity(
            reset_record["user_id"],
            "PASSWORD_RESET_COMPLETE",
            None,
            f"Password reset successfully completed for {reset_record['username']}",
        )

        flash("Your password has been successfully reset. You can now sign in with your new password.", "success")
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html", token=raw_token, csrf_token=generate_csrf_token())

