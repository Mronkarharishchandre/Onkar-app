"""
StorageOS Authentication Layer
User registration, credential verification, session handling, and access decorators.
"""

import os
import json
import secrets
import urllib.parse
import urllib.request
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.database import (
    create_user,
    get_user_by_username,
    get_user_by_id,
    log_activity,
    create_or_link_google_user,
)
from app.security import (
    validate_username,
    validate_password,
    hash_password,
    verify_password,
    generate_csrf_token,
    validate_csrf_token,
)
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

    csrf_token = generate_csrf_token()

    if request.method == "POST":
        token = request.form.get("csrf_token")
        if not validate_csrf_token(token):
            flash("Invalid security token. Please try again.", "danger")
            return render_template("register.html", csrf_token=csrf_token)

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
        session["_csrf_token"] = generate_csrf_token()

        flash(f"Welcome to StorageOS, {username}! Your personal storage volume has been provisioned.", "success")
        return redirect(url_for("main.dashboard"))

    return render_template("register.html", csrf_token=csrf_token)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Handle user login and authentication."""
    if "user_id" in session:
        return redirect(url_for("main.dashboard"))

    csrf_token = generate_csrf_token()

    if request.method == "POST":
        token = request.form.get("csrf_token")
        if not validate_csrf_token(token):
            flash("Invalid security token. Please try again.", "danger")
            return render_template("login.html", csrf_token=csrf_token)

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
        session["_csrf_token"] = generate_csrf_token()

        # Ensure user storage exists
        get_user_storage_path(user["username"])

        log_activity(user["id"], "LOGIN", None, f"Successful login from user {user['username']}")

        next_url = request.args.get("next")
        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)

        return redirect(url_for("main.dashboard"))

    return render_template("login.html", csrf_token=csrf_token)


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

    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI")
    if not redirect_uri:
        redirect_uri = url_for("auth.google_callback", _external=True)

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


@auth_bp.route("/google/callback")
def google_callback():
    """Handle the OAuth 2.0 callback from Google."""
    error = request.args.get("error")
    if error:
        flash(f"Google authorization was denied or failed: {error}", "danger")
        return redirect(url_for("auth.login"))

    code = request.args.get("code")
    state = request.args.get("state")

    expected_state = session.pop("google_oauth_state", None)
    if not state or not expected_state or state != expected_state:
        flash("Google login failed: Invalid or expired OAuth state token.", "danger")
        return redirect(url_for("auth.login"))

    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI")
    if not redirect_uri:
        redirect_uri = url_for("auth.google_callback", _external=True)

    if not client_id or not client_secret or not code:
        flash("Google OAuth credentials or authorization code missing.", "danger")
        return redirect(url_for("auth.login"))

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

        access_token = token_res.get("access_token")
        if not access_token:
            flash("Failed to retrieve access token from Google.", "danger")
            return redirect(url_for("auth.login"))

        # Fetch user info
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
            flash("Google account did not provide a verified email address.", "danger")
            return redirect(url_for("auth.login"))

        user = create_or_link_google_user(email, google_id, display_name, avatar_url)

        # Initialize storage
        get_user_storage_path(user["username"])

        # Authenticate session
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
        return redirect(url_for("main.dashboard"))

    except Exception as e:
        flash(f"Google login failed: {str(e)}", "danger")
        return redirect(url_for("auth.login"))

