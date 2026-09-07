"""
StorageOS Authentication Layer
User registration, credential verification, session handling, and access decorators.
"""

from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.database import (
    create_user,
    get_user_by_username,
    get_user_by_id,
    log_activity,
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
