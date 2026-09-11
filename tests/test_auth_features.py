import os
import shutil
import tempfile
import pytest
from app.app import create_app
from app.database import (
    init_db,
    create_user,
    get_user_by_username,
    get_user_by_email,
    create_password_reset_token,
    verify_password_reset_token,
    consume_password_reset_token,
    update_user_preferences,
)
from app.security import hash_password, verify_password


@pytest.fixture
def app():
    test_dir = tempfile.mkdtemp()
    db_path = os.path.join(test_dir, "test_auth_storageos.db")
    storage_path = os.path.join(test_dir, "storage")

    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": db_path,
        "STORAGE_PATH": storage_path,
        "SECRET_KEY": "test-auth-secret-key",
        "WTF_CSRF_ENABLED": False,
        "APP_BASE_URL": "http://localhost:3000",
    })

    with app.app_context():
        init_db()

    yield app

    shutil.rmtree(test_dir, ignore_errors=True)


@pytest.fixture
def client(app):
    return app.test_client()


def test_forgot_password_get(client):
    """Test forgot password page renders successfully."""
    response = client.get("/forgot-password")
    assert response.status_code == 200
    assert b"Forgot password?" in response.data
    assert b"Send Reset Link" in response.data
    assert b"email" in response.data


def test_login_page_has_forgot_password_link(client):
    """Test login page includes the 'Forgot password?' link."""
    response = client.get("/login")
    assert response.status_code == 200
    assert b"Forgot password?" in response.data
    assert b"/forgot-password" in response.data
    assert b"Sign in with Google" in response.data


def test_forgot_password_post_nonexistent_email(client):
    """Test requesting a reset for a non-existent email returns generic anti-enumeration response."""
    response = client.post("/forgot-password", data={"email": "nonexistent@example.com"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"If an account exists for this email, a password reset link has been sent" in response.data


def test_forgot_password_post_valid_user(app, client):
    """Test requesting a reset for an existing user generates token and displays dev link when SMTP unconfigured."""
    with app.app_context():
        uid = create_user("alice", hash_password("OldPassword123!"))
        update_user_preferences(uid, email="alice@example.com")

    response = client.post("/forgot-password", data={"email": "alice@example.com"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"If an account exists for this email, a password reset link has been sent" in response.data
    # In dev mode, dev reset banner is present
    assert b"Open Password Reset Form" in response.data
    assert b"/reset-password?token=" in response.data


def test_token_creation_and_verification(app):
    """Test cryptographic token creation, verification, and consumption."""
    with app.app_context():
        uid = create_user("bob", hash_password("BobPassword123!"))
        token = create_password_reset_token(uid, expires_minutes=30)
        assert token is not None
        assert len(token) >= 32

        # Verify token
        record = verify_password_reset_token(token)
        assert record is not None
        assert record["user_id"] == uid
        assert record["username"] == "bob"

        # Invalid token verification
        assert verify_password_reset_token("invalid-random-token") is None
        assert verify_password_reset_token("") is None


def test_password_reset_flow_end_to_end(app, client):
    """Test full end-to-end password reset: request -> visit link -> submit new password -> login."""
    with app.app_context():
        uid = create_user("charlie", hash_password("InitialPassword123!"))
        update_user_preferences(uid, email="charlie@example.com")
        raw_token = create_password_reset_token(uid, expires_minutes=30)

    # 1. Access reset password page with valid token
    resp = client.get(f"/reset-password?token={raw_token}")
    assert resp.status_code == 200
    assert b"Reset Password" in resp.data
    assert b"Confirm New Password" in resp.data

    # 2. Submit password mismatch
    resp_mismatch = client.post("/reset-password", data={
        "token": raw_token,
        "password": "BrandNewPassword123!",
        "confirm_password": "DifferentPassword123!",
    }, follow_redirects=True)
    assert resp_mismatch.status_code == 200
    assert b"Passwords do not match" in resp_mismatch.data

    # 3. Submit password too short
    resp_short = client.post("/reset-password", data={
        "token": raw_token,
        "password": "short",
        "confirm_password": "short",
    }, follow_redirects=True)
    assert resp_short.status_code == 200
    assert b"at least 8 characters" in resp_short.data

    # 4. Submit valid new password
    resp_success = client.post("/reset-password", data={
        "token": raw_token,
        "password": "BrandNewPassword123!",
        "confirm_password": "BrandNewPassword123!",
    }, follow_redirects=True)
    assert resp_success.status_code == 200
    assert b"Your password has been successfully reset" in resp_success.data

    # 5. Token is now consumed and single-use
    assert verify_password_reset_token(raw_token) is None
    resp_reuse = client.get(f"/reset-password?token={raw_token}", follow_redirects=True)
    assert b"Invalid or expired password reset link" in resp_reuse.data

    # 6. Old password no longer works
    login_old = client.post("/login", data={
        "username": "charlie",
        "password": "InitialPassword123!",
    }, follow_redirects=True)
    assert b"Invalid username or password" in login_old.data

    # 7. New password works
    login_new = client.post("/login", data={
        "username": "charlie",
        "password": "BrandNewPassword123!",
    }, follow_redirects=True)
    assert login_new.status_code == 200
    assert b"Dashboard" in login_new.data or b"StorageOS" in login_new.data


def test_google_login_routes(client, monkeypatch):
    """Test Google login endpoints behavior when unconfigured and configured."""
    # When unconfigured
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_CLIENT_SECRET", raising=False)

    # Standard redirect
    resp = client.get("/google", follow_redirects=True)
    assert resp.status_code == 200
    assert b"Google Login is currently not configured" in resp.data

    # JSON popup URL endpoint
    resp_json = client.get("/google/url")
    assert resp_json.status_code == 200
    data = resp_json.get_json()
    assert data["configured"] is False
    assert "Google Login is currently not configured" in data["message"]

    # When configured
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "mock-google-client-id.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "mock-google-client-secret")

    resp_configured = client.get("/google")
    assert resp_configured.status_code == 302
    assert "accounts.google.com" in resp_configured.headers["Location"]
    assert "mock-google-client-id" in resp_configured.headers["Location"]

    resp_json_conf = client.get("/google/url")
    assert resp_json_conf.status_code == 200
    data_conf = resp_json_conf.get_json()
    assert data_conf["configured"] is True
    assert "accounts.google.com" in data_conf["url"]
