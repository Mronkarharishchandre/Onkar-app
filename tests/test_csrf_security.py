import os
import re
import shutil
import tempfile
import pytest
from app.app import create_app
from app.database import init_db
from app.security import (
    generate_csrf_token,
    validate_csrf_token,
    get_or_create_secret_key,
)


@pytest.fixture
def csrf_app():
    test_dir = tempfile.mkdtemp()
    db_path = os.path.join(test_dir, "test_csrf.db")
    storage_path = os.path.join(test_dir, "storage")

    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": db_path,
        "STORAGE_PATH": storage_path,
        "SECRET_KEY": "a-strong-test-secret-key-32chars!",
        "WTF_CSRF_ENABLED": True,
        "SESSION_COOKIE_SECURE": False,
    })

    with app.app_context():
        init_db()

    yield app

    shutil.rmtree(test_dir, ignore_errors=True)


def test_secret_key_persistence(tmp_path):
    """Verify get_or_create_secret_key persists and reuses the same key across calls."""
    data_dir = str(tmp_path / "data")
    key1 = get_or_create_secret_key(data_dir)
    key2 = get_or_create_secret_key(data_dir)
    assert key1 == key2
    assert len(key1) >= 32

    # Verify key is saved in .secret_key file
    secret_file = os.path.join(data_dir, ".secret_key")
    assert os.path.exists(secret_file)
    with open(secret_file, "r") as f:
        file_key = f.read().strip()
    assert file_key == key1


def test_registration_and_login_csrf_flow(csrf_app):
    """Verify CSRF token extraction from GET and submission in POST succeeds."""
    client = csrf_app.test_client()

    # 1. GET /register and extract CSRF token
    res_reg_get = client.get("/register")
    assert res_reg_get.status_code == 200
    html_reg = res_reg_get.data.decode("utf-8")
    token_match = re.search(r'name="csrf_token" value="([^"]+)"', html_reg)
    assert token_match is not None, "CSRF token missing in register form"
    reg_token = token_match.group(1)

    # 2. POST /register with valid CSRF token
    res_reg_post = client.post("/register", data={
        "csrf_token": reg_token,
        "username": "tester_csrf_user",
        "password": "StrongPassword123!",
        "confirm_password": "StrongPassword123!",
    }, follow_redirects=True)
    assert res_reg_post.status_code == 200
    assert "Invalid security token" not in res_reg_post.data.decode("utf-8")
    assert b"Welcome to StorageOS" in res_reg_post.data

    # 3. Log out
    client.get("/logout", follow_redirects=True)

    # 4. GET /login and extract CSRF token
    res_login_get = client.get("/login")
    assert res_login_get.status_code == 200
    html_login = res_login_get.data.decode("utf-8")
    login_token_match = re.search(r'name="csrf_token" value="([^"]+)"', html_login)
    assert login_token_match is not None, "CSRF token missing in login form"
    login_token = login_token_match.group(1)

    # 5. POST /login with valid CSRF token
    res_login_post = client.post("/login", data={
        "csrf_token": login_token,
        "username": "tester_csrf_user",
        "password": "StrongPassword123!",
    }, follow_redirects=True)
    assert res_login_post.status_code == 200
    assert "Invalid security token" not in res_login_post.data.decode("utf-8")
    assert b"StorageOS" in res_login_post.data


def test_invalid_csrf_token_rejected(csrf_app):
    """Verify forged or invalid CSRF tokens are rejected with appropriate error message."""
    client = csrf_app.test_client()

    # GET /login to initialize session
    client.get("/login")

    # POST with fake token
    res_fake = client.post("/login", data={
        "csrf_token": "forged_invalid_csrf_token_xyz",
        "username": "someuser",
        "password": "SomePassword123!",
    })
    assert res_fake.status_code == 200
    assert b"Invalid security token. Please try again." in res_fake.data

    # POST with missing token
    res_missing = client.post("/login", data={
        "username": "someuser",
        "password": "SomePassword123!",
    })
    assert res_missing.status_code == 200
    assert b"Invalid security token. Please try again." in res_missing.data


def test_proxy_headers_and_scheme(csrf_app):
    """Verify ProxyFix handles X-Forwarded-Proto and X-Forwarded-Host properly."""
    client = csrf_app.test_client()

    # Send request with X-Forwarded-Proto: https
    res = client.get("/login", headers={
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "cloud.storageos.example",
    })
    assert res.status_code == 200
    assert res.headers.get("Set-Cookie") is not None


def test_iframe_partitioned_cookie_generation():
    """Verify DynamicSecureSessionInterface produces SameSite=None, Secure, Partitioned in HTTPS/iframe contexts."""
    test_dir = tempfile.mkdtemp()
    try:
        app = create_app({
            "TESTING": True,
            "DATABASE_PATH": os.path.join(test_dir, "test.db"),
            "STORAGE_PATH": os.path.join(test_dir, "storage"),
            "SECRET_KEY": "a-strong-test-secret-key-32chars!",
        })
        client = app.test_client()
        res = client.get("/login", headers={
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "ais-preview.run.app",
        })
        cookie_header = res.headers.get("Set-Cookie", "")
        assert "storageos_session=" in cookie_header
        assert "SameSite=None" in cookie_header
        assert "Secure" in cookie_header
        assert "Partitioned" in cookie_header
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

