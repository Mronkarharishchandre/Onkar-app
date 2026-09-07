import io
import os
import shutil
import tempfile
import pytest
from app.app import create_app
from app.database import get_db, init_db


@pytest.fixture
def app():
    test_dir = tempfile.mkdtemp()
    db_path = os.path.join(test_dir, "test_improvements.db")
    storage_path = os.path.join(test_dir, "storage")

    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": db_path,
        "STORAGE_PATH": storage_path,
        "SECRET_KEY": "test-secret-key-improvements",
        "STORAGEOS_QUOTA": 10 * 1024 * 1024,
        "WTF_CSRF_ENABLED": False,
    })

    with app.app_context():
        init_db()

    yield app

    shutil.rmtree(test_dir, ignore_errors=True)


@pytest.fixture
def client(app):
    return app.test_client()


def get_csrf(client):
    with client.session_transaction() as sess:
        if "csrf_token" not in sess:
            sess["csrf_token"] = "test-csrf-token"
        return sess["csrf_token"]


def test_language_and_theme_routes(client):
    csrf = get_csrf(client)
    # Register and login user
    client.post("/register", data={
        "username": "alice",
        "password": "Password123!",
        "confirm_password": "Password123!",
        "csrf_token": csrf
    }, follow_redirects=True)

    client.post("/login", data={
        "username": "alice",
        "password": "Password123!",
        "csrf_token": csrf
    }, follow_redirects=True)

    # Test setting language to Hindi
    resp_lang = client.post("/set-language", data={"language": "hi"}, follow_redirects=True)
    assert resp_lang.status_code == 200

    # Verify session or cookie
    with client.session_transaction() as sess:
        assert sess.get("lang") == "hi"

    # Test setting theme to dark
    resp_theme = client.post("/set-theme", data={"theme": "dark"}, headers={"Accept": "application/json"})
    assert resp_theme.status_code == 200
    assert resp_theme.get_json() == {"status": "ok", "theme": "dark"}


def test_file_preview_api(client):
    csrf = get_csrf(client)
    client.post("/register", data={
        "username": "bob",
        "password": "Password123!",
        "confirm_password": "Password123!",
        "csrf_token": csrf
    }, follow_redirects=True)
    client.post("/login", data={
        "username": "bob",
        "password": "Password123!",
        "csrf_token": csrf
    }, follow_redirects=True)

    # Upload sample text file
    client.post("/files/upload", data={
        "file": (io.BytesIO(b"Hello StorageOS preview system!"), "notes.txt"),
        "current_path": "",
        "csrf_token": csrf
    }, content_type="multipart/form-data")

    # Call preview info
    resp_preview = client.get("/api/preview-info?rel_path=notes.txt")
    assert resp_preview.status_code == 200
    data = resp_preview.get_json()
    assert data["filename"] == "notes.txt"
    assert data["category"] in ["text", "code"]
    assert "raw_url" in data

    # Test raw file serving
    resp_raw = client.get(data["raw_url"])
    assert resp_raw.status_code == 200
    assert b"Hello StorageOS preview system!" in resp_raw.data


def test_public_share_link_and_view(client):
    csrf = get_csrf(client)
    client.post("/register", data={
        "username": "charlie",
        "password": "Password123!",
        "confirm_password": "Password123!",
        "csrf_token": csrf
    }, follow_redirects=True)
    client.post("/login", data={
        "username": "charlie",
        "password": "Password123!",
        "csrf_token": csrf
    }, follow_redirects=True)

    client.post("/files/upload", data={
        "file": (io.BytesIO(b"Confidential project specs"), "specs.txt"),
        "current_path": "",
        "csrf_token": csrf
    }, content_type="multipart/form-data")

    # Generate public link with password
    resp_link = client.post("/share-link/create", data={
        "relative_path": "specs.txt",
        "expires_hours": "24",
        "password": "ShareSecret999",
        "csrf_token": csrf
    }, headers={"Accept": "application/json"})
    assert resp_link.status_code == 200
    link_data = resp_link.get_json()
    assert link_data["success"] is True
    token = link_data["token"]
    assert token

    # Logout to simulate anonymous guest
    client.get("/logout", follow_redirects=True)

    # Access link without password -> should prompt for password
    resp_guest = client.get(f"/share/{token}")
    assert resp_guest.status_code == 200
    assert b"Password Protected" in resp_guest.data

    # Submit correct password
    resp_auth = client.post(f"/share/{token}", data={"password": "ShareSecret999"}, follow_redirects=True)
    assert resp_auth.status_code == 200
    assert b"specs.txt" in resp_auth.data
    assert b"Download File" in resp_auth.data

    # Download file via public share link
    resp_dl = client.get(f"/share/{token}/download")
    assert resp_dl.status_code == 200
    assert resp_dl.data == b"Confidential project specs"
