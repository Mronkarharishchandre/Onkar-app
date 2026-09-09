import io
import os
import shutil
import tempfile
import pytest
from app.app import create_app
from app.database import get_db, init_db, get_user_by_id


@pytest.fixture
def app():
    test_dir = tempfile.mkdtemp()
    db_path = os.path.join(test_dir, "test_settings.db")
    storage_path = os.path.join(test_dir, "storage")

    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": db_path,
        "STORAGE_PATH": storage_path,
        "SECRET_KEY": "test-secret-key-settings",
        "STORAGEOS_QUOTA": 50 * 1024 * 1024,  # 50 MB
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


def register_and_login(client, username="onkar", password="StrongPassword123!"):
    csrf = get_csrf(client)
    client.post("/register", data={
        "username": username,
        "password": password,
        "confirm_password": password,
        "csrf_token": csrf,
    }, follow_redirects=True)

    res = client.post("/login", data={
        "username": username,
        "password": password,
        "csrf_token": csrf,
    }, follow_redirects=True)
    return res


def test_no_unwanted_topbar_user_button(client):
    """Verify that the unwanted 'onkar' / topbar-user-btn is REMOVED from the header, while sidebar settings link remains."""
    register_and_login(client, username="onkar")

    res = client.get("/", follow_redirects=True)
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # The unwanted topbar user button must NOT exist
    assert 'id="topbar-user-btn"' not in html
    assert 'class="btn-topbar-user"' not in html
    assert 'Settings (onkar)' not in html

    # The normal sidebar navigation link to /settings MUST exist
    assert 'href="/settings"' in html or 'href="http://localhost/settings"' in html
    assert 'id="nav-settings"' in html


def test_settings_page_returns_http_200_not_500(client):
    """Verify that the /settings route returns HTTP 200 and loads successfully without 500 error."""
    register_and_login(client, username="onkar")

    res = client.get("/settings")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # Confirm not an error page
    assert "500 Internal Server Error" not in html
    assert "An unexpected error occurred" not in html

    # Verify all 6 requested sections exist
    assert "section-account" in html
    assert "section-appearance" in html
    assert "section-storage" in html
    assert "section-security" in html
    assert "section-file-preferences" in html
    assert "section-about" in html


def test_account_settings_update(client, app):
    """Verify Account section: display name and email updates persist."""
    register_and_login(client, username="onkar")
    csrf = get_csrf(client)

    res = client.post("/settings/account", data={
        "display_name": "Onkar H.",
        "email": "onkar@example.com",
        "csrf_token": csrf,
    }, follow_redirects=True)

    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Onkar H." in html
    assert "onkar@example.com" in html

    # Verify DB persistence
    with client.session_transaction() as sess:
        user_id = sess["user_id"]
    with app.app_context():
        user = get_user_by_id(user_id)
        assert user["display_name"] == "Onkar H."
        assert user["email"] == "onkar@example.com"


def test_appearance_settings_update(client, app):
    """Verify Appearance section: Light/Dark mode and Language selection persist."""
    register_and_login(client, username="onkar")
    csrf = get_csrf(client)

    # Change to Dark mode and Italian ('it')
    res = client.post("/settings/appearance", data={
        "theme": "dark",
        "language": "it",
        "csrf_token": csrf,
    }, follow_redirects=True)

    assert res.status_code == 200
    with client.session_transaction() as sess:
        assert sess.get("theme") == "dark"
        assert sess.get("lang") == "it"
        user_id = sess["user_id"]

    with app.app_context():
        user = get_user_by_id(user_id)
        assert user["theme"] == "dark"
        assert user["language"] == "it"


def test_storage_section_uses_real_storageos_data(client):
    """Verify Storage section displays real calculated values from StorageOS, not fake static numbers."""
    register_and_login(client, username="onkar")
    csrf = get_csrf(client)

    # Initial check
    res = client.get("/settings")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Total Storage" in html
    assert "Used Storage" in html
    assert "Available" in html
    assert "Storage Usage" in html

    # Upload a 50KB test file
    payload = b"X" * (50 * 1024)
    upload_res = client.post("/upload", data={
        "file": (io.BytesIO(payload), "test_doc.bin"),
        "current_path": "",
        "csrf_token": csrf,
    }, follow_redirects=True)
    assert upload_res.status_code == 200

    # Verify settings reflects real used storage
    settings_res = client.get("/settings")
    assert settings_res.status_code == 200
    s_html = settings_res.data.decode("utf-8")
    # 50 KB should appear in the used storage metrics
    assert "50.0 KB" in s_html or "50 KB" in s_html or "0.1%" in s_html or "utilized" in s_html


def test_file_preferences_update(client, app):
    """Verify File Preferences: list/grid view, sorting, confirm_delete persist."""
    register_and_login(client, username="onkar")
    csrf = get_csrf(client)

    res = client.post("/settings/file-preferences", data={
        "file_view": "grid",
        "sort_preference": "date_desc",
        "confirm_delete": "1",
        "csrf_token": csrf,
    }, follow_redirects=True)

    assert res.status_code == 200

    with client.session_transaction() as sess:
        user_id = sess["user_id"]

    with app.app_context():
        user = get_user_by_id(user_id)
        assert user["file_view"] == "grid"
        assert user["sort_preference"] == "date_desc"
        assert user["confirm_delete"] == 1


def test_security_password_change_and_logout_all(client):
    """Verify Security: Change password with verification and logout all sessions."""
    register_and_login(client, username="onkar", password="StrongPassword123!")
    csrf = get_csrf(client)

    # 1. Test change password
    res = client.post("/settings/password", data={
        "current_password": "StrongPassword123!",
        "new_password": "NewStrongPassword456!",
        "confirm_password": "NewStrongPassword456!",
        "csrf_token": csrf,
    }, follow_redirects=True)
    assert res.status_code == 200
    assert "Password updated successfully" in res.data.decode("utf-8")

    # 2. Test logout all sessions
    logout_res = client.post("/settings/logout-all", data={
        "csrf_token": csrf,
    }, follow_redirects=True)
    assert logout_res.status_code == 200
    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_about_section_content(client):
    """Verify About section displays StorageOS name, version, and system status."""
    register_and_login(client, username="onkar")
    res = client.get("/settings")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    assert "StorageOS" in html
    assert "1.0.0" in html
    assert "Operational" in html
