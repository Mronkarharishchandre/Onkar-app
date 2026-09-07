import io
import os
import shutil
import tempfile
import pytest
from app.app import create_app
from app.database import get_db, init_db
from app.security import generate_csrf_token


@pytest.fixture
def app():
    # Create temporary directories for testing
    test_dir = tempfile.mkdtemp()
    db_path = os.path.join(test_dir, "test_storageos.db")
    storage_path = os.path.join(test_dir, "storage")

    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": db_path,
        "STORAGE_PATH": storage_path,
        "SECRET_KEY": "test-secret-key-for-unit-testing",
        "STORAGEOS_QUOTA": 5 * 1024 * 1024,  # 5MB quota for test
        "WTF_CSRF_ENABLED": False,
    })

    with app.app_context():
        init_db()

    yield app

    # Cleanup
    shutil.rmtree(test_dir, ignore_errors=True)


@pytest.fixture
def client(app):
    return app.test_client()


def get_csrf(client):
    with client.session_transaction() as sess:
        if "csrf_token" not in sess:
            sess["csrf_token"] = "test-csrf-token"
        return sess["csrf_token"]


def register_user(client, username, password):
    csrf = get_csrf(client)
    return client.post("/register", data={
        "username": username,
        "password": password,
        "confirm_password": password,
        "csrf_token": csrf,
    }, follow_redirects=True)


def login_user(client, username, password):
    csrf = get_csrf(client)
    return client.post("/login", data={
        "username": username,
        "password": password,
        "csrf_token": csrf,
    }, follow_redirects=True)


def logout_user(client):
    return client.get("/logout", follow_redirects=True)


# ==========================================
# 1. Health Endpoint Test
# ==========================================
def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"
    assert data["filesystem"] == "writable"


# ==========================================
# 2. Registration, Login, Logout & Unauthorized Access
# ==========================================
def test_user_registration_and_login(client):
    # Registration succeeds
    resp = register_user(client, "alice", "Password123!")
    assert resp.status_code == 200
    assert b"Registration successful" in resp.data or b"Welcome, alice" in resp.data

    # Duplicate registration fails
    logout_user(client)
    resp_dup = register_user(client, "alice", "Password123!")
    assert b"Username already exists" in resp_dup.data

    # Logout
    resp_logout = logout_user(client)
    assert resp_logout.status_code == 200

    # Login succeeds
    resp_login = login_user(client, "alice", "Password123!")
    assert resp_login.status_code == 200
    assert b"Welcome, alice" in resp_login.data

    # Login with wrong password fails
    logout_user(client)
    resp_bad = login_user(client, "alice", "WrongPassword")
    assert b"Invalid username or password" in resp_bad.data


def test_unauthorized_access_redirects_to_login(client):
    # Guest cannot access protected routes
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code in (302, 401)
    assert "/login" in resp.headers.get("Location", "")

    resp_files = client.get("/files", follow_redirects=False)
    assert resp_files.status_code in (302, 401)
    assert "/login" in resp_files.headers.get("Location", "")


# ==========================================
# 3. File Upload, Download, User Isolation & Path Traversal
# ==========================================
def test_file_upload_and_download(client):
    register_user(client, "bob", "SecretPass123!")
    login_user(client, "bob", "SecretPass123!")
    csrf = get_csrf(client)

    # Upload test file
    file_content = b"Hello StorageOS! This is a secure file."
    data = {
        "file": (io.BytesIO(file_content), "test_doc.txt"),
        "current_path": "",
        "csrf_token": csrf,
    }
    resp = client.post("/files/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200
    assert b"uploaded successfully" in resp.data

    # Download test file
    resp_dl = client.get("/files/download?rel_path=test_doc.txt")
    assert resp_dl.status_code == 200
    assert resp_dl.data == file_content


def test_path_traversal_prevention(client):
    register_user(client, "eve", "EvePass12345!")
    login_user(client, "eve", "EvePass12345!")

    # Attempt directory traversal download
    resp1 = client.get("/files/download?rel_path=../../etc/passwd")
    assert resp1.status_code in (400, 403, 404)

    resp2 = client.get("/files/download?rel_path=/etc/passwd")
    assert resp2.status_code in (400, 403, 404)

    resp3 = client.get("/files/download?rel_path=..%2F..%2Fetc%2Fshadow")
    assert resp3.status_code in (400, 403, 404)


def test_user_isolation(client):
    # User A (charlie) uploads a private file
    register_user(client, "charlie", "CharliePass123!")
    login_user(client, "charlie", "CharliePass123!")
    csrf = get_csrf(client)

    client.post("/files/upload", data={
        "file": (io.BytesIO(b"Charlie confidential info"), "confidential.txt"),
        "current_path": "",
        "csrf_token": csrf,
    }, content_type="multipart/form-data", follow_redirects=True)

    logout_user(client)

    # User B (david) attempts to download Charlie's file
    register_user(client, "david", "DavidPass1234!")
    login_user(client, "david", "DavidPass1234!")

    # Direct relative path should not find charlie's file in david's storage
    resp = client.get("/files/download?rel_path=confidential.txt")
    assert resp.status_code == 404

    # Traversal attempt to reach charlie's folder
    resp_traverse = client.get("/files/download?rel_path=../charlie/confidential.txt")
    assert resp_traverse.status_code in (400, 403, 404)


# ==========================================
# 4. Folder Creation, Nested Folders & Rename
# ==========================================
def test_folders_and_nested_structure(client):
    register_user(client, "frank", "FrankPass123!")
    login_user(client, "frank", "FrankPass123!")
    csrf = get_csrf(client)

    # Create root folder 'Projects'
    resp = client.post("/files/create-folder", data={
        "folder_name": "Projects",
        "current_path": "",
        "csrf_token": csrf,
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"created successfully" in resp.data

    # Create nested folder 'StorageOS' inside 'Projects'
    resp_nested = client.post("/files/create-folder", data={
        "folder_name": "StorageOS",
        "current_path": "Projects",
        "csrf_token": csrf,
    }, follow_redirects=True)
    assert resp_nested.status_code == 200

    # Upload file into nested folder
    client.post("/files/upload", data={
        "file": (io.BytesIO(b"nested code file"), "main.py"),
        "current_path": "Projects/StorageOS",
        "csrf_token": csrf,
    }, content_type="multipart/form-data", follow_redirects=True)

    # Download from nested path
    resp_dl = client.get("/files/download?rel_path=Projects/StorageOS/main.py")
    assert resp_dl.status_code == 200
    assert resp_dl.data == b"nested code file"

    # Rename nested file
    resp_rename = client.post("/files/rename", data={
        "relative_path": "Projects/StorageOS/main.py",
        "new_name": "app.py",
        "item_type": "file",
        "current_path": "Projects/StorageOS",
        "csrf_token": csrf,
    }, follow_redirects=True)
    assert resp_rename.status_code == 200
    assert b"Renamed successfully" in resp_rename.data

    # Old name should be gone, new name should be downloadable
    resp_old = client.get("/files/download?rel_path=Projects/StorageOS/main.py")
    assert resp_old.status_code == 404

    resp_new = client.get("/files/download?rel_path=Projects/StorageOS/app.py")
    assert resp_new.status_code == 200
    assert resp_new.data == b"nested code file"


# ==========================================
# 5. Trash Bin, Restore & Permanent Delete
# ==========================================
def test_trash_restore_and_purge(client):
    register_user(client, "grace", "GracePass123!")
    login_user(client, "grace", "GracePass123!")
    csrf = get_csrf(client)

    # Upload file
    client.post("/files/upload", data={
        "file": (io.BytesIO(b"Data to be deleted"), "notes.txt"),
        "current_path": "",
        "csrf_token": csrf,
    }, content_type="multipart/form-data", follow_redirects=True)

    # Move to trash
    resp_del = client.post("/files/delete", data={
        "relative_path": "notes.txt",
        "current_path": "",
        "csrf_token": csrf,
    }, follow_redirects=True)
    assert resp_del.status_code == 200
    assert b"Moved to trash" in resp_del.data

    # File should no longer be in active storage
    resp_gone = client.get("/files/download?rel_path=notes.txt")
    assert resp_gone.status_code == 404

    # Check trash page
    resp_trash = client.get("/trash")
    assert resp_trash.status_code == 200
    assert b"notes.txt" in resp_trash.data

    # Restore from trash
    with client.application.app_context():
        db = get_db()
        trash_item = db.execute("SELECT id FROM trash WHERE filename = 'notes.txt'").fetchone()
        trash_id = trash_item["id"]

    resp_restore = client.post(f"/trash/restore/{trash_id}", data={"csrf_token": csrf}, follow_redirects=True)
    assert resp_restore.status_code == 200
    assert b"restored successfully" in resp_restore.data

    # Download restored file
    resp_restored_dl = client.get("/files/download?rel_path=notes.txt")
    assert resp_restored_dl.status_code == 200
    assert resp_restored_dl.data == b"Data to be deleted"

    # Delete to trash again and permanently purge
    client.post("/files/delete", data={"relative_path": "notes.txt", "current_path": "", "csrf_token": csrf})
    with client.application.app_context():
        db = get_db()
        trash_item2 = db.execute("SELECT id FROM trash WHERE filename = 'notes.txt'").fetchone()
        trash_id2 = trash_item2["id"]

    resp_purge = client.post(f"/trash/delete/{trash_id2}", data={"csrf_token": csrf}, follow_redirects=True)
    assert resp_purge.status_code == 200
    assert b"Permanently deleted" in resp_purge.data


# ==========================================
# 6. Recursive Search (excludes .trash)
# ==========================================
def test_recursive_search(client):
    register_user(client, "heidi", "HeidiPass123!")
    login_user(client, "heidi", "HeidiPass123!")
    csrf = get_csrf(client)

    # Create folder and upload files
    client.post("/files/create-folder", data={"folder_name": "Reports", "current_path": "", "csrf_token": csrf})
    client.post("/files/upload", data={
        "file": (io.BytesIO(b"Quarterly financial report"), "q3_report.pdf"),
        "current_path": "Reports",
        "csrf_token": csrf,
    }, content_type="multipart/form-data")

    # Search for 'report'
    resp_search = client.get("/search?q=report")
    assert resp_search.status_code == 200
    assert b"q3_report.pdf" in resp_search.data
    assert b"Reports/q3_report.pdf" in resp_search.data


# ==========================================
# 7. Quota Enforcement
# ==========================================
def test_quota_limits(client):
    register_user(client, "ivan", "IvanPass123!")
    login_user(client, "ivan", "IvanPass123!")
    csrf = get_csrf(client)

    # Try uploading a file larger than 5MB (the test quota)
    large_payload = b"X" * (6 * 1024 * 1024)  # 6MB
    resp = client.post("/files/upload", data={
        "file": (io.BytesIO(large_payload), "huge_backup.bin"),
        "current_path": "",
        "csrf_token": csrf,
    }, content_type="multipart/form-data", follow_redirects=True)

    assert b"Quota exceeded" in resp.data or b"exceed your available storage quota" in resp.data


# ==========================================
# 8. Sharing: Viewer & Editor Roles, Revocation & Security
# ==========================================
def test_sharing_viewer_and_editor_roles(client):
    # Setup owner (judy) and recipient (kevin)
    register_user(client, "judy", "JudyPass123!")
    logout_user(client)
    register_user(client, "kevin", "KevinPass123!")
    logout_user(client)

    # Judy logs in and uploads report.docx
    login_user(client, "judy", "JudyPass123!")
    csrf = get_csrf(client)
    client.post("/files/upload", data={
        "file": (io.BytesIO(b"Judy report content"), "report.docx"),
        "current_path": "",
        "csrf_token": csrf,
    }, content_type="multipart/form-data")

    # Judy shares report.docx with kevin as VIEWER
    resp_share = client.post("/files/share", data={
        "relative_path": "report.docx",
        "target_username": "kevin",
        "permission": "viewer",
        "csrf_token": csrf,
    }, follow_redirects=True)
    assert resp_share.status_code == 200
    assert b"Shared" in resp_share.data

    logout_user(client)

    # Kevin logs in
    login_user(client, "kevin", "KevinPass123!")
    resp_shared_page = client.get("/shared")
    assert resp_shared_page.status_code == 200
    assert b"report.docx" in resp_shared_page.data
    assert b"VIEWER" in resp_shared_page.data

    # Kevin downloads shared file
    with client.application.app_context():
        db = get_db()
        share = db.execute("SELECT id FROM shares WHERE filename = 'report.docx'").fetchone()
        share_id = share["id"]

    resp_dl = client.get(f"/shared/download/{share_id}")
    assert resp_dl.status_code == 200
    assert resp_dl.data == b"Judy report content"

    # Viewer CANNOT rename (must return 403)
    resp_no_rename = client.post(f"/shared/rename/{share_id}", data={
        "new_name": "hacked.docx",
        "csrf_token": csrf,
    })
    assert resp_no_rename.status_code == 403

    # Viewer CANNOT delete (must return 403)
    resp_no_delete = client.post(f"/shared/delete/{share_id}", data={
        "csrf_token": csrf,
    })
    assert resp_no_delete.status_code == 403

    logout_user(client)

    # Now Judy updates Kevin's permission to EDITOR
    login_user(client, "judy", "JudyPass123!")
    client.post("/files/share", data={
        "relative_path": "report.docx",
        "target_username": "kevin",
        "permission": "editor",
        "csrf_token": csrf,
    })
    logout_user(client)

    # Kevin logs back in and renames the file
    login_user(client, "kevin", "KevinPass123!")
    resp_renamed = client.post(f"/shared/rename/{share_id}", data={
        "new_name": "report_v2.docx",
        "csrf_token": csrf,
    }, follow_redirects=True)
    assert resp_renamed.status_code == 200
    assert b"Renamed shared file" in resp_renamed.data

    # Invalid share ID access
    resp_invalid = client.get("/shared/download/99999")
    assert resp_invalid.status_code in (403, 404)


# ==========================================
# 9. Activity Logging
# ==========================================
def test_activity_logging(client):
    register_user(client, "leo", "LeoPass123!")
    login_user(client, "leo", "LeoPass123!")
    csrf = get_csrf(client)

    client.post("/files/create-folder", data={"folder_name": "Documents", "current_path": "", "csrf_token": csrf})

    resp_act = client.get("/activity")
    assert resp_act.status_code == 200
    assert b"CREATE_FOLDER" in resp_act.data
    assert b"Documents" in resp_act.data
