# StorageOS

**StorageOS** is a secure, lightweight, self-hosted personal cloud storage platform built with Python, Flask, and SQLite. Designed for privacy-conscious self-hosters, home labs, and small teams, StorageOS provides complete data sovereignty with zero vendor lock-in.

---

## Key Features

- **Isolated User Storage**: Per-user directory isolation (`storage/<username>/`) with strict canonical path traversal defenses preventing access outside user boundaries.
- **Hierarchical File Management**: Upload, download, create nested folder hierarchies, rename, and organize files.
- **Safe Two-Phase Deletion (Trash Bin)**: Files are safely moved to a user-specific trash holding area with collision-resistant naming, supporting full restore to their original path or permanent purge.
- **Role-Based Sharing**: Share files with other users on the platform with granular permissions:
  - `viewer`: Read-only access to download and view shared documents.
  - `editor`: Collaborative permission to rename and modify shared files without altering ownership.
- **Audit Logging & Activity Tracking**: Tamper-evident activity logs recording uploads, renames, deletions, restorations, and shares with timestamps and IP metadata.
- **Quota & Storage Enforcement**: Real-time quota calculations and pre-upload enforcement (default 5 GB per user, customizable per-user or globally).
- **Hardened Security & Authentication**:
  - Constant-time comparison CSRF protection on all mutating HTTP requests.
  - PBKDF2-HMAC-SHA256 password hashing with high iteration counts and cryptographic salts.
  - **Forgot Password / Password Reset**: Secure single-use cryptographic reset tokens with 30-minute expiration, email delivery via SMTP or development-mode console logging, and user enumeration protection.
  - **Sign in with Google (OAuth 2.0 / OIDC)**: Native Google authentication supporting both popup and redirect flows with CSRF state verification and seamless account linking.
  - Strict filename sanitization removing control characters, NULL bytes, and traversal segments (`../`, `..\`).
  - Automatic Content-Disposition and MIME type sandboxing on downloads.
- **Full Automation & DevOps Tooling**:
  - Production `Dockerfile` and `Containerfile` adhering to rootless security standards (`UID 1000`).
  - Complete `docker-compose.yml` with healthchecks, isolated networks, and persistent data volumes.
  - Production `nginx/storageos.conf` reverse proxy configuration tuned for large file streaming (`proxy_request_buffering off`, 10GB max body size).
  - Production-ready systemd unit file with Linux kernel sandboxing (`ProtectSystem=strict`).
  - Automated SQLite online backup script (`backup-storageos.sh`) with SHA-256 integrity checks and retention pruning.
  - Atomic disaster recovery restore script (`restore-storageos.sh`) with integrity verification.
  - Health check script (`health-check.sh`) verifying HTTP availability, DB connectivity, and filesystem writeability.

---

## Directory Structure

```text
├── app/
│   ├── app.py          # Application factory, routes, blueprints, error handlers
│   ├── auth.py         # User registration, login, session auth, rate limiting
│   ├── database.py     # SQLite schema, migrations, connection pool, activity logger
│   ├── security.py     # CSRF validation, password hashing, filename sanitization
│   ├── sharing.py      # Role-based sharing mechanics (viewer / editor)
│   ├── storage.py      # Canonical path validation, filesystem ops, trash, quota
│   ├── static/         # CSS stylesheets, UI icons, client scripts
│   └── templates/      # Jinja2 responsive HTML5 templates
├── scripts/
│   ├── backup-storageos.sh   # Automated SQLite backup + storage tarball + checksums
│   ├── restore-storageos.sh  # Disaster recovery restoration script
│   └── health-check.sh       # Health probe for Docker/systemd/cron monitoring
├── nginx/
│   └── storageos.conf        # High-performance Nginx reverse proxy config
├── systemd/
│   └── storageos.service     # Hardened systemd unit configuration
├── tests/
│   └── test_storageos.py     # Comprehensive pytest test suite (12 passed test cases)
├── Dockerfile                # Production container specification
├── Containerfile             # Podman / OCI compliant rootless containerfile
├── docker-compose.yml        # Multi-container orchestration (App + Nginx + Volumes)
├── requirements.txt          # Python dependencies (Flask, Gunicorn, pytest)
└── README.md                 # Documentation and deployment guide
```

---

## Quickstart

### 1. Docker Compose (Recommended)

Run StorageOS with Nginx reverse proxy and persistent volumes in one command:

```bash
docker compose up -d --build
```

Access the web interface at `http://localhost`.

To view logs:
```bash
docker compose logs -f storageos
```

To stop:
```bash
docker compose down
```

### 2. Standalone Container (Podman / Docker)

Build and run using rootless container permissions:

```bash
# Build image
docker build -t storageos:1.0.0 .

# Run container with persistent data volume
docker run -d \
  --name storageos \
  -p 5000:5000 \
  -v storageos_data:/data \
  -e STORAGEOS_SECRET_KEY="your_strong_random_secret_here" \
  storageos:1.0.0
```

Access StorageOS directly at `http://localhost:5000`.

### 3. Local Development / Native Linux

```bash
# Clone and enter directory
cd StorageOS

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run test suite
pytest -v

# Run development server
python3 -m flask --app app.app run --port 5000
```

---

## Configuration & Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `STORAGEOS_SECRET_KEY` | *(ephemeral)* | Cryptographic secret for signing session cookies, reset tokens, and CSRF tokens. |
| `STORAGEOS_STORAGE_ROOT` | `/storage` or `app/data/storage` | Root filesystem directory where user files and trash are stored. |
| `STORAGEOS_DATABASE_PATH` | `app/data/storageos.db` | SQLite database file location. |
| `STORAGEOS_QUOTA` | `1073741824` (1 GB) | Default disk space quota allotted to newly registered users in bytes. |
| `APP_BASE_URL` | *(detected from Host header)* | Public canonical URL for generating password reset links and OAuth callbacks (e.g. `https://your-domain.com`). |
| `GOOGLE_CLIENT_ID` | *(empty)* | Google Cloud OAuth 2.0 Web Application Client ID. |
| `GOOGLE_CLIENT_SECRET` | *(empty)* | Google Cloud OAuth 2.0 Client Secret. |
| `GOOGLE_REDIRECT_URI` | `{APP_BASE_URL}/google/callback` | Authorized redirect URI configured in Google Cloud Console. |
| `SMTP_HOST` | *(empty)* | SMTP server hostname (e.g. `smtp.gmail.com` or `smtp.sendgrid.net`). If empty, reset links are printed to server console for local testing. |
| `SMTP_PORT` | `587` | SMTP server port (`587` for STARTTLS, `465` for SSL, `25` for unencrypted). |
| `SMTP_USER` | *(empty)* | SMTP authentication username. |
| `SMTP_PASSWORD` | *(empty)* | SMTP authentication password or App Password. |
| `SMTP_FROM_EMAIL` | *(empty)* | Sender email address shown on password reset emails. |
| `SMTP_FROM_NAME` | `StorageOS Cloud` | Sender display name. |
| `SMTP_USE_TLS` | `True` | Enable STARTTLS encryption. |
| `SMTP_USE_SSL` | `False` | Enable direct SSL/TLS encryption. |

---

## Authentication & OAuth Setup

### 1. Password Reset (Forgot Password)
- **Production Email Delivery**: Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, and `SMTP_FROM_EMAIL`. Reset links will be dispatched directly to the user's verified or registered email address.
- **Development Mode**: If no SMTP credentials are provided, StorageOS automatically logs the password reset URL to the terminal/server console and displays a development direct-link helper on the confirmation page so you can test password recovery effortlessly without an email server.
- **Security Protections**: Reset links use single-use cryptographic tokens with a 30-minute expiry window. Attempting to request a reset for an unregistered email returns an identical confirmation message to prevent user enumeration attacks.

### 2. Sign in with Google (OAuth 2.0)
1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Navigate to **APIs & Services** > **Credentials**.
3. Create an **OAuth 2.0 Client ID** with Application type **Web application**.
4. In **Authorized redirect URIs**, add:
   ```text
   https://<your-domain>/google/callback
   ```
   (For local development, add `http://localhost:3000/google/callback`).
5. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in your environment or `.env`.
6. When users click "Sign in with Google", StorageOS completes the handshake, verifies their Google ID token cryptographically, and provisions or links their StorageOS account with isolated storage.


---

## Backup & Disaster Recovery

### Creating a Backup

StorageOS includes a backup script that uses SQLite's online backup API (preventing database corruption during concurrent writes) and creates an integrity-verified, timestamped tarball:

```bash
./scripts/backup-storageos.sh
```

Backups are saved to `/data/backups/` with `.sha256` checksums. The script automatically prunes backups older than the retention threshold (default: 7 days).

### Restoring from Backup

To restore data onto a new server or recover from an incident:

```bash
./scripts/restore-storageos.sh /data/backups/storageos_backup_YYYYMMDD_HHMMSS.tar.gz --force
```

---

## Health Monitoring

The `/health` endpoint and `health-check.sh` script inspect:
1. **HTTP Service**: Confirms the WSGI server is accepting requests.
2. **Database Integrity**: Executes a ping query against SQLite.
3. **Storage Writeability**: Confirms the user data directory is mounted and writeable.

Run health check:
```bash
./scripts/health-check.sh http://127.0.0.1:5000/health
```

Sample JSON response from `/health`:
```json
{
  "status": "ok",
  "database": "connected",
  "filesystem": "writable",
  "app": "StorageOS",
  "version": "1.0.0",
  "checks": {
    "database": true,
    "storage": true
  }
}
```

---

## Running the Test Suite

The test suite covers full user flows, path traversal attack vectors, user isolation boundaries, file operations, trash and restore mechanics, quota limits, sharing roles (viewer vs. editor), and activity logging:

```bash
pytest -v
```

All 12 test specifications run against an isolated temporary environment.
