# StorageOS - Production Rootless Containerfile (OCI & Podman Compliant)
FROM python:3.11-slim

# Set non-interactive debian frontend and python environment flags
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    STORAGEOS_STORAGE_ROOT=/data/storage \
    STORAGEOS_DB_PATH=/data/database/storageos.db \
    PORT=5000

# Install minimal OS dependencies for healthchecks, security tools, and SQLite
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged application user and group (Rootless container security)
RUN groupadd -g 1000 storageos && \
    useradd -u 1000 -g storageos -m -s /bin/bash storageos

# Create application directory and persistent volume directories
WORKDIR /app
RUN mkdir -p /data/database /data/storage /data/backups && \
    chown -R storageos:storageos /app /data && \
    chmod -R 750 /data

# Install Python requirements
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code, scripts, and tests
COPY app /app/app
COPY scripts /app/scripts
COPY tests /app/tests

# Set ownership and permissions for the storageos user
RUN chown -R storageos:storageos /app && \
    chmod +x /app/scripts/*.sh || true

# Switch to rootless user
USER storageos

# Declare persistent volumes
VOLUME ["/data"]

# Expose internal HTTP port
EXPOSE 5000

# Define container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:5000/health || exit 1

# Launch production WSGI Gunicorn server
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "--access-logfile", "-", "--error-logfile", "-", "app.app:create_app()"]
