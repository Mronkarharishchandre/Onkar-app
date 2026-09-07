# StorageOS - Production Rootless Containerfile (OCI, Docker & Podman Compliant)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    STORAGEOS_STORAGE_ROOT=/data/storage \
    STORAGEOS_DB_PATH=/data/database/storageos.db \
    PORT=5000

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 storageos && \
    useradd -u 1000 -g storageos -m -s /bin/bash storageos

WORKDIR /app
RUN mkdir -p /data/database /data/storage /data/backups && \
    chown -R storageos:storageos /app /data && \
    chmod -R 750 /data

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY app /app/app
COPY scripts /app/scripts
COPY tests /app/tests

RUN chown -R storageos:storageos /app && \
    chmod +x /app/scripts/*.sh || true

USER storageos

VOLUME ["/data"]

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:5000/health || exit 1

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "--access-logfile", "-", "--error-logfile", "-", "app.app:create_app()"]
