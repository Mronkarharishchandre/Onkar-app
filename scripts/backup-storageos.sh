#!/usr/bin/env bash
# ==============================================================================
# StorageOS Automated Backup Script
# Performs atomic SQLite online backup and compressed tar of user storage.
# ==============================================================================
set -euo pipefail

# Configuration with sensible defaults
BACKUP_DIR="${STORAGEOS_BACKUP_DIR:-/data/backups}"
DATA_DIR="${STORAGEOS_DATA_DIR:-/data}"
DB_PATH="${STORAGEOS_DB_PATH:-/data/database/storageos.db}"
STORAGE_ROOT="${STORAGEOS_STORAGE_ROOT:-/data/storage}"
RETENTION_DAYS="${STORAGEOS_BACKUP_RETENTION_DAYS:-7}"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="storageos_backup_${TIMESTAMP}"
DEST_DIR="${BACKUP_DIR}/${BACKUP_NAME}"
ARCHIVE_PATH="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"

echo "========================================================"
echo "Starting StorageOS Backup: ${TIMESTAMP}"
echo "========================================================"

mkdir -p "${DEST_DIR}" "${BACKUP_DIR}"

# 1. Atomic SQLite Online Backup (safe against concurrent transactions)
if [ -f "${DB_PATH}" ]; then
    echo "[1/4] Performing atomic SQLite online backup..."
    sqlite3 "${DB_PATH}" ".backup '${DEST_DIR}/storageos.db'"
    echo "       Database backup saved to ${DEST_DIR}/storageos.db"
else
    echo "[1/4] Warning: Database file ${DB_PATH} not found. Skipping DB backup."
fi

# 2. Archive User Storage Filesystem
if [ -d "${STORAGE_ROOT}" ]; then
    echo "[2/4] Archiving user storage volume from ${STORAGE_ROOT}..."
    tar -cf "${DEST_DIR}/storage.tar" -C "${STORAGE_ROOT}" .
    echo "       Storage archive saved to ${DEST_DIR}/storage.tar"
else
    echo "[2/4] Warning: Storage root ${STORAGE_ROOT} not found. Skipping filesystem backup."
fi

# 3. Create Manifest and Compressed Tarball
echo "[3/4] Creating final compressed backup archive..."
cat <<EOF > "${DEST_DIR}/backup_manifest.json"
{
  "timestamp": "${TIMESTAMP}",
  "created_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "storageos_version": "1.0.0",
  "db_path": "${DB_PATH}",
  "storage_root": "${STORAGE_ROOT}"
}
EOF

tar -czf "${ARCHIVE_PATH}" -C "${BACKUP_DIR}" "${BACKUP_NAME}"
rm -rf "${DEST_DIR}"

# Generate SHA-256 Checksum for integrity verification
sha256sum "${ARCHIVE_PATH}" > "${ARCHIVE_PATH}.sha256"
echo "       Backup archive created: ${ARCHIVE_PATH}"
echo "       SHA-256 Checksum: $(cat "${ARCHIVE_PATH}.sha256" | awk '{print $1}')"

# 4. Retention Policy - Delete backups older than RETENTION_DAYS
echo "[4/4] Enforcing backup retention policy (${RETENTION_DAYS} days)..."
find "${BACKUP_DIR}" -type f -name "storageos_backup_*.tar.gz*" -mtime +"${RETENTION_DAYS}" -print -delete 2>/dev/null || true

echo "========================================================"
echo "StorageOS Backup Complete! Size: $(du -h "${ARCHIVE_PATH}" | awk '{print $1}')"
echo "========================================================"
