#!/usr/bin/env bash
# ==============================================================================
# StorageOS Disaster Recovery & Restore Script
# Restores SQLite database and user filesystem storage from backup archive.
# ==============================================================================
set -euo pipefail

BACKUP_ARCHIVE="${1:-}"
FORCE_RESTORE="${2:-}"

if [ -z "${BACKUP_ARCHIVE}" ]; then
    echo "Usage: $0 <path-to-backup.tar.gz> [--force]"
    echo "Example: $0 /data/backups/storageos_backup_20260907_120000.tar.gz"
    exit 1
fi

if [ ! -f "${BACKUP_ARCHIVE}" ]; then
    echo "Error: Backup file '${BACKUP_ARCHIVE}' not found."
    exit 1
fi

# Paths
DB_DEST="${STORAGEOS_DB_PATH:-/data/database/storageos.db}"
STORAGE_DEST="${STORAGEOS_STORAGE_ROOT:-/data/storage}"
CHECKSUM_FILE="${BACKUP_ARCHIVE}.sha256"

echo "========================================================"
echo "StorageOS Disaster Recovery Restore"
echo "Target Archive: ${BACKUP_ARCHIVE}"
echo "========================================================"

# 1. Verify Checksum if present
if [ -f "${CHECKSUM_FILE}" ]; then
    echo "[1/4] Verifying SHA-256 archive checksum..."
    CHECKSUM_DIR=$(dirname "${BACKUP_ARCHIVE}")
    (cd "${CHECKSUM_DIR}" && sha256sum -c "$(basename "${CHECKSUM_FILE}")")
    echo "       Checksum verified successfully."
else
    echo "[1/4] Notice: No checksum file found. Proceeding with caution."
fi

# 2. Confirmation prompt if not forced
if [ "${FORCE_RESTORE}" != "--force" ]; then
    echo "WARNING: Restoring will overwrite existing database and files!"
    echo "Database target: ${DB_DEST}"
    echo "Storage target:  ${STORAGE_DEST}"
    read -r -p "Type 'RESTORE' to confirm: " CONFIRMATION
    if [ "${CONFIRMATION}" != "RESTORE" ]; then
        echo "Restore cancelled by user."
        exit 0
    fi
fi

# 3. Extract Archive to Temporary Location
RESTORE_TEMP=$(mktemp -d /tmp/storageos_restore_XXXXXX)
trap 'rm -rf "${RESTORE_TEMP}"' EXIT

echo "[2/4] Extracting backup payload..."
tar -xzf "${BACKUP_ARCHIVE}" -C "${RESTORE_TEMP}"
BACKUP_ROOT=$(find "${RESTORE_TEMP}" -mindepth 1 -maxdepth 1 -type d | head -n 1)

if [ -z "${BACKUP_ROOT}" ]; then
    echo "Error: Corrupt or unrecognized backup archive structure."
    exit 1
fi

# 4. Restore Database
echo "[3/4] Restoring SQLite database..."
mkdir -p "$(dirname "${DB_DEST}")"
if [ -f "${BACKUP_ROOT}/storageos.db" ]; then
    # Test integrity of the backup database before placing into production
    sqlite3 "${BACKUP_ROOT}/storageos.db" "PRAGMA integrity_check;" > /dev/null
    cp "${BACKUP_ROOT}/storageos.db" "${DB_DEST}"
    chmod 640 "${DB_DEST}"
    echo "       Database restored successfully to ${DB_DEST}."
else
    echo "       Warning: No database file found in archive."
fi

# 5. Restore Storage Files
echo "[4/4] Restoring user storage volume..."
mkdir -p "${STORAGE_DEST}"
if [ -f "${BACKUP_ROOT}/storage.tar" ]; then
    tar -xf "${BACKUP_ROOT}/storage.tar" -C "${STORAGE_DEST}"
    chmod -R 750 "${STORAGE_DEST}"
    echo "       User storage restored successfully to ${STORAGE_DEST}."
else
    echo "       Warning: No storage filesystem archive found in backup."
fi

echo "========================================================"
echo "Restore operation completed successfully!"
echo "Please restart or reload the StorageOS service if running."
echo "========================================================"
