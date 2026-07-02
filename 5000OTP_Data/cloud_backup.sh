#!/usr/bin/env bash
set -euo pipefail

SRC="${SRC:-$HOME/Desktop/5000OTP}"
REMOTE="${REMOTE:-gdrive}"
DEST="${DEST:-5000_Data}"
LOG="${LOG:-$HOME/Desktop/cloud_backup.log}"

EXCLUDES=(
    "build/**"
    "libs/liboqs/**"
    "libs/libsodium/**"
    "libs/ascon-c/**"
    "libs/snowv/snowv_test"
    "libs/snowv/snowv_neon_test"
    "libs/snowv/kat_output_*.txt"
    ".git/**"
    "__pycache__/**"
    "*.o"
    "*.a"
    "*.so"
    "*.pyc"
)

command -v rclone >/dev/null 2>&1 || { echo "ERROR: rclone is not installed or not on PATH"; exit 1; }
[ -d "$SRC" ] || { echo "ERROR: source folder not found: $SRC"; exit 1; }
rclone lsd "${REMOTE}:" >/dev/null 2>&1 || { echo "ERROR: remote '${REMOTE}:' not reachable (run: rclone config)"; exit 1; }

exclude_args=()
for e in "${EXCLUDES[@]}"; do exclude_args+=(--exclude "$e"); done

echo "Backing up: $SRC  ->  ${REMOTE}:${DEST}"
rclone copy "$SRC" "${REMOTE}:${DEST}" \
    "${exclude_args[@]}" \
    --transfers 4 \
    --checkers 8 \
    --retries 3 \
    --low-level-retries 10 \
    --fast-list \
    --progress \
    --log-file "$LOG" \
    --log-level INFO

echo "Done. Uploaded to ${REMOTE}:${DEST}. Log: $LOG"
