#!/bin/bash
# validate_snowv.sh
# Run the SNOW-V KAT binary and save the output to a device-tagged file.
# Commit the output files from both Pis to the repo and diff them on
# Windows to confirm cross-device consistency.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "./snowv_test" ]; then
    echo "[ERROR] snowv_test not found. Run build_snowv.sh first."
    exit 1
fi

HOSTNAME=$(hostname)
OUT_FILE="kat_output_${HOSTNAME}.txt"

echo "[VALIDATE] Running KAT on $HOSTNAME..."
./snowv_test | tee "$OUT_FILE"

if grep -q "FAIL" "$OUT_FILE"; then
    echo ""
    echo "[VALIDATE] RESULT: FAIL — one or more test vectors did not match."
    echo "[VALIDATE] Check the diff above for the first failing block."
    exit 1
else
    echo ""
    echo "[VALIDATE] RESULT: PASS — all vectors match on $HOSTNAME."
    echo "[VALIDATE] Output saved to $OUT_FILE"
    echo "[VALIDATE] Commit this file to the repo for cross-device diff."
fi
