#!/usr/bin/env bash
# rebuild.sh  -- run on the Pi (5 or Zero 2 W).
#
# Wipes the old build/ and compiles all EIGHT benchmark binaries fresh for THIS
# board, so run_experiments_real.sh has current A/B/C/D (SNOW-Vi System B, opt64
# Ascon System D) and not a stale or B/D-only tree with old object files.
#
# The binaries are per-device ARM builds against the Pi's own liboqs / OpenSSL /
# libsodium and are gitignored, so they never live in the repo; they only exist
# on the Pi that built them. This script is the reproducible way to make them.
#
# Usage:   ./rebuild.sh           # auto-detects PI5 vs PI0 from the board model
#          ./rebuild.sh PI5       # force the device explicitly
#          ./rebuild.sh PI0

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 1. Work out which board this is.
DEV="${1:-}"
if [[ -z "$DEV" ]]; then
    model="$(tr -d '\000' < /proc/device-tree/model 2>/dev/null || true)"
    case "$model" in
        *"Pi 5"*)   DEV=PI5 ;;
        *"Zero 2"*) DEV=PI0 ;;
        *) echo "Could not detect the board (model: '${model:-unknown}')."
           echo "Run again naming the device:  ./rebuild.sh PI5   or   ./rebuild.sh PI0"; exit 1 ;;
    esac
    echo "Detected: ${model}  ->  DEVICE=${DEV}"
fi
[[ "$DEV" == "PI5" || "$DEV" == "PI0" ]] || { echo "DEVICE must be PI5 or PI0 (got '$DEV')"; exit 1; }

# 2. Guard: never rebuild a stale System B (would silently produce SNOW-V data).
grep -q '"SNOW-Vi-GCM"' systems/system_b/cipher.hpp \
    || { echo "ERROR: System B is not wired to SNOW-Vi in systems/system_b/cipher.hpp; aborting."; exit 1; }

# 3. Delete the old build entirely and reconfigure from scratch.
echo "Removing old build/ ..."
rm -rf build
cmake -S . -B build -DDEVICE="$DEV"
cmake --build build -j"$(nproc)"

# 4. Confirm all eight binaries are present.
shopt -s nullglob
bins=(build/system_?_kem*)
shopt -u nullglob
echo ""
echo "Rebuilt ${#bins[@]} binary(ies) for ${DEV}:"
printf '  %s\n' "${bins[@]}"
if (( ${#bins[@]} != 8 )); then
    echo ""
    echo "WARNING: expected 8 binaries (a/b/c/d x kem768/kem1024), got ${#bins[@]}. Check the cmake output above."
    exit 1
fi
echo ""
echo "All 8 present. Optional on-device re-check of the SNOW-Vi path:  ./run_snowvi_tests.sh"
echo "Then: generate payloads with datasets/prepare_real_payloads.py, copy them to LOCAL"
echo "storage, and run  ./run_experiments_real.sh"
