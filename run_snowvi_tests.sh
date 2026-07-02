#!/usr/bin/env bash
# run_snowvi_tests.sh
#
# Builds and runs the SNOW-Vi validation tests only. It does NOT build the main
# project, touch System B, or run any experiment. It compiles the SNOW-Vi source
# in libs/snowv/ (snow-vi.h, snowvi_ghash.hpp, snowvi_gcm.hpp) with the tests in
# tests/snowvi_*.cpp and reports pass/fail.
#
# GHASH path is chosen by hardware, so this doubles as the on-device acceptance
# test for the accelerated GHASH:
#   - Pi 5  (Cortex-A76, crypto ext) -> PMULL GHASH   (-march=armv8.2-a+crypto)
#   - Zero  (Cortex-A53, no crypto)  -> 4-bit table    (-march=armv8-a)
#   - x86 dev host                   -> PCLMUL GHASH   (-mpclmul ...)
#
# Usage:  ./run_snowvi_tests.sh            (auto-detect arch)
#         CXX=g++-12 ./run_snowvi_tests.sh (override compiler)
#         FLAGS="-march=armv8-a" ./run_snowvi_tests.sh  (force flags)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INC="-I$SCRIPT_DIR/libs/snowv"
CXX="${CXX:-g++}"
STD="-std=c++17 -O2"

# Pick architecture flags: use hardware crypto where present, else portable.
if [[ -n "${FLAGS:-}" ]]; then
    PATHNOTE="user-supplied FLAGS"
else
    ARCH="$(uname -m)"
    case "$ARCH" in
        aarch64|arm*)
            if grep -qiE '(^| )(aes|pmull)( |$)' /proc/cpuinfo 2>/dev/null; then
                FLAGS="-march=armv8.2-a+crypto"; PATHNOTE="ARM + crypto ext -> PMULL GHASH"
            else
                FLAGS="-march=armv8-a";          PATHNOTE="ARM, no crypto ext -> table GHASH"
            fi ;;
        x86_64|i?86)
            FLAGS="-mpclmul -mssse3 -msse2 -maes"; PATHNOTE="x86 -> PCLMUL GHASH" ;;
        *)
            FLAGS="";                              PATHNOTE="unknown arch -> portable table GHASH" ;;
    esac
fi

echo "SNOW-Vi test build:  arch=$(uname -m)  |  $PATHNOTE"
echo "compiler: $CXX $STD $FLAGS"
echo "------------------------------------------------------------"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail=0

run_one() {
    local src="$1" name="$2" title="$3"
    echo "=== $title ==="
    if ! $CXX $STD $FLAGS $INC "$SCRIPT_DIR/tests/$src" -o "$TMP/$name" 2>"$TMP/$name.log"; then
        echo "  BUILD FAILED:"; sed 's/^/    /' "$TMP/$name.log" | head -25
        fail=1; echo ""; return
    fi
    if ! "$TMP/$name"; then fail=1; fi
    echo ""
}

run_one snowvi_kat.cpp        snowvi_kat        "1. SNOW-Vi KAT (official keystream vectors)"
run_one snowvi_ghash_kat.cpp  snowvi_ghash_kat  "2. Accelerated GHASH vs bitwise reference"
run_one snowvi_gcm_kat.cpp    snowvi_gcm_kat    "3. SNOW-Vi-GCM (round-trip / tamper / re-derivation)"

echo "------------------------------------------------------------"
if (( fail )); then
    echo "RESULT: SNOW-Vi TESTS FAILED (see above)"
    exit 1
else
    echo "RESULT: ALL SNOW-Vi TESTS PASSED"
fi
