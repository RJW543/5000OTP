#!/bin/bash
# build_snowv.sh
# Compile the SNOW-V reference implementation on a Raspberry Pi.
# Detects the CPU model and selects the correct -march flag automatically.
# Run this after git pull on each device.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---- CPU detection -------------------------------------------------------
# /proc/cpuinfo reports "CPU part" in hex:
#   0xd0b = Cortex-A76  (Raspberry Pi 5)
#   0xd03 = Cortex-A53  (Raspberry Pi Zero 2W)
CPU_PART=$(grep -m1 "CPU part" /proc/cpuinfo | awk '{print $NF}')

case "$CPU_PART" in
    0xd0b)
        MARCH="armv8.2-a+crypto"
        DEVICE="Raspberry Pi 5 (Cortex-A76)"
        ;;
    0xd03)
        MARCH="armv8-a+crypto"
        DEVICE="Raspberry Pi Zero 2W (Cortex-A53)"
        ;;
    *)
        echo "[WARN] Unknown CPU part '$CPU_PART' — falling back to -march=native"
        MARCH="native"
        DEVICE="Unknown (CPU part: $CPU_PART)"
        ;;
esac

echo "[BUILD] Device : $DEVICE"
echo "[BUILD] -march : $MARCH"

# ---- Build ---------------------------------------------------------------
# NOTE: the reference implementation uses C++ struct member functions,
# so we compile with g++, not gcc.

g++ -O2 -march=$MARCH -std=c++11 \
    -o snowv_test \
    main_kat.cpp

echo "[BUILD] snowv_test built successfully."
echo "[BUILD] Run ./validate_snowv.sh to verify against paper test vectors."
