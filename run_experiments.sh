#!/usr/bin/env bash
# run_experiments.sh
#
# Runs all benchmark combinations for the dissertation.
# Execute once per device (Pi 5 and Pi Zero 2 W).
#
# Workload parameters are derived from four real-world datasets
# (see dev_log.md Entry 012 and datasets/analyse_datasets.py):
#
#   Workload                    rate_mbps  packet_bytes  Source
#   Telemetry - NB-IoT          0.1        512           UCI Household Power + TON_IoT
#   Telemetry - LTE-M           0.5        512           Edge-IIoTset (Ferrag et al. 2022)
#   Video - low (~10 fps)       0.62       16384         UCF-Crime (Sultani et al. 2018)
#   Video - mean (30 fps)       1.85       16384         UCF-Crime
#   Video - p95 (30 fps)        2.65       16384         UCF-Crime
#   Video - stress/max          2.69       16384         UCF-Crime
#
# Workloads are run as explicit (rate, packet_bytes) pairs, NOT as a
# Cartesian product. Crossing telemetry rates with video packet sizes
# (or vice versa) would produce combinations with no real-world analogue.
#
# Iterates over:
#   Systems A-D, KEM levels 768/1024, 6 workload pairs, 30 repeats.
#   Total: 4 x 2 x 6 x 30 = 1,440 runs (~28 hours).
#
# Resumable: completed runs are recorded in completed_runs.log.
# Interrupt with Ctrl+C and restart safely at any time.
#
# Background usage:
#   nohup ./run_experiments.sh > experiment_log.txt 2>&1 &
#
# Thermal management philosophy
# ------------------------------
# Temperature is checked and enforced BEFORE each run only.
# A run is never paused or interrupted once it has started.
# If a cipher causes the SoC to heat up during a run, that is
# valid data reflecting the real computational cost of that system.
# The only requirement is that all runs begin from a consistent
# thermal baseline (below THERMAL_LIMIT_C) so that starting
# conditions are comparable across systems and repetitions.

set -euo pipefail

BIN_DIR="./build"
DURATION=70        # 10 s warm-up + 60 s measurement
RUNS=30
THERMAL_LIMIT_C=70  # maximum permitted START temperature in °C
THERMAL_WAIT_S=30   # seconds between temperature re-checks during a cooling pause
PROGRESS_LOG="completed_runs.log"
EXPERIMENT_LOG="experiment_log.txt"

SYSTEMS=("a" "b" "c" "d")
KEM_LEVELS=(768 1024)

# Workload pairs derived from dataset analysis (datasets/analyse_datasets.py).
# Each index i defines one (rate, packet_bytes, label) workload tuple.
# Generated: 2026-05-30. Re-run analyse_datasets.py if datasets change.
WORKLOAD_RATES=(0.1   0.5   0.62   1.85   2.65          2.69)
WORKLOAD_PKTS=(512   512   16384  16384  16384          16384)
WORKLOAD_NAMES=(
    "telemetry_nbiot"
    "telemetry_ltem"
    "video_low_10fps"
    "video_mean_30fps"
    "video_p95_30fps"
    "video_stress_max"
)

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg"
    echo "$msg" >> "$EXPERIMENT_LOG"
}

# get_temp_c() - reads SoC temperature in whole degrees Celsius.
# Uses the kernel sysfs thermal interface, which is present on both
# Pi 5 and Pi Zero 2 W under Raspberry Pi OS and does not require
# vcgencmd or any additional tooling.  Returns 0 if the file is
# unreadable (e.g. unexpected OS); runs will proceed without pausing.
get_temp_c() {
    local raw
    raw=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo "0")
    echo $(( raw / 1000 ))
}

# wait_for_start_temp() - blocks until the SoC temperature is below
# THERMAL_LIMIT_C, then logs the actual start temperature.
#
# Called once immediately before each binary is launched.
# It is NEVER called during a run — a run that heats the device
# reflects the true cost of that cipher and must not be interrupted.
wait_for_start_temp() {
    local temp
    temp=$(get_temp_c)
    if (( temp >= THERMAL_LIMIT_C )); then
        log "Thermal pause: ${temp}°C >= ${THERMAL_LIMIT_C}°C. Waiting to cool before next run..."
        while (( temp >= THERMAL_LIMIT_C )); do
            sleep "$THERMAL_WAIT_S"
            temp=$(get_temp_c)
            log "  Cooling: ${temp}°C"
        done
    fi
    log "Start temperature: ${temp}°C  (limit: <${THERMAL_LIMIT_C}°C)"
}

already_done() {
    [[ -f "$PROGRESS_LOG" ]] && grep -qF "$1" "$PROGRESS_LOG"
}

mark_done() {
    echo "$1" >> "$PROGRESS_LOG"
}

# verify all binaries exist.
missing=0
for sys in "${SYSTEMS[@]}"; do
    for kem in "${KEM_LEVELS[@]}"; do
        bin="${BIN_DIR}/system_${sys}_kem${kem}"
        if [[ ! -x "$bin" ]]; then
            log "ERROR: missing binary: $bin"
            missing=1
        fi
    done
done
if (( missing )); then
    log "Build first: cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j4"
    exit 1
fi

total_runs=$(( ${#SYSTEMS[@]} * ${#KEM_LEVELS[@]} * ${#WORKLOAD_RATES[@]} * RUNS ))
completed_count=0
[[ -f "$PROGRESS_LOG" ]] && completed_count=$(wc -l < "$PROGRESS_LOG")
log "Starting. Total runs: ${total_runs}. Progress: ${completed_count} already done."

run_number=0

for sys in "${SYSTEMS[@]}"; do
for kem in "${KEM_LEVELS[@]}"; do
for i in "${!WORKLOAD_RATES[@]}"; do
for repeat in $(seq 1 $RUNS); do

    rate="${WORKLOAD_RATES[$i]}"
    pkt="${WORKLOAD_PKTS[$i]}"
    workload="${WORKLOAD_NAMES[$i]}"

    run_number=$(( run_number + 1 ))
    run_key="sys=${sys} kem=${kem} workload=${workload} repeat=${repeat}"

    if already_done "$run_key"; then
        continue
    fi

    bin="${BIN_DIR}/system_${sys}_kem${kem}"
    log "Run ${run_number}/${total_runs} | System ${sys^^} | KEM-${kem} | ${workload} | ${rate} Mbps | ${pkt}B | repeat ${repeat}/${RUNS}"

    # Pre-run thermal check. The binary is launched only after the SoC
    # temperature is confirmed below THERMAL_LIMIT_C.  Once launched,
    # the binary runs to completion without any thermal intervention.
    wait_for_start_temp

    if "$bin" "$DURATION" "$rate" "$pkt"; then
        mark_done "$run_key"
    else
        log "WARNING: non-zero exit for $run_key — will retry on next invocation."
    fi

done
done
done
done

final_count=0
[[ -f "$PROGRESS_LOG" ]] && final_count=$(wc -l < "$PROGRESS_LOG")
log "Done. ${final_count}/${total_runs} runs completed. $(ls results_*.csv 2>/dev/null | wc -l) CSV files in $(pwd)."
