#!/usr/bin/env bash
# run_experiments_saturation.sh
#
# Experiment 1 (maximum throughput) and the saturation half of Experiment 7.
# Runs each pipeline FLAT OUT (rate_mbps = 0): the producer disables the rate
# limiter and encrypts/enqueues continuously, so the bottleneck thread is fully
# loaded and the figure reported is the true sustained end-to-end rate.  Only
# the packet size varies, so the twelve workloads collapse to four distinct
# sizes (512, 16384, 32768, 65536 B).
#
#   4 systems x 2 KEM levels x 4 packet sizes x 30 repeats = 960 runs/device.
#
# Depends on the harness changes in CODE_CHANGES_REQUIRED.md: rate_mbps = 0
# disables the limiter, and the SPSC ring buffer blocks (no drop) when full so
# System D's continuous keystream stays synchronised.
#
# Execute once per device.  Resumable via completed_runs_saturation.log.
# Background:
#   nohup ./run_experiments_saturation.sh > experiment_log_saturation.txt 2>&1 &

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/build"
RESULTS_DIR="$SCRIPT_DIR/results_saturation"
DURATION=70          # 10 s warm-up + 60 s measurement
RUNS=30
THERMAL_LIMIT_C=70   # maximum permitted START temperature in °C
THERMAL_WAIT_S=30
PROGRESS_LOG="$SCRIPT_DIR/completed_runs_saturation.log"
EXPERIMENT_LOG="$SCRIPT_DIR/experiment_log_saturation.txt"

SYSTEMS=("a" "b" "c" "d")
KEM_LEVELS=(768 1024)

# Four distinct packet sizes: telemetry (512), 1-frame (16384),
# 2-frame bundle (32768), 4-frame bundle (65536).
PACKET_SIZES=(512 16384 32768 65536)

# Time-saver: ML-KEM runs once at startup and is outside the 60 s throughput
# window, so saturation does not depend on the KEM level.  Restrict to a single
# level for 480 runs by uncommenting the next line.
# KEM_LEVELS=(768)

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg"
    echo "$msg" >> "$EXPERIMENT_LOG"
}

get_temp_c() {
    local raw
    raw=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo "0")
    echo $(( raw / 1000 ))
}

wait_for_start_temp() {
    local temp
    temp=$(get_temp_c)
    if (( temp >= THERMAL_LIMIT_C )); then
        log "Thermal pause: ${temp}°C >= ${THERMAL_LIMIT_C}°C. Cooling before next run..."
        while (( temp >= THERMAL_LIMIT_C )); do
            sleep "$THERMAL_WAIT_S"
            temp=$(get_temp_c)
            log "  Cooling: ${temp}°C"
        done
    fi
    log "Start temperature: ${temp}°C  (limit: <${THERMAL_LIMIT_C}°C)"
}

already_done() { [[ -f "$PROGRESS_LOG" ]] && grep -qF "$1" "$PROGRESS_LOG"; }
mark_done()    { echo "$1" >> "$PROGRESS_LOG"; }

# Verify all binaries exist.
missing=0
for sys in "${SYSTEMS[@]}"; do
    for kem in "${KEM_LEVELS[@]}"; do
        if [[ ! -x "$BIN_DIR/system_${sys}_kem${kem}" ]]; then
            log "ERROR: missing binary: $BIN_DIR/system_${sys}_kem${kem}"
            missing=1
        fi
    done
done
if (( missing )); then
    log "Build first: cmake -S . -B build -DDEVICE=PI5 && cmake --build build -j4"
    exit 1
fi

mkdir -p "$RESULTS_DIR"

total_runs=$(( ${#SYSTEMS[@]} * ${#KEM_LEVELS[@]} * ${#PACKET_SIZES[@]} * RUNS ))
completed_count=0
[[ -f "$PROGRESS_LOG" ]] && completed_count=$(wc -l < "$PROGRESS_LOG")
log "Saturation campaign. Total runs: ${total_runs}. Progress: ${completed_count} already done."

run_number=0
for sys in "${SYSTEMS[@]}"; do
for kem in "${KEM_LEVELS[@]}"; do
for size in "${PACKET_SIZES[@]}"; do
for repeat in $(seq 1 $RUNS); do

    run_number=$(( run_number + 1 ))
    run_key="sat sys=${sys} kem=${kem} size=${size} repeat=${repeat}"
    already_done "$run_key" && continue

    bin="$BIN_DIR/system_${sys}_kem${kem}"
    log "Run ${run_number}/${total_runs} | System ${sys^^} | KEM-${kem} | ${size}B | rate 0 (saturation) | repeat ${repeat}/${RUNS}"

    wait_for_start_temp

    # rate_mbps = 0 → saturation.  CSV is written into RESULTS_DIR.
    if ( cd "$RESULTS_DIR" && "$bin" "$DURATION" 0 "$size" ); then
        mark_done "$run_key"
    else
        log "WARNING: non-zero exit for ${run_key} — will retry on next invocation."
    fi

done
done
done
done

final_count=0
[[ -f "$PROGRESS_LOG" ]] && final_count=$(wc -l < "$PROGRESS_LOG")
log "Done. ${final_count}/${total_runs} saturation runs completed. CSVs in ${RESULTS_DIR}."
