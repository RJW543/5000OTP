#!/usr/bin/env bash
# run_experiments_real.sh
#
# Experiment 6: the real-dataset payload mirror.  Re-runs the full rate-
# controlled campaign (all twelve workloads: six base + six bundling) with
# actual bytes from the source corpora instead of synthetic plaintext, by
# passing --dataset-source <file> to each binary.  Holding every other
# parameter constant, this yields the real-versus-synthetic delta for latency,
# CPU, RAM and bundling.  Throughput is content-independent by construction, so
# it is not re-measured at saturation here.
#
#   4 systems x 2 KEM levels x 12 workloads x 30 repeats = 2,880 runs/device.
#
# Requires the five pre-processed payload files from
# datasets/prepare_real_payloads.py, copied to PAYLOAD_DIR on THIS device's
# LOCAL storage (never a network mount, which would distort the I/O cost).
# Override the location with:  PAYLOAD_DIR=/path ./run_experiments_real.sh
#
# Execute once per device.  Resumable via completed_runs_real.log.
# Background:
#   nohup ./run_experiments_real.sh > experiment_log_real.txt 2>&1 &

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/build"
RESULTS_DIR="$SCRIPT_DIR/results_real"
PAYLOAD_DIR="${PAYLOAD_DIR:-$HOME/datasets/real_payloads}"
DURATION=70
RUNS=30
THERMAL_LIMIT_C=70
THERMAL_WAIT_S=30
PROGRESS_LOG="$SCRIPT_DIR/completed_runs_real.log"
EXPERIMENT_LOG="$SCRIPT_DIR/experiment_log_real.txt"

SYSTEMS=("a" "b" "c" "d")
KEM_LEVELS=(768 1024)

# Twelve workloads as parallel arrays: rate, packet_bytes, label, payload file.
# The two 512 B telemetry workloads map to DIFFERENT payload files, so the file
# is selected per workload rather than by packet size alone.
WORKLOAD_RATES=(0.1  0.5  0.62  1.85  2.65  2.69   1.85   1.85   2.65   2.65   2.69   2.69)
WORKLOAD_PKTS=( 512  512  16384 16384 16384 16384  32768  65536  32768  65536  32768  65536)
WORKLOAD_NAMES=(
    "telemetry_nbiot"
    "telemetry_ltem"
    "video_low_10fps"
    "video_mean_30fps"
    "video_p95_30fps"
    "video_stress_max"
    "video_mean_2frame"
    "video_mean_4frame"
    "video_p95_2frame"
    "video_p95_4frame"
    "video_stress_2frame"
    "video_stress_4frame"
)
WORKLOAD_PAYLOADS=(
    "real_payloads_telemetry_nbiot.bin"
    "real_payloads_telemetry_ltem.bin"
    "real_payloads_video_1frame.bin"
    "real_payloads_video_1frame.bin"
    "real_payloads_video_1frame.bin"
    "real_payloads_video_1frame.bin"
    "real_payloads_video_2frame.bin"
    "real_payloads_video_4frame.bin"
    "real_payloads_video_2frame.bin"
    "real_payloads_video_4frame.bin"
    "real_payloads_video_2frame.bin"
    "real_payloads_video_4frame.bin"
)

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

# Pre-flight 1: all eight binaries present.
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

# Pre-flight 2: all five distinct payload files present and readable.
for f in real_payloads_telemetry_nbiot.bin \
         real_payloads_telemetry_ltem.bin \
         real_payloads_video_1frame.bin \
         real_payloads_video_2frame.bin \
         real_payloads_video_4frame.bin; do
    if [[ ! -r "$PAYLOAD_DIR/$f" ]]; then
        log "ERROR: missing payload file: $PAYLOAD_DIR/$f"
        missing=1
    fi
done
if (( missing )); then
    log "Generate the payload files with datasets/prepare_real_payloads.py and copy"
    log "them to PAYLOAD_DIR (currently: $PAYLOAD_DIR) on this device's local storage."
    exit 1
fi

mkdir -p "$RESULTS_DIR"

total_runs=$(( ${#SYSTEMS[@]} * ${#KEM_LEVELS[@]} * ${#WORKLOAD_RATES[@]} * RUNS ))
completed_count=0
[[ -f "$PROGRESS_LOG" ]] && completed_count=$(wc -l < "$PROGRESS_LOG")
log "Real-dataset campaign. Total runs: ${total_runs}. Progress: ${completed_count} already done."
log "Payload directory: ${PAYLOAD_DIR}"

run_number=0
for sys in "${SYSTEMS[@]}"; do
for kem in "${KEM_LEVELS[@]}"; do
for i in "${!WORKLOAD_RATES[@]}"; do
for repeat in $(seq 1 $RUNS); do

    rate="${WORKLOAD_RATES[$i]}"
    pkt="${WORKLOAD_PKTS[$i]}"
    workload="${WORKLOAD_NAMES[$i]}"
    payload="$PAYLOAD_DIR/${WORKLOAD_PAYLOADS[$i]}"

    run_number=$(( run_number + 1 ))
    run_key="real sys=${sys} kem=${kem} workload=${workload} repeat=${repeat}"
    already_done "$run_key" && continue

    bin="$BIN_DIR/system_${sys}_kem${kem}"
    log "Run ${run_number}/${total_runs} | System ${sys^^} | KEM-${kem} | ${workload} | ${rate} Mbps | ${pkt}B | real | repeat ${repeat}/${RUNS}"

    wait_for_start_temp

    # CSV is written into RESULTS_DIR; payload bytes come from the .bin file.
    if ( cd "$RESULTS_DIR" && "$bin" "$DURATION" "$rate" "$pkt" --dataset-source "$payload" ); then
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
log "Done. ${final_count}/${total_runs} real-dataset runs completed. CSVs in ${RESULTS_DIR}."
