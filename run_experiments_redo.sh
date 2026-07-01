#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/build"
RESULTS_DIR="$SCRIPT_DIR/results_redo"
DURATION=70
THERMAL_LIMIT_C=70
THERMAL_WAIT_S=30
PROGRESS_LOG="$SCRIPT_DIR/completed_runs_redo.log"
EXPERIMENT_LOG="$SCRIPT_DIR/experiment_log_redo.txt"

REDO=(
  "a 768 0 16384 sat_16384 30"
  "a 768 0 32768 sat_32768 30"
  "a 768 0 512 sat_512 30"
  "a 768 0 65536 sat_65536 30"
  "a 768 1.85 32768 video_mean_2frame 1"
  "a 1024 0 16384 sat_16384 30"
  "a 1024 0 32768 sat_32768 30"
  "a 1024 0 512 sat_512 30"
  "a 1024 0 65536 sat_65536 30"
  "d 768 0 16384 sat_16384 30"
  "d 768 0 32768 sat_32768 29"
  "d 768 0 512 sat_512 30"
  "d 768 0 65536 sat_65536 23"
  "d 768 1.85 65536 video_mean_4frame 5"
  "d 768 2.65 32768 video_p95_2frame 30"
  "d 768 2.65 65536 video_p95_4frame 30"
  "d 768 2.69 32768 video_stress_2frame 30"
  "d 768 2.69 65536 video_stress_4frame 29"
  "d 1024 0 16384 sat_16384 10"
  "d 1024 0 512 sat_512 30"
  "d 1024 0 65536 sat_65536 10"
  "d 1024 0.1 512 telemetry_nbiot 17"
  "d 1024 1.85 32768 video_mean_2frame 21"
  "d 1024 1.85 65536 video_mean_4frame 30"
  "d 1024 2.65 32768 video_p95_2frame 30"
  "d 1024 2.65 65536 video_p95_4frame 30"
  "d 1024 2.69 32768 video_stress_2frame 30"
  "d 1024 2.69 65536 video_stress_4frame 30"
  "c 768 0 16384 sat_16384 30"
  "c 768 0 32768 sat_32768 30"
  "c 768 0 512 sat_512 30"
  "c 768 0 65536 sat_65536 30"
  "c 768 1.85 32768 video_mean_2frame 15"
  "c 768 1.85 65536 video_mean_4frame 13"
  "c 768 2.65 32768 video_p95_2frame 2"
  "c 768 2.69 16384 video_stress_max 4"
  "c 1024 0 16384 sat_16384 30"
  "c 1024 0 32768 sat_32768 30"
  "c 1024 0 512 sat_512 30"
  "c 1024 0 65536 sat_65536 30"
  "b 768 0 16384 sat_16384 26"
  "b 768 0 32768 sat_32768 30"
  "b 768 0 512 sat_512 30"
  "b 768 0 65536 sat_65536 30"
  "b 768 0.5 512 telemetry_ltem 15"
  "b 768 0.1 512 telemetry_nbiot 28"
  "b 1024 0 16384 sat_16384 30"
  "b 1024 0 32768 sat_32768 30"
  "b 1024 0 512 sat_512 30"
  "b 1024 0 65536 sat_65536 30"
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

missing=0
for sys in a b c d; do
    for kem in 768 1024; do
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

total=0
for entry in "${REDO[@]}"; do
    total=$(( total + $(awk "{print \$6}" <<< "$entry") ))
done
completed_count=0
[[ -f "$PROGRESS_LOG" ]] && completed_count=$(wc -l < "$PROGRESS_LOG")
log "Redo campaign. Cells: ${#REDO[@]}. Total runs to redo: ${total}. Progress: ${completed_count} already done."

run_number=0
for entry in "${REDO[@]}"; do
    read -r sys kem rate pkt workload reps <<< "$entry"
    for repeat in $(seq 1 "$reps"); do
        run_number=$(( run_number + 1 ))
        run_key="redo sys=${sys} kem=${kem} workload=${workload} repeat=${repeat}"
        already_done "$run_key" && continue

        bin="$BIN_DIR/system_${sys}_kem${kem}"
        log "Run ${run_number}/${total} | System ${sys^^} | KEM-${kem} | ${workload} | ${rate} Mbps | ${pkt}B | repeat ${repeat}/${reps}"

        wait_for_start_temp

        if ( cd "$RESULTS_DIR" && "$bin" "$DURATION" "$rate" "$pkt" ); then
            mark_done "$run_key"
        else
            log "WARNING: non-zero exit for ${run_key} — will retry on next invocation."
        fi
    done
done

final_count=0
[[ -f "$PROGRESS_LOG" ]] && final_count=$(wc -l < "$PROGRESS_LOG")
log "Done. ${final_count}/${total} redo runs completed. CSVs in ${RESULTS_DIR}."
log "Next: move results_redo/*.csv into your Data folder, delete the throttled originals listed in throttled_files.csv, then re-run the gate."
