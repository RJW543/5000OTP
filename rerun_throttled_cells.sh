#!/usr/bin/env bash
# rerun_throttled_cells.sh
#
# Re-runs ONLY the pi5 cells that contained runs above the 80 C throttle limit
# in the 02 Jul 2026 synthetic analysis (analyse_synthetic.py integrity gate).
# It is the automated equivalent of run_experiments_redo.sh, regenerated from
# analysis_out/cells_to_rerun.csv.
#
#   14 cells, 65 runs total (all pi5).  The per-cell "reps" is the number of
#   throttled runs in that cell, i.e. the count needed to top each cell back to
#   30 clean repeats after the throttled originals are deleted.
#
# >>> RUN THIS ON THE PI 5 ONLY. <<<
# Every listed cell is a pi5 cell.  The binary stamps the device into each CSV
# name at build time (-DDEVICE=PI5), so running it on the Pi Zero would write
# pi0 files and corrupt the wrong cells.
#
# Format of each REDO entry:  "sys kem rate pkt workload reps"
#   sys      a=AES-256-GCM  b=SNOW-V-GCM  c=ChaCha20-Poly1305  d=Ascon-PRNG-XOR
#   rate     Mbps for rate-controlled workloads; 0 = saturation (limiter off)
#   pkt      packet_bytes
#   reps     repeats to run for this cell
#
# Resumable via completed_runs_rerun.log.  Background:
#   nohup ./rerun_throttled_cells.sh > experiment_log_rerun.txt 2>&1 &
#
# Thermal note: these cells throttled because they heat the SoC DURING the run,
# which the pre-run 70 C gate cannot prevent.  To get genuinely clean replacements
# improve cooling (active fan / lower ambient) before running.  THERMAL_LIMIT_C is
# kept at 70 to match the rest of the campaign; lowering it would start these runs
# from a cooler baseline than every other cell, which is itself an inconsistency.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/build"
RESULTS_DIR="$SCRIPT_DIR/results_rerun"
DURATION=70          # 10 s warm-up + 60 s measurement
THERMAL_LIMIT_C=70   # maximum permitted START temperature in °C
THERMAL_WAIT_S=30
PROGRESS_LOG="$SCRIPT_DIR/completed_runs_rerun.log"
EXPERIMENT_LOG="$SCRIPT_DIR/experiment_log_rerun.txt"

# One entry per throttled cell (generated from analysis_out/cells_to_rerun.csv).
REDO=(
  "a 768 1.85 32768 video_mean_2frame 1"
  "b 768 0 16384 sat_16384 4"
  "b 768 0.1 512 telemetry_nbiot 2"
  "c 768 1.85 32768 video_mean_2frame 6"
  "c 768 1.85 65536 video_mean_4frame 9"
  "c 768 2.65 32768 video_p95_2frame 1"
  "c 768 2.69 16384 video_stress_max 4"
  "d 768 0 65536 sat_65536 7"
  "d 768 1.85 65536 video_mean_4frame 6"
  "d 768 2.69 65536 video_stress_4frame 1"
  "d 1024 0 16384 sat_16384 2"
  "d 1024 0 65536 sat_65536 7"
  "d 1024 0.1 512 telemetry_nbiot 6"
  "d 1024 1.85 32768 video_mean_2frame 9"
)

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg"
    echo "$msg" >> "$EXPERIMENT_LOG"
}

# get_temp_c() - SoC temperature in whole degrees C via kernel sysfs.
get_temp_c() {
    local raw
    raw=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo "0")
    echo $(( raw / 1000 ))
}

# wait_for_start_temp() - block until the SoC is below THERMAL_LIMIT_C.
# Called only before a run starts; a run is never interrupted once launched.
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

# Verify the binaries these cells need (systems a,b,c,d; kem 768 and 1024).
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
    read -r _s _k _r _p _w reps <<< "$entry"
    total=$(( total + reps ))
done
completed_count=0
[[ -f "$PROGRESS_LOG" ]] && completed_count=$(wc -l < "$PROGRESS_LOG")
log "Re-run of throttled pi5 cells. Cells: ${#REDO[@]}. Runs to do: ${total}. Progress: ${completed_count} already done."
log "REMINDER: run on the Pi 5 only (all cells are pi5)."

run_number=0
for entry in "${REDO[@]}"; do
    read -r sys kem rate pkt workload reps <<< "$entry"
    for repeat in $(seq 1 "$reps"); do
        run_number=$(( run_number + 1 ))
        run_key="rerun sys=${sys} kem=${kem} workload=${workload} repeat=${repeat}"
        already_done "$run_key" && continue

        bin="$BIN_DIR/system_${sys}_kem${kem}"
        log "Run ${run_number}/${total} | System ${sys^^} | KEM-${kem} | ${workload} | ${rate} Mbps | ${pkt}B | repeat ${repeat}/${reps}"

        wait_for_start_temp

        # CSV is written into RESULTS_DIR; rate 0 = saturation.
        if ( cd "$RESULTS_DIR" && "$bin" "$DURATION" "$rate" "$pkt" ); then
            mark_done "$run_key"
        else
            log "WARNING: non-zero exit for ${run_key} — will retry on next invocation."
        fi
    done
done

final_count=0
[[ -f "$PROGRESS_LOG" ]] && final_count=$(wc -l < "$PROGRESS_LOG")
log "Done. ${final_count}/${total} re-runs completed. CSVs in ${RESULTS_DIR}."
log "Next steps (on the analysis machine):"
log "  1. Copy results_rerun/*.csv into your Desktop\\Data folder."
log "  2. Delete the 65 throttled originals listed in analysis_out\\throttled_runs_to_delete.csv."
log "  3. Re-run analyse_synthetic.py; each cell should now hold 30 clean runs and the gate should pass."
log "  (Before deleting, spot-check the new CSVs did not themselves exceed 80 C, or those cells will need another pass.)"
