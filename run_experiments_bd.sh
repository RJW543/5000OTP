#!/usr/bin/env bash
# run_experiments_bd.sh
#
# Full re-run of ONLY System B (SNOW-Vi-GCM) and System D (Ascon-Xof v1.2).
# B changed cipher (SNOW-V -> SNOW-Vi) and D's permutation was re-implemented
# (opt64), so both must be re-collected. Systems A and C are UNCHANGED and are
# deliberately NOT run here.
#
# Runs three regimes for b and d, both KEM levels, 30 repeats each:
#   1. rate-controlled synthetic (12 workloads)  -> results_bd/
#   2. saturation synthetic     (4 packet sizes) -> results_bd/
#   3. real-dataset mirror       (12 workloads)  -> results_bd_real/   (needs payloads)
# That is 28 workloads x 2 systems x 2 KEM x 30 = 3,360 runs/device (1,920 with --no-real).
#
# Before you run: remove the stale System B (SNOW-V) and System D (old Ascon)
# CSVs from your Data folder (remove_snowv_data.py / remove_ascon_data.py), or
# the new and old runs will be mixed.
#
# Resumable via completed_runs_bd.log. Thermal-gated at 70 C start temperature.
# The binary stamps device (pi5/pi0) into each CSV name, so run on each Pi.
#
# Usage:
#   nohup ./run_experiments_bd.sh > experiment_log_bd.txt 2>&1 &
#   PAYLOAD_DIR=/path ./run_experiments_bd.sh     # real-payload location (default ~/datasets/real_payloads)
#   ./run_experiments_bd.sh --no-real             # synthetic only
#   ./run_experiments_bd.sh --validate-only       # run the SNOW-Vi + KAT checks and stop

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/build"
DURATION=70
RUNS=30
THERMAL_LIMIT_C=70
THERMAL_WAIT_S=30
PROGRESS_LOG="$SCRIPT_DIR/completed_runs_bd.log"
EXPERIMENT_LOG="$SCRIPT_DIR/experiment_log_bd.txt"
SYN_DIR="$SCRIPT_DIR/results_bd"
REAL_DIR="$SCRIPT_DIR/results_bd_real"
PAYLOAD_DIR="${PAYLOAD_DIR:-$HOME/datasets/real_payloads}"

SYSTEMS=(b d)
KEM_LEVELS=(768 1024)

# 12 rate-controlled workloads (rate Mbps / packet bytes / name / real-payload file)
WL_RATES=(0.1  0.5  0.62  1.85  2.65  2.69   1.85   1.85   2.65   2.65   2.69   2.69)
WL_PKTS=( 512  512  16384 16384 16384 16384  32768  65536  32768  65536  32768  65536)
WL_NAMES=(telemetry_nbiot telemetry_ltem video_low_10fps video_mean_30fps video_p95_30fps \
          video_stress_max video_mean_2frame video_mean_4frame video_p95_2frame video_p95_4frame \
          video_stress_2frame video_stress_4frame)
WL_PAYLOADS=(real_payloads_telemetry_nbiot.bin real_payloads_telemetry_ltem.bin \
             real_payloads_video_1frame.bin real_payloads_video_1frame.bin real_payloads_video_1frame.bin \
             real_payloads_video_1frame.bin real_payloads_video_2frame.bin real_payloads_video_4frame.bin \
             real_payloads_video_2frame.bin real_payloads_video_4frame.bin real_payloads_video_2frame.bin \
             real_payloads_video_4frame.bin)
# 4 saturation packet sizes (rate limiter off)
SAT_SIZES=(512 16384 32768 65536)

DO_REAL=1; VALIDATE_ONLY=0
for a in "$@"; do
    case "$a" in
        --no-real) DO_REAL=0 ;;
        --validate-only) VALIDATE_ONLY=1 ;;
        *) echo "unknown option: $a" ; exit 2 ;;
    esac
done

log() { local m="[$(date '+%Y-%m-%d %H:%M:%S')] $*"; echo "$m"; echo "$m" >> "$EXPERIMENT_LOG"; }
get_temp_c() { local r; r=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0); echo $((r/1000)); }
wait_for_start_temp() {
    local t; t=$(get_temp_c)
    if (( t >= THERMAL_LIMIT_C )); then
        log "Thermal pause: ${t}C >= ${THERMAL_LIMIT_C}C. Cooling..."
        while (( t >= THERMAL_LIMIT_C )); do sleep "$THERMAL_WAIT_S"; t=$(get_temp_c); log "  ${t}C"; done
    fi
    log "Start temperature: ${t}C (limit <${THERMAL_LIMIT_C}C)"
}
already() { [[ -f "$PROGRESS_LOG" ]] && grep -qF "$1" "$PROGRESS_LOG"; }
mark()    { echo "$1" >> "$PROGRESS_LOG"; }

# ---------------- pre-flight ----------------
# 1. System B must actually be SNOW-Vi (guards against running old SNOW-V).
if ! grep -q '"SNOW-Vi-GCM"' "$SCRIPT_DIR/systems/system_b/cipher.hpp"; then
    log "ERROR: systems/system_b/cipher.hpp is not wired to SNOW-Vi (CipherB::NAME != SNOW-Vi-GCM)."
    log "       Wire System B to SNOW-Vi first, else this would produce SNOW-V data mislabelled."
    exit 1
fi
# 2. Binaries present.
miss=0
for s in "${SYSTEMS[@]}"; do for k in "${KEM_LEVELS[@]}"; do
    [[ -x "$BIN_DIR/system_${s}_kem${k}" ]] || { log "ERROR: missing binary $BIN_DIR/system_${s}_kem${k}"; miss=1; }
done; done
(( miss )) && { log "Build first: cmake -S . -B build -DDEVICE=PI5 (or PI0) && cmake --build build -j4"; exit 1; }

# 3. Validate before committing hours: SNOW-Vi (incl. the on-Pi PMULL GHASH) + the System B/D KATs.
log "Pre-flight validation..."
if [[ -x "$SCRIPT_DIR/run_snowvi_tests.sh" ]]; then
    bash "$SCRIPT_DIR/run_snowvi_tests.sh" || { log "ERROR: SNOW-Vi tests failed; aborting."; exit 1; }
else
    log "WARN: run_snowvi_tests.sh not found; skipping SNOW-Vi validation."
fi
for kat in kat_system_b kat_system_d; do
    p=$(find "$BIN_DIR" -name "$kat" -type f 2>/dev/null | head -1)
    [[ -n "$p" && -x "$p" ]] && { "$p" >/dev/null && log "$kat: PASS" || { log "ERROR: $kat FAILED"; exit 1; }; }
done
(( VALIDATE_ONLY )) && { log "Validation only: done."; exit 0; }

mkdir -p "$SYN_DIR"
[[ -f "$PROGRESS_LOG" ]] && log "Resuming; $(wc -l < "$PROGRESS_LOG") runs already done."

# run_one <regime> <sys> <kem> <rate> <pkt> <name> <results_dir> [payload_path]
run_one() {
    local regime="$1" s="$2" k="$3" rate="$4" pkt="$5" name="$6" rdir="$7" payload="${8:-}"
    local bin="$BIN_DIR/system_${s}_kem${k}"
    local rep key
    for rep in $(seq 1 "$RUNS"); do
        key="bd $regime sys=$s kem=$k wl=$name rep=$rep"
        already "$key" && continue
        log "[$regime] System ${s^^} | KEM-$k | $name | ${rate} Mbps | ${pkt}B | rep $rep/$RUNS"
        wait_for_start_temp
        if [[ -n "$payload" ]]; then
            ( cd "$rdir" && "$bin" "$DURATION" "$rate" "$pkt" --dataset-source "$payload" ) && mark "$key" || log "WARN: nonzero exit for $key"
        else
            ( cd "$rdir" && "$bin" "$DURATION" "$rate" "$pkt" ) && mark "$key" || log "WARN: nonzero exit for $key"
        fi
    done
}

# ---------------- regime 1: rate-controlled synthetic ----------------
log "=== Regime 1/3: rate-controlled synthetic ==="
for s in "${SYSTEMS[@]}"; do for k in "${KEM_LEVELS[@]}"; do
    for i in "${!WL_RATES[@]}"; do
        run_one rate "$s" "$k" "${WL_RATES[$i]}" "${WL_PKTS[$i]}" "${WL_NAMES[$i]}" "$SYN_DIR"
    done
done; done

# ---------------- regime 2: saturation synthetic (rate 0) ----------------
log "=== Regime 2/3: saturation synthetic ==="
for s in "${SYSTEMS[@]}"; do for k in "${KEM_LEVELS[@]}"; do
    for sz in "${SAT_SIZES[@]}"; do
        run_one sat "$s" "$k" 0 "$sz" "sat_${sz}" "$SYN_DIR"
    done
done; done

# ---------------- regime 3: real-dataset mirror ----------------
if (( DO_REAL )); then
    log "=== Regime 3/3: real-dataset mirror ==="
    real_ok=1
    for f in real_payloads_telemetry_nbiot.bin real_payloads_telemetry_ltem.bin \
             real_payloads_video_1frame.bin real_payloads_video_2frame.bin real_payloads_video_4frame.bin; do
        [[ -r "$PAYLOAD_DIR/$f" ]] || { log "WARN: missing payload $PAYLOAD_DIR/$f"; real_ok=0; }
    done
    if (( real_ok )); then
        mkdir -p "$REAL_DIR"
        for s in "${SYSTEMS[@]}"; do for k in "${KEM_LEVELS[@]}"; do
            for i in "${!WL_RATES[@]}"; do
                run_one real "$s" "$k" "${WL_RATES[$i]}" "${WL_PKTS[$i]}" "${WL_NAMES[$i]}" \
                        "$REAL_DIR" "$PAYLOAD_DIR/${WL_PAYLOADS[$i]}"
            done
        done; done
    else
        log "Skipping real-data regime: payloads missing in $PAYLOAD_DIR."
        log "Copy the five .bin files there, or re-run with --no-real to silence this."
    fi
fi

final=0; [[ -f "$PROGRESS_LOG" ]] && final=$(wc -l < "$PROGRESS_LOG")
log "Done. Completed $final runs. Synthetic CSVs -> $SYN_DIR ; real CSVs -> $REAL_DIR (if run)."
log "Next: copy results_bd/ into your synthetic Data folder and results_bd_real/ into the real-data folder, then analyse."
