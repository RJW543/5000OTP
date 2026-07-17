#!/usr/bin/env bash
# run_experiment4_ram.sh
#
# Experiment 4 (RAM footprint), standalone.  A fast re-run to confirm the
# malloc-arena fix in run_loop.hpp (mallopt(M_ARENA_MAX, 1)): AES-256-GCM at
# ML-KEM-1024 should no longer inflate to ~54 MB, and every binary should sit
# near ~24 MB.
#
# Why it can be short and narrow: in the original campaign RSS was
# deterministic (standard deviation 0 across all 30 repeats), identical across
# all six workloads, and identical on both devices to the kilobyte.  RSS is
# therefore workload- and thermal-independent, so one representative workload,
# a short run and a few repeats capture it exactly.  Peak RSS is read straight
# from the rss_kb column of each CSV, so no full re-analysis is needed.
#
# >>> Run on BOTH devices: once on the Pi 5, once on the Pi Zero 2 W. <<<
# The anomaly appeared on both, the fix changes both, and Experiment 4 reports
# RSS per device.  Rebuild on each device first so the fix is compiled in:
#     ./rebuild.sh            # or: cmake --build build -j4
# The binary stamps the device (pi5/pi0) into each CSV name at build time.
#
# Prerequisites (as per the main campaign): CPU governor = performance and
# swap disabled.  RSS depends on neither; they are kept only for consistency.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/build"
RESULTS_DIR="$SCRIPT_DIR/results_exp4_ram"

DURATION=30     # 10 s warm-up + 20 s measurement; RSS is constant, so this is ample
REPEATS=3       # RSS is deterministic; repeats are only a sanity check

# One representative rate-controlled workload.  RSS is workload-independent
# because the ring buffer is pre-allocated to its maximum regardless of packet
# size, so the mean-rate 30 fps video point stands in for all of them.
RATE=1.85
PKT=16384
WORKLOAD="video_mean_30fps"

SYSTEMS=("a" "b" "c" "d")
KEM_LEVELS=(768 1024)
declare -A SYS_NAME=(
  [a]="AES-256-GCM" [b]="SNOW-Vi-GCM"
  [c]="ChaCha20-Poly1305" [d]="Ascon-PRNG-XOR"
)

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# Verify the eight binaries exist on this device.
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
  log "Build first on this device, e.g.: cmake -S . -B build -DDEVICE=PI5 && cmake --build build -j4"
  exit 1
fi

mkdir -p "$RESULTS_DIR"
total=$(( ${#SYSTEMS[@]} * ${#KEM_LEVELS[@]} * REPEATS ))
log "Experiment 4 (RAM) re-run: ${total} runs (8 configs x ${REPEATS}) x ${DURATION}s at ${WORKLOAD} (${RATE} Mbps, ${PKT} B)."
log "CSVs -> $RESULTS_DIR"

run_number=0
for sys in "${SYSTEMS[@]}"; do
for kem in "${KEM_LEVELS[@]}"; do
for repeat in $(seq 1 "$REPEATS"); do
  run_number=$(( run_number + 1 ))
  bin="$BIN_DIR/system_${sys}_kem${kem}"
  log "Run ${run_number}/${total} | System ${sys^^} | KEM-${kem} | repeat ${repeat}/${REPEATS}"
  if ! ( cd "$RESULTS_DIR" && "$bin" "$DURATION" "$RATE" "$PKT" >/dev/null ); then
    log "WARNING: non-zero exit for system_${sys}_kem${kem} repeat ${repeat}"
  fi
done
done
done

# --- Summary: peak RSS (MB) per (system, KEM), read from field 7 (rss_kb). ---
# The packet_id=-1 summary row and pre-first-tick rows carry rss_kb=0 and are
# ignored by the max.  Healthy: AES-256-GCM/1024 near the others (~24 MB).  If
# it is still ~54 MB the arena fix did not take, and massif is the next step.
peak_mb_for() {
  local sys="$1" kem="$2" f v max=0
  for f in "$RESULTS_DIR"/results_"${SYS_NAME[$sys]}"_kem"${kem}"_*.csv; do
    [[ -e "$f" ]] || continue
    v=$(awk -F, 'NR>1 && ($7+0)>m {m=$7} END{print m+0}' "$f")
    if (( v > max )); then max="$v"; fi
  done
  awk -v k="$max" 'BEGIN{ printf "%.1f", k/1024 }'
}

log "-------------------------------------------------------------"
log "Experiment 4 - peak RSS (MB) by system and KEM level:"
printf '  %-20s %9s %9s\n' "System" "KEM-768" "KEM-1024"
for sys in "${SYSTEMS[@]}"; do
  printf '  %-20s %9s %9s\n' "${SYS_NAME[$sys]}" "$(peak_mb_for "$sys" 768)" "$(peak_mb_for "$sys" 1024)"
done
log "-------------------------------------------------------------"
log "Done. To fold these into the paper's analysis, copy ${RESULTS_DIR}/*.csv"
log "into your Desktop\\Data folder and re-run analyse_synthetic.py."
