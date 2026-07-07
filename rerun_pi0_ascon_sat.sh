#!/usr/bin/env bash
# rerun_pi0_ascon_sat.sh  -- run on the Pi ZERO 2 W only.
#
# Re-collects System D (Ascon) SATURATION on the Pi Zero, which the campaign
# understated by about half. A clean isolated run (diag_pi0_ascon_clock.sh) did
# 202 Mbps at 65536 B, at a full 1 GHz, no throttle flags, matching the
# 37 ns/byte per-byte cost -- yet the campaign large-packet saturation cells
# plateau at ~90-105 Mbps. Clock, temperature and cipher are all ruled out, so
# the campaign figures are a collection-condition artefact of that batch.
#
# This regenerates 30 clean runs per saturation cell. Because dedup_runs.py keeps
# the newest 30 by timestamp, these fresh runs REPLACE the suspect ones with no
# separate delete step. Each kept run prints its SUSTAINED throughput so you can
# watch it land near 200, not 100.
#
#   4 sizes x 2 KEM x 30 = 240 runs, roughly 5-6 h.
#   To shorten: trim SIZES or KEMS below. sat_512 (~17 Mbps) is overhead-bound,
#   not anomalous, so SIZES=(16384 32768 65536) is a defensible faster subset.
#
# Output -> results_bd_satfix0/. Copy into Data, then dedup + gate + analyse.
#
# Usage:   nohup ./rerun_pi0_ascon_sat.sh > satfix0.log 2>&1 &
#          SIZES="16384 32768 65536" ./rerun_pi0_ascon_sat.sh

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATE="$SCRIPT_DIR/validate_run.py"
OUT="$SCRIPT_DIR/results_bd_satfix0"
DURATION=70
THERMAL_LIMIT_C="${THERMAL_LIMIT_C:-70}"
THERMAL_WAIT_S=30
RUNS="${RUNS:-30}"
read -r -a KEMS  <<< "${KEMS:-768 1024}"
read -r -a SIZES <<< "${SIZES:-512 16384 32768 65536}"

get_temp_c() { local r; r=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0); echo $((r/1000)); }
cool() {
    local t; t=$(get_temp_c)
    while (( t >= THERMAL_LIMIT_C )); do
        echo "    cooling: ${t}C >= ${THERMAL_LIMIT_C}C ..."; sleep "$THERMAL_WAIT_S"; t=$(get_temp_c)
    done
}
# sustained post-warmup throughput of one CSV, in Mbps (for live confirmation)
sustained_mbps() {
    python3 - "$1" <<'PY'
import sys, csv
WARM = 10e9
ts, by = [], []
for r in csv.reader(open(sys.argv[1])):
    if len(r) < 3 or r[1] in ("-1", "packet_id"):
        continue
    try:
        t, b = int(r[0]), int(r[2])
    except ValueError:
        continue
    ts.append(t); by.append(b)
if len(ts) < 2:
    print("NA"); sys.exit()
t0 = ts[0]
k = [(t, b) for t, b in zip(ts, by) if t - t0 >= WARM]
if len(k) < 2:
    print("NA"); sys.exit()
span = (k[-1][0] - k[0][0]) / 1e9
print("%.0f" % (sum(b for _, b in k) * 8 / span / 1e6))
PY
}

[[ -f "$VALIDATE" ]] || { echo "ERROR: missing $VALIDATE next to this script"; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 not found on this Pi"; exit 1; }
for k in "${KEMS[@]}"; do
    [[ -x "$SCRIPT_DIR/build/system_d_kem${k}" ]] || { echo "ERROR: missing build/system_d_kem${k} (build the PI0 tree first)"; exit 1; }
done
mkdir -p "$OUT"; cd "$OUT"

total=0
for k in "${KEMS[@]}"; do
    BIN="$SCRIPT_DIR/build/system_d_kem${k}"
    GLOB="results_Ascon-PRNG-XOR_kem${k}_pi0_*.csv"
    for sz in "${SIZES[@]}"; do
        name="sat_${sz}"; got=0; att=0; maxatt=$(( RUNS * 3 + 6 ))
        echo "=== kem${k}  ${name}: need ${RUNS} ==="
        while (( got < RUNS )); do
            (( ++att ))
            if (( att > maxatt )); then
                echo "  WARNING: ${att} attempts, only ${got}/${RUNS} for kem${k} ${name}; stopping this cell."; break
            fi
            cool
            before=$(ls -t $GLOB 2>/dev/null | head -1)
            "$BIN" "$DURATION" 0 "$sz" || echo "  (binary returned non-zero)"
            after=$(ls -t $GLOB 2>/dev/null | head -1)
            if [[ -z "$after" || "$after" == "$before" ]]; then
                echo "  no new pi0 CSV appeared -- is this really the PI0 build?"; continue
            fi
            if python3 "$VALIDATE" "$after" "$name" "$DURATION" >/dev/null; then
                (( ++got, ++total )); echo "  kept ${got}/${RUNS}: $(sustained_mbps "$after") Mbps sustained  ${after##*/}"
            else
                rm -f "$after"
            fi
        done
        echo ""
    done
done

echo "Done. ${total} good run(s) in: $OUT"
echo "If these read ~200 Mbps at 32768/65536, the campaign column was the artefact; proceed to replace it:"
echo "  1. copy $OUT/*.csv into your Data folder"
echo "  2. dedup_runs.py --results <Data> --apply   (newest-30 keeps these, drops the old ~100 Mbps runs)"
echo "  3. re-gate and re-analyse"
