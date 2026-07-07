#!/usr/bin/env bash
# rerun_pi5_ascon_sat.sh  -- run on the Pi 5 only.
#
# Re-collects System D (Ascon) SATURATION for kem1024 on the Pi 5. That column
# was collected in the troubled July-4 batch (the one that also produced the
# corrupt CSVs) and carries slow outliers: sat_512 CV 31% (runs at 17-33 vs a
# 180 Mbps median), sat_16384/sat_32768 with runs ~445 vs ~635. kem768 saturation
# and sat_65536 kem1024 are clean and are NOT re-run here.
#
# Same design as rerun_pi0_ascon_sat.sh: 30 clean validated runs per cell, so
# dedup (newest-30) replaces the suspect runs with no separate delete. Each kept
# run prints its sustained throughput so you can watch it land on the ~180-660
# band rather than the slow tail.
#
#   Default: kem1024, all four sizes = 120 runs (~2.5-3 h).
#   sat_65536 kem1024 is already clean; drop it with  SIZES="512 16384 32768".
#   kem768 is clean; do not add it unless a spot-check says otherwise.
#
# Output -> results_bd_satfix5/. Copy into Data, then dedup + gate + analyse.
#
# Usage:   nohup ./rerun_pi5_ascon_sat.sh > satfix5.log 2>&1 &
#          SIZES="512 16384 32768" ./rerun_pi5_ascon_sat.sh

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATE="$SCRIPT_DIR/validate_run.py"
OUT="$SCRIPT_DIR/results_bd_satfix5"
DURATION=70
THERMAL_LIMIT_C="${THERMAL_LIMIT_C:-55}"
THERMAL_WAIT_S=30
RUNS="${RUNS:-30}"
read -r -a KEMS  <<< "${KEMS:-1024}"
read -r -a SIZES <<< "${SIZES:-512 16384 32768 65536}"

get_temp_c() { local r; r=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0); echo $((r/1000)); }
cool() {
    local t; t=$(get_temp_c)
    while (( t >= THERMAL_LIMIT_C )); do
        echo "    cooling: ${t}C >= ${THERMAL_LIMIT_C}C ..."; sleep "$THERMAL_WAIT_S"; t=$(get_temp_c)
    done
}
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
    [[ -x "$SCRIPT_DIR/build/system_d_kem${k}" ]] || { echo "ERROR: missing build/system_d_kem${k} (build the PI5 tree first)"; exit 1; }
done
mkdir -p "$OUT"; cd "$OUT"

total=0
for k in "${KEMS[@]}"; do
    BIN="$SCRIPT_DIR/build/system_d_kem${k}"
    GLOB="results_Ascon-PRNG-XOR_kem${k}_pi5_*.csv"
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
                echo "  no new pi5 CSV appeared -- is this really the PI5 build?"; continue
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
echo "Next: copy $OUT/*.csv into Data, then dedup --apply, gate, analyse."
