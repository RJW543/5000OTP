#!/usr/bin/env bash
# rerun_pi5_ascon_sat.sh  — run on the Pi 5 ONLY.
#
# Tops up the two short cells left after the campaign:
#   System D (Ascon), kem1024, sat_32768  (need 1 more good run)
#   System D (Ascon), kem1024, sat_65536  (need 14 more good runs)
#
# These are the largest-packet saturation runs, the hottest workload, which is
# why they truncated before. So this script:
#   - is thermal-gated with a STRICTER start limit than the campaign (55 C),
#   - verifies each CSV is complete (thousands of rows, not a truncated stub),
#     discards and retries any truncated run, and
#   - stops with a warning if runs keep truncating even when cool (which would
#     mean a real hardware/cooling problem, not bad luck).
#
# Output goes to results_bd_fix/. Copy those into your Data folder afterwards,
# re-run dedup_runs.py (keeps newest 30), then the gate.
#
# Usage:   ./rerun_pi5_ascon_sat.sh
#          THERMAL_LIMIT_C=60 ./rerun_pi5_ascon_sat.sh   # relax the start gate

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/build/system_d_kem1024"
OUT="$SCRIPT_DIR/results_bd_fix"
DURATION=70
THERMAL_LIMIT_C="${THERMAL_LIMIT_C:-55}"   # stricter than the 70 campaign default
THERMAL_WAIT_S=30
MIN_LINES=1000                             # a full 70 s saturation run has tens of thousands

# work list: "packet_size:good_runs_needed"  (largest/hottest first)
WORK=("65536:14" "32768:1")

get_temp_c() { local r; r=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0); echo $((r/1000)); }
cool() {
    local t; t=$(get_temp_c)
    while (( t >= THERMAL_LIMIT_C )); do
        echo "  cooling: ${t}C >= ${THERMAL_LIMIT_C}C ..."; sleep "$THERMAL_WAIT_S"; t=$(get_temp_c)
    done
    echo "  start temp ${t}C (limit <${THERMAL_LIMIT_C}C)"
}

[[ -x "$BIN" ]] || { echo "ERROR: missing $BIN — build first (cmake --build build -j4)"; exit 1; }
# guard: this must be the Pi 5 build (the binary stamps the device into the CSV name)
mkdir -p "$OUT"; cd "$OUT"

for spec in "${WORK[@]}"; do
    pkt="${spec%%:*}"; need="${spec##*:}"; got=0; attempts=0; maxatt=$(( need * 3 + 6 ))
    echo "=== sat_${pkt}: need ${need} good run(s) ==="
    while (( got < need )); do
        (( ++attempts ))
        if (( attempts > maxatt )); then
            echo "  WARNING: ${attempts} attempts, only ${got}/${need} good for sat_${pkt}."
            echo "  Runs keep truncating even when cool — likely a hardware/cooling fault or a"
            echo "  repeatable crash at kem1024 + ${pkt}B. Stop and investigate; do not brute-force."
            break
        fi
        cool
        "$BIN" "$DURATION" 0 "$pkt" || echo "  (binary returned non-zero)"
        f=$(ls -t results_Ascon-PRNG-XOR_kem1024_pi5_*.csv 2>/dev/null | head -1)
        lines=$(wc -l < "$f" 2>/dev/null || echo 0)
        if [[ -n "$f" && "$lines" -ge "$MIN_LINES" ]]; then
            got=$(( got + 1 )); echo "  ok (${got}/${need})  ${f##*/}  [${lines} rows]"
        else
            echo "  TRUNCATED (${lines} rows) -> ${f##*/} ; discarding and retrying"
            [[ -n "$f" ]] && rm -f "$f"
        fi
    done
    echo ""
done

echo "Done. New good runs are in: $OUT"
echo "Next:"
echo "  1. Confirm each Pi-5 device tag is 'pi5' (it is, if this was the Pi 5 build)."
echo "  2. Copy results_bd_fix/*.csv into your Desktop\\Data folder."
echo "  3. Re-run dedup_runs.py --results ...\\Data --apply  (trims any cell back to 30)."
echo "  4. Re-run the gate; sat_32768 and sat_65536 should now read 30/30."
