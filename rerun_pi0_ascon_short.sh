#!/usr/bin/env bash
# rerun_pi0_ascon_short.sh  -- run on the Pi ZERO 2 W only.
#
# Tops up the four System D (Ascon) kem768 rate-controlled cells that came out
# short (26-29 of 30) after write corruption during the campaign:
#
#     video_p95_30fps   16384 B @ 2.65 Mbps   need 2
#     video_stress_max  16384 B @ 2.69 Mbps   need 4
#     video_mean_2frame 32768 B @ 1.85 Mbps   need 4
#     video_p95_2frame  32768 B @ 2.65 Mbps   need 1
#
# Every new CSV is checked by validate_run.py before it counts: it must be free
# of the binary corruption / torn rows that caused the losses, span the full
# run, AND classify into the exact intended cell. That last check matters here
# because on 16384 B the 2.65 and 2.69 Mbps targets are only 0.04 apart, so a
# jittery run could otherwise be filed in the neighbouring cell. Rejected runs
# are deleted and retried.
#
# Output -> results_bd_fix0/. Copy into your Data folder AFTER you have run
# clean_corrupt_csvs.py on it (so dedup keeps good files, not corrupt ones).
#
# Usage:   ./rerun_pi0_ascon_short.sh
#          THERMAL_LIMIT_C=65 ./rerun_pi0_ascon_short.sh

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/build/system_d_kem768"
VALIDATE="$SCRIPT_DIR/validate_run.py"
OUT="$SCRIPT_DIR/results_bd_fix0"
DURATION=70
THERMAL_LIMIT_C="${THERMAL_LIMIT_C:-70}"
THERMAL_WAIT_S=30

# name:rate_mbps:packet_bytes:runs_needed
WORK=(
  "video_p95_30fps:2.65:16384:2"
  "video_stress_max:2.69:16384:4"
  "video_mean_2frame:1.85:32768:4"
  "video_p95_2frame:2.65:32768:1"
)
GLOB="results_Ascon-PRNG-XOR_kem768_pi0_*.csv"

get_temp_c() { local r; r=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0); echo $((r/1000)); }
cool() {
    local t; t=$(get_temp_c)
    while (( t >= THERMAL_LIMIT_C )); do
        echo "  cooling: ${t}C >= ${THERMAL_LIMIT_C}C ..."; sleep "$THERMAL_WAIT_S"; t=$(get_temp_c)
    done
}

[[ -x "$BIN" ]]      || { echo "ERROR: missing $BIN  (build the Pi Zero tree: cmake -S . -B build -DDEVICE=PI0 && cmake --build build -j4)"; exit 1; }
[[ -f "$VALIDATE" ]] || { echo "ERROR: missing $VALIDATE next to this script"; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 not found on this Pi"; exit 1; }
mkdir -p "$OUT"; cd "$OUT"

total=0
for spec in "${WORK[@]}"; do
    IFS=: read -r name rate pkt need <<< "$spec"
    got=0; att=0; maxatt=$(( need * 4 + 6 ))
    echo "=== $name  (${pkt} B @ ${rate} Mbps): need ${need} ==="
    while (( got < need )); do
        (( ++att ))
        if (( att > maxatt )); then
            echo "  WARNING: ${att} attempts, only ${got}/${need} good for ${name}."
            echo "  Runs keep failing validation even when cool -- investigate (rate limiter /"
            echo "  SD card / power), do not brute-force."; break
        fi
        cool
        before=$(ls -t $GLOB 2>/dev/null | head -1)
        "$BIN" "$DURATION" "$rate" "$pkt" || echo "  (binary returned non-zero)"
        after=$(ls -t $GLOB 2>/dev/null | head -1)
        if [[ -z "$after" || "$after" == "$before" ]]; then
            echo "  no new pi0 CSV appeared -- is this really the PI0 build?"; continue
        fi
        if python3 "$VALIDATE" "$after" "$name" "$DURATION"; then
            (( ++got, ++total )); echo "  kept ${got}/${need}: ${after##*/}"
        else
            rm -f "$after"
        fi
    done
    echo ""
done

echo "Done. ${total} good run(s) in: $OUT"
echo "Next:"
echo "  1. clean_corrupt_csvs.py --results <Data> --apply     (quarantine the corrupt originals)"
echo "  2. copy $OUT/*.csv into your Data folder"
echo "  3. dedup_runs.py --results <Data> --apply             (trims any cell back to newest 30)"
echo "  4. re-run the gate; these four cells should read 30/30"
