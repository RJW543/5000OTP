#!/usr/bin/env bash
# rerun_pi5_ascon_short.sh  -- run on the Pi 5 only.
#
# Tops up the one System D (Ascon) kem1024 saturation cell still short after the
# first partial top-up:
#
#     sat_512   512 B saturation   need 1   (cell is at 29/30)
#
# Each new CSV must be free of binary corruption / torn rows, span the full run,
# and classify as sat_512; rejected runs are deleted and retried. It collects
# exactly `need` good runs and then stops -- no more.
#
# The default need below is the current deficit. To reuse this later against a
# different shortfall, override per cell WITHOUT editing the file:
#     ./rerun_pi5_ascon_short.sh sat_512=2
#
# Output -> results_bd_fix5/. Copy into Data, then dedup + re-gate.
#
# Usage:   ./rerun_pi5_ascon_short.sh
#          THERMAL_LIMIT_C=60 ./rerun_pi5_ascon_short.sh sat_512=1

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/build/system_d_kem1024"
VALIDATE="$SCRIPT_DIR/validate_run.py"
OUT="$SCRIPT_DIR/results_bd_fix5"
DURATION=70
THERMAL_LIMIT_C="${THERMAL_LIMIT_C:-55}"
THERMAL_WAIT_S=30

# name:rate_mbps:packet_bytes:runs_needed   (rate 0 == saturation)
# Default = current deficit; override any cell with a  name=N  argument.
WORK=( "sat_512:0:512:1" )
GLOB="results_Ascon-PRNG-XOR_kem1024_pi5_*.csv"

# apply optional  name=N  overrides from the command line
for arg in "$@"; do
    case "$arg" in
        *=*) _nm="${arg%%=*}"; _val="${arg##*=}"
             for _i in "${!WORK[@]}"; do
                 IFS=: read -r _n _r _p _need <<< "${WORK[$_i]}"
                 [[ "$_n" == "$_nm" ]] && WORK[$_i]="${_n}:${_r}:${_p}:${_val}"
             done ;;
    esac
done

get_temp_c() { local r; r=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0); echo $((r/1000)); }
cool() {
    local t; t=$(get_temp_c)
    while (( t >= THERMAL_LIMIT_C )); do
        echo "  cooling: ${t}C >= ${THERMAL_LIMIT_C}C ..."; sleep "$THERMAL_WAIT_S"; t=$(get_temp_c)
    done
}

[[ -x "$BIN" ]]      || { echo "ERROR: missing $BIN  (build the Pi 5 tree: cmake -S . -B build -DDEVICE=PI5 && cmake --build build -j4)"; exit 1; }
[[ -f "$VALIDATE" ]] || { echo "ERROR: missing $VALIDATE next to this script"; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 not found on this Pi"; exit 1; }
mkdir -p "$OUT"; cd "$OUT"

total=0
for spec in "${WORK[@]}"; do
    IFS=: read -r name rate pkt need <<< "$spec"
    (( need <= 0 )) && { echo "=== $name: need 0, skipping ==="; echo; continue; }
    got=0; att=0; maxatt=$(( need * 4 + 6 ))
    echo "=== $name  (${pkt} B, rate ${rate}): need ${need} ==="
    while (( got < need )); do
        (( ++att ))
        if (( att > maxatt )); then
            echo "  WARNING: ${att} attempts, only ${got}/${need} good for ${name}."
            echo "  Runs keep failing validation even when cool -- investigate, do not brute-force."; break
        fi
        cool
        before=$(ls -t $GLOB 2>/dev/null | head -1)
        "$BIN" "$DURATION" "$rate" "$pkt" || echo "  (binary returned non-zero)"
        after=$(ls -t $GLOB 2>/dev/null | head -1)
        if [[ -z "$after" || "$after" == "$before" ]]; then
            echo "  no new pi5 CSV appeared -- is this really the PI5 build?"; continue
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
echo "Next: copy $OUT/*.csv into Data, then dedup + re-gate."
