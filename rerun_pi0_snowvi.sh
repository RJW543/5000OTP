#!/usr/bin/env bash
# rerun_pi0_snowvi.sh  -- run on the Pi ZERO 2 W only.
#
# Re-collects System B (SNOW-Vi-GCM) on the Pi Zero for the large-packet
# workloads, which the synthetic campaign captured with the pre-acceleration
# table GHASH and are therefore ~2x too slow. The real campaign (current,
# accelerated build) is the correct reference; this brings the synthetic Zero
# SNOW-Vi data onto the same build. Pi 5 (PMULL) and telemetry (512 B) already
# agree, so they are NOT re-run here.
#
# Workloads: the ten rate-controlled video points (16384/32768/65536 B) plus the
# three large saturation sizes. Both KEM levels, 30 repeats. 13 x 2 x 30 = 780
# runs, roughly 15 h on the Zero. Each run is validated (free of corruption,
# full duration, lands in the intended cell); saturation runs print sustained
# throughput. dedup (newest-30) then replaces the stale runs.
#
# REBUILD FIRST so the accelerated GHASH is compiled in (same build as the real
# campaign):  cmake -S . -B build -DDEVICE=PI0 && cmake --build build -j4
#
# Output -> results_snowvi_pi0/. Copy into Data, then dedup + gate + re-analyse
# (and re-run patch_rss.py + the equivalence).
#
# Usage:   nohup ./rerun_pi0_snowvi.sh > snowvi_pi0.log 2>&1 &

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATE="$SCRIPT_DIR/validate_run.py"
OUT="$SCRIPT_DIR/results_snowvi_pi0"
DURATION=70
THERMAL_LIMIT_C="${THERMAL_LIMIT_C:-70}"
THERMAL_WAIT_S=30
RUNS="${RUNS:-30}"
read -r -a KEMS <<< "${KEMS:-768 1024}"

# name:rate_mbps:packet_bytes   (rate 0 == saturation). Telemetry and sat_512
# are omitted: they agree between builds. Override the set with WORKSET if needed.
WORK=(
  "video_low_10fps:0.62:16384"   "video_mean_30fps:1.85:16384"
  "video_p95_30fps:2.65:16384"   "video_stress_max:2.69:16384"
  "video_mean_2frame:1.85:32768" "video_p95_2frame:2.65:32768" "video_stress_2frame:2.69:32768"
  "video_mean_4frame:1.85:65536" "video_p95_4frame:2.65:65536" "video_stress_4frame:2.69:65536"
  "sat_16384:0:16384" "sat_32768:0:32768" "sat_65536:0:65536"
)

get_temp_c() { local r; r=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0); echo $((r/1000)); }
cool() { local t; t=$(get_temp_c); while (( t >= THERMAL_LIMIT_C )); do echo "    cooling ${t}C"; sleep "$THERMAL_WAIT_S"; t=$(get_temp_c); done; }
sustained_mbps() {
    python3 - "$1" <<'PY'
import sys, csv
WARM=10e9; ts=[]; by=[]
for r in csv.reader(open(sys.argv[1])):
    if len(r)<3 or r[1] in ("-1","packet_id"): continue
    try: t,b=int(r[0]),int(r[2])
    except ValueError: continue
    ts.append(t); by.append(b)
if len(ts)<2: print("NA"); sys.exit()
t0=ts[0]; k=[(t,b) for t,b in zip(ts,by) if t-t0>=WARM]
if len(k)<2: print("NA"); sys.exit()
print("%.0f"%(sum(b for _,b in k)*8/((k[-1][0]-k[0][0])/1e9)/1e6))
PY
}

[[ -f "$VALIDATE" ]] || { echo "ERROR: missing $VALIDATE"; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 not found"; exit 1; }
for k in "${KEMS[@]}"; do
    [[ -x "$SCRIPT_DIR/build/system_b_kem${k}" ]] || { echo "ERROR: missing build/system_b_kem${k} (rebuild the PI0 tree first)"; exit 1; }
done
# guard: System B must actually be SNOW-Vi
grep -q '"SNOW-Vi-GCM"' "$SCRIPT_DIR/systems/system_b/cipher.hpp" || { echo "ERROR: System B is not wired to SNOW-Vi"; exit 1; }
mkdir -p "$OUT"; cd "$OUT"

total=0
for k in "${KEMS[@]}"; do
    BIN="$SCRIPT_DIR/build/system_b_kem${k}"
    GLOB="results_SNOW-Vi-GCM_kem${k}_pi0_*.csv"
    for spec in "${WORK[@]}"; do
        IFS=: read -r name rate pkt <<< "$spec"
        got=0; att=0; maxatt=$(( RUNS * 3 + 6 ))
        echo "=== kem${k} ${name} (${pkt}B rate ${rate}): need ${RUNS} ==="
        while (( got < RUNS )); do
            (( ++att ))
            if (( att > maxatt )); then echo "  WARNING: ${att} attempts, only ${got}/${RUNS} for kem${k} ${name}; stopping cell."; break; fi
            cool
            before=$(ls -t $GLOB 2>/dev/null | head -1)
            "$BIN" "$DURATION" "$rate" "$pkt" || echo "  (binary non-zero)"
            after=$(ls -t $GLOB 2>/dev/null | head -1)
            if [[ -z "$after" || "$after" == "$before" ]]; then echo "  no new pi0 CSV (is this the PI0 build?)"; continue; fi
            if python3 "$VALIDATE" "$after" "$name" "$DURATION" >/dev/null; then
                (( ++got, ++total ))
                if [[ "$rate" == "0" ]]; then echo "  kept ${got}/${RUNS}: $(sustained_mbps "$after") Mbps"; else echo "  kept ${got}/${RUNS}"; fi
            else
                rm -f "$after"
            fi
        done
        echo ""
    done
done
echo "Done. ${total} good run(s) in: $OUT"
echo "Next: copy into Data, dedup --apply, gate, re-run analyse_synthetic + patch_rss + equivalence."
