#!/usr/bin/env bash
# diag_pi0_ascon_clock.sh  -- run on the Pi ZERO 2 W.
#
# Explains why Ascon's sat_65536 throughput (~100 Mbps) is only about half what
# its per-byte time predicts (~219 Mbps), while AES/ChaCha/SNOW-Vi saturate as
# expected. Temperatures were fine (~68 C), so plain thermal throttling is ruled
# out -- but the Pi Zero 2 W also caps its clock on UNDER-VOLTAGE, which no
# temperature reading shows and which the heaviest per-byte cipher (Ascon) would
# trigger first under sustained load. This logs the ARM clock, temperature and
# the vcgencmd throttle flags every 0.5 s during:
#     (1) a 64 KB saturation run   (sustained, heavy)
#     (2) a 64 KB rate-controlled run (bursty, light)
# If the sat clock sits well below the video clock, or a throttle flag appears,
# you have the mechanism and a sentence for the write-up.
#
# vcgencmd get_throttled bits:  0=under-voltage now  1=freq-capped now
#   2=throttled now  16=under-voltage occurred  17=cap occurred  18=throttle occurred
#
# Usage:   ./diag_pi0_ascon_clock.sh

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/build/system_d_kem768"
OUT="$SCRIPT_DIR/diag_pi0"
DURATION=30
[[ -x "$BIN" ]] || { echo "ERROR: missing $BIN (build the PI0 tree first)"; exit 1; }
command -v vcgencmd >/dev/null || { echo "ERROR: vcgencmd not found"; exit 1; }
mkdir -p "$OUT"

run_and_log() {  # $1 label   $2 rate   $3 pkt
    local label="$1" rate="$2" pkt="$3" f="$OUT/clock_${1}.csv"
    echo "epoch,arm_hz,temp_c,throttled" > "$f"
    echo "-> ${label}: rate=${rate} pkt=${pkt} for ${DURATION}s"
    ( cd "$OUT" && "$BIN" "$DURATION" "$rate" "$pkt" ) & local pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        printf "%s,%s,%s,%s\n" \
            "$(date +%s.%N)" \
            "$(vcgencmd measure_clock arm | cut -d= -f2)" \
            "$(( $(cat /sys/class/thermal/thermal_zone0/temp)/1000 ))" \
            "$(vcgencmd get_throttled | cut -d= -f2)" >> "$f"
        sleep 0.5
    done
    wait "$pid" 2>/dev/null || true
    local med flags
    med=$(awk -F, 'NR>1{print $2}' "$f" | sort -n | awk '{a[NR]=$1} END{if(NR)printf "%d", a[int((NR+1)/2)]/1000000}')
    flags=$(awk -F, 'NR>1{print $4}' "$f" | sort -u | tr '\n' ' ')
    echo "   median ARM clock: ${med} MHz   throttle flags seen: ${flags}"
}

run_and_log sat65536   0    65536
run_and_log video65536 2.65 65536

echo ""
echo "Read it like this:"
echo "  * sat clock ~= video clock, flags all 0x0   -> not DVFS; the gap is real"
echo "    algorithmic cost at sustained rate (report the two regimes separately)."
echo "  * sat clock << video clock, or a non-0x0 flag -> the core is being capped"
echo "    (bit 0/16 = under-voltage: try a better PSU/cable; bit 2/18 = thermal)."
echo "Per-run logs: $OUT/clock_sat65536.csv , $OUT/clock_video65536.csv"
