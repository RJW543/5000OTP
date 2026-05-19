#!/bin/bash
while true; do
    TEMP=$(cat /sys/class/thermal/thermal_zone0/temp)
    if [ "$TEMP" -gt 80000 ]; then
        echo "[$(date)] WARNING: CPU Temperature is ${TEMP}"
    fi
    sleep 2
done