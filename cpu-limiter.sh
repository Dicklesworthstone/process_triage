#!/usr/bin/env bash
# Auto-limit CPU for pt-core processes
# Run with: nohup ./cpu-limiter.sh &

set -uo pipefail

LIMIT=50  # Max CPU % per process

for cmd in cpulimit pgrep ps; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        printf 'Error: required command not found: %s\n' "$cmd" >&2
        exit 1
    fi
done

while true; do
    # Use [p]t-core trick to avoid pgrep matching its own command line
    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue
        # Check if already being limited
        if ! pgrep -f "cpulimit -p ${pid}" > /dev/null 2>&1; then
            cpu=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ')
            if [[ -n "$cpu" ]] && awk -v c="$cpu" 'BEGIN { exit !(c > 80) }'; then
                printf '[%s] Limiting PID %s (CPU: %s%%)\n' "$(date)" "$pid" "$cpu"
                cpulimit -p "$pid" -l "$LIMIT" -b 2>/dev/null || true
            fi
        fi
    done < <(pgrep -x pt-core 2>/dev/null || true)
    sleep 5
done
