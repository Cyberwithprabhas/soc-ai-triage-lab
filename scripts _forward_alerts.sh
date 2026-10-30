#!/bin/sh
# Lab only: sends NEW Suricata alerts to n8n (max 5 unique alerts per run)
LOG=/var/log/suricata/suricata_em153236/alerts.log
STATE=/root/alerts.offset
URL=http://192.168.83.1:5678/webhook/suricata-alert

[ -f "$LOG" ] || exit 0
TOTAL=$(wc -l < "$LOG" | tr -d ' ')

# First run: remember current position, send nothing
if [ ! -f "$STATE" ]; then
  echo "$TOTAL" > "$STATE"
  echo "First run: position saved ($TOTAL lines). Nothing sent."
  exit 0
fi

LAST=$(cat "$STATE")
[ "$TOTAL" -lt "$LAST" ] && LAST=0      # log was rotated
[ "$TOTAL" -eq "$LAST" ] && exit 0      # no new alerts
echo "$TOTAL" > "$STATE"

# Parse: signature|priority|src|dst|dport
tail -n +$((LAST + 1)) "$LOG" \
| sed -nE 's/^[^ ]+ +\[\*\*\] \[[0-9:]+\] (.*) \[\*\*\] (\[Classification: [^]]*\] )?\[Priority: ([0-9]+)\] \{[A-Za-z0-9]+\} ([0-9.]+)(:[0-9]+)? -> ([0-9.]+)(:([0-9]+))?$/\1|\3|\4|\6|\8/p' \
| sort -u | head -n 5 \
| while IFS='|' read -r SIG PRIO SRC DST DPORT; do
    SIG=$(printf '%s' "$SIG" | tr -d '"\\')
    curl -s -m 10 -X POST -H "Content-Type: application/json" \
      -d "{\"signature\":\"$SIG\",\"src\":\"$SRC\",\"dst\":\"$DST\",\"dport\":${DPORT:-0},\"priority\":$PRIO}" \
      "$URL" > /dev/null
    echo "Sent: $SIG $SRC -> $DST:${DPORT:-0}"
  done
