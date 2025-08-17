#!/usr/bin/env bash
# Simple Suricata response: log suspicious IPs to a file (works in WSL2)

LOG=/var/log/suricata/eve.json
BLACKLIST=/var/log/suricata/blacklisted_ips.txt

# Ensure blacklist file exists
sudo touch "$BLACKLIST"

# Follow Suricata alerts in real-time
sudo tail -F -n0 "$LOG" | jq -r 'select(.event_type=="alert") | .src_ip' | while read -r IP; do
  [[ -z "$IP" ]] && continue
  # Avoid duplicates
  if ! grep -q "$IP" "$BLACKLIST"; then
    echo "$(date +"%F %T") - $IP" | tee -a "$BLACKLIST"
    echo "Logged suspicious IP: $IP"
  fi
done
