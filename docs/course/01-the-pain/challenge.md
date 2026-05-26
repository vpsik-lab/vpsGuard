# Challenge: The Pain

**Difficulty levels — pick your path.**

---

## ⭐ Level 1: Observe the Attacks

Check your own VPS (or any Linux machine with SSH logs):

```bash
journalctl -u ssh --since "24 hours ago" | grep "Failed password" | wc -l
```

**Task:** Count how many failed SSH attempts your server received in the last 24 hours.

**Hint:** `journalctl` is the systemd journal viewer. `-u ssh` filters to SSH unit.

---

## ⭐⭐ Level 2: Analyze the Attackers

Extract the top 10 attacking IPs:

```bash
journalctl -u ssh --since "24 hours ago" | grep "Failed password" | grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -rn | head -10
```

**Task:** Pick the top IP and look it up:
- `curl https://ipinfo.io/<IP>/json`
- Is it a datacenter? Residential? Known VPN?

**Hint:** Most SSH bots come from datacenters and cloud providers.

---

## ⭐⭐⭐ Level 3: Trace the Botnet

For the top 3 attacking IPs:

1. Get their ASN: `curl https://ipinfo.io/<IP>/json | grep org`
2. Do they share the same ASN? (same hosting provider?)
3. Check if they're reported on AbuseIPDB: `curl https://api.abuseipdb.com/api/v2/check?ipAddress=<IP>` (free API key required)
4. Write a small shell script that reports all unique attackers from your logs to a CSV file

**Hint:** Attackers from the same /24 subnet are likely part of the same botnet scan.

---

## Solution

Don't peek before you try!

<details>
<summary>Click for Level 3 solution approach</summary>

```bash
#!/bin/bash
# attack-report.sh — generate CSV of SSH attackers

LOGFILE="ssh-attackers-$(date +%Y%m%d).csv"
echo "IP,Count,ASN,Country" > "$LOGFILE"

journalctl -u ssh --since "24 hours ago" | \
  grep "Failed password" | \
  grep -oP 'from \K[0-9.]+' | \
  sort | uniq -c | sort -rn | \
  while read count ip; do
    info=$(curl -s "https://ipinfo.io/$ip/json")
    asn=$(echo "$info" | jq -r '.org // "unknown"')
    country=$(echo "$info" | jq -r '.country // "unknown"')
    echo "$ip,$count,$asn,$country" >> "$LOGFILE"
  done

echo "Report written to $LOGFILE"
```

This is exactly the kind of data that a real threat intelligence pipeline uses.
</details>
