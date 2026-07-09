# Log-Analyzer_Mini-SIEM-Project
A Python tool that reads raw authentication logs and hunts for — failed logins, brute-force bursts, and raises alerts.
# This was a beginner project I worked on to help with understanding Log Analyzing and make a Mini-SIEM

# Mini-SIEM — Auth Log Brute-Force Detector

A command-line log analyzer that parses SSH authentication logs
and detects brute-force login attempts, mapped to MITRE ATT&CK
**T1110**.

# What it does
- Ingests raw `auth.log` files line by line
- Parses each entry with regex to extract user + source IP
- Counts failed logins per IP and alerts over a threshold
- Writes a timestamped report of findings

# Usage
```
python3 analyze.py auth.log --threshold 3\

```

# Example output
```
[ALERT] T1110 Brute Force | IP=203.0.113.7 | failed_attempts=4
[ALERT] T1110 Brute Force | IP=198.51.100.22 | failed_attempts=3

[+] Wrote 2 alert(s) to report.txt

```

# What I learned
- Regex-based log parsing and field extraction
- Threshold tuning: the false-positive / false-negative tradeoff
- Mapping detections to the MITRE ATT&CK framework

# Next steps
- Detect logins at unusual hours
- Output JSON for ingestion into a real SIEM
