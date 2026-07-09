def read_logs(filepath):
    """Open a log file and yield one line at a time."""
    with open(filepath, 'r') as f:
        for line in f:
            yield line.strip()


if __name__ == "__main__":
    for line in read_logs("auth.log"):
        print(line)
        
        
import re

FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)"
)

def parse_line(line):
    """Return (user, ip) if the line is a failed login, else None."""
    match = FAILED_PATTERN.search(line)
    if match:
        return match.group(1), match.group(2)
    return None


from collections import Counter

def count_failures(filepath):
    """Tally failed logins per source IP."""
    ip_counts = Counter()
    for line in read_logs(filepath):
        result = parse_line(line)
        if result:
            user, ip = result
            ip_counts[ip] += 1
    return ip_counts
print(count_failures("auth.log"))


def detect_brute_force(ip_counts, threshold=3):
    """Return a list of alerts for IPs over the threshold."""
    alerts = []
    for ip, count in ip_counts.items():
        if count >= threshold:
            alerts.append({
                "technique": "T1110 Brute Force",
                "ip": ip,
                "count": count,
            }) 
    return alerts


def write_report(alerts, outfile="report.txt"):
    """Print alerts and save them to a report file"""
    if not alerts:
        print("[+] No brute-force acticity detected.")
        return
    
    with open(outfile, "w") as f:
              for a in alerts:
                line = (
                    f"[ALERT] {a['technique']} | "
                    f"IP={a['ip']} | failed_attempts={a['count']}"
                )
                print(line)           # to screen
                f.write(line + "\n")      # to file

    print(f"\n[+] Wrote {len(alerts)} alert(s) to {outfile}")


import argparse

def main():
    parser = argparse.ArgumentParser(
        description="Mini-SIEM: detect brute-force attacks in auth logs"
    )
    parser.add_argument("logfile", help="path to the log file")
    parser.add_argument(
        "--threshold", type=int, default=5,
        help="failed attempts before alerting (default: 5)"
    )
    args = parser.parse_args()

    counts = count_failures(args.logfile)
    alerts = detect_brute_force(counts, args.threshold)
    write_report(alerts)


if __name__ == "__main__":
    main()
