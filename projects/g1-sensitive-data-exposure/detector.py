"""
detector.py  --  your actual project. Reads a log file and reports any case
                 where a secret was sent to someone OUTSIDE this machine.

WHERE THIS GOES : your home folder on the TARGET Ubuntu VM  (~)
                  (the same folder as app_public.py, so it can find the log)
HOW TO RUN IT   : cd ~
                  python3 detector.py evidence.log

THE WHOLE IDEA  : for each log line it checks TWO things and only reports when
                  BOTH are true:
                     1. did the response contain something that looks like a secret?
                     2. was the person asking from an external address?
                  A secret sent to 127.0.0.1 is normal. A secret sent to an
                  outside machine is an exposure. One condition alone is not
                  enough - that is what makes this a detector and not an alarm.

If you are asked ONE hard question in your demo it will be "how do you know
it is not a false positive?" The answer is the negative control: the same
script, the same log format, a local request - and it stays silent.
"""
import sys, re, json, os, datetime

# things that look like a leaked secret. \S+ means "one or more non-space chars"
SECRET_PATTERNS = [r"SECRET=\S+", r"api_key=\S+", r"password=\S+"]

# addresses that mean "this same machine" - requests from these are NOT a leak
LOCAL_IPS = ("127.0.0.1", "::1", "localhost")

FINDINGS_FILE = "findings.json"   # app_public.py's /dashboard reads this


def save_finding(summary, severity="High", ip="", path="", pattern=""):
    """Append one finding to findings.json so the dashboard can display it.

    This lives HERE, in the detector, because the detector is what discovers
    the finding. The Flask app only reads the file. They are two separate
    programs and cannot call each other's functions - they share the file.

    The ip, path and pattern are saved as their own fields rather than only
    inside the sentence, so the dashboard can show them as sortable columns.
    """
    data = []
    if os.path.exists(FINDINGS_FILE):
        with open(FINDINGS_FILE) as f:
            data = json.load(f)
    data.append({"time": datetime.datetime.now().strftime("%H:%M:%S"),
                 "summary": summary,
                 "severity": severity,
                 "ip": ip,
                 "path": path,
                 "pattern": pattern})
    with open(FINDINGS_FILE, "w") as f:
        json.dump(data[-50:], f, indent=2)   # keep the last 50


def check_line(line):
    """Examine one log line. Returns a finding dict, or None if it is fine.

    A log line looks like:
        <timestamp> <ip> <method> <path> <response body>
    split(" ", 4) cuts it into exactly 5 pieces, keeping the whole response
    body as the last piece even if it contains spaces.
    """
    parts = line.strip().split(" ", 4)
    if len(parts) < 5:
        return None                      # blank or malformed line - skip it
    timestamp, ip, method, path, body = parts

    matched = next((pat for pat in SECRET_PATTERNS if re.search(pat, body)), None)
    is_external = ip not in LOCAL_IPS

    if matched and is_external:          # BOTH conditions - this is the point
        return {"ip": ip, "path": path, "pattern": matched, "time": timestamp}
    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector.py <logfile>")
        print("Example: python3 detector.py evidence.log")
        return

    logfile = sys.argv[1]
    if not os.path.exists(logfile):
        print(f"ERROR: cannot find '{logfile}' in this folder.")
        print(f"       You are in: {os.getcwd()}")
        print("       Run 'cd ~' first, then 'ls' to check the file is there.")
        return

    findings = []
    with open(logfile) as f:
        for line in f:
            result = check_line(line)
            if result:
                findings.append(result)

    if findings:
        for r in findings:
            msg = (f"{r['ip']} reached {r['path']} and received a secret "
                   f"matching {r['pattern']}")
            print("EXPOSURE:", msg)
            # <-- this is what feeds /dashboard
            save_finding(msg, "High", r["ip"], r["path"], r["pattern"])
        print(f"\n{len(findings)} finding(s) written to {FINDINGS_FILE} - "
              f"refresh http://localhost:5000/dashboard to see them.")
    else:
        print("No external exposure found in", logfile)


if __name__ == "__main__":
    main()
