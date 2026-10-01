"""
detector.py  --  your project: detect a ransomware encryption burst in Sysmon
                 events, store incidents in SQLite, and feed the live viewer.

WHERE THIS GOES : C:\\AtomicLab\\  on your Windows VM (the snapshotted one)
HOW TO RUN IT   : open Command Prompt (cmd) or PowerShell, then:
                      cd C:\\AtomicLab
                      python detector.py sysmon_events.csv     <- the attack
                      python detector.py sysmon_baseline.csv   <- the control

WHAT IT LOOKS FOR
    Ransomware does something very distinctive: it rewrites a LOT of files in
    a very short time. Sysmon records each one as Event ID 11 (FileCreate).
    So this script counts FileCreate events in each short time bucket and
    reports a burst - 20 or more in 10 seconds, by default.

    That is a real signature. "Lots of file writes at once" is what mass
    encryption looks like and what ordinary work does NOT look like, which is
    exactly why your negative control (sysmon_baseline.csv) stays clean
    without you having to change a single setting between the two runs.

WHY NOT JUST "EVENTS BETWEEN TWO TIMESTAMPS"
    Because that detects "something happened while I was watching", not
    ransomware - it would flag ordinary activity just as happily. If you are
    asked why your detector is more than a time filter, this is the answer.

WHAT IT WRITES
    incidents.db    SQLite - your incident database (the record of truth)
    findings.json   a small export that index.html reads to draw the screen
"""
import argparse, csv, json, os, sqlite3, sys
from collections import defaultdict
from datetime import datetime

DB_FILE = "incidents.db"
FINDINGS_FILE = "findings.json"      # index.html reads this
TS_FORMAT = "%Y-%m-%d %H:%M:%S"

EVENT_FILE_CREATE = "11"             # Sysmon: a file was created/overwritten
EVENT_PROCESS_CREATE = "1"           # Sysmon: a process started


# --------------------------------------------------------------------------- #
#  storage
# --------------------------------------------------------------------------- #
def db_connect():
    """Open incidents.db and make sure the table exists."""
    con = sqlite3.connect(DB_FILE)
    con.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at  TEXT,
            window_start TEXT,
            event_count  INTEGER,
            severity     TEXT,
            summary      TEXT,
            source_file  TEXT
        )""")
    con.commit()
    return con


def save_finding(con, summary, severity, window_start, event_count, source_file):
    """Record one incident in SQLite. This is your evidence store."""
    con.execute(
        "INSERT INTO findings (detected_at, window_start, event_count, severity,"
        " summary, source_file) VALUES (?,?,?,?,?,?)",
        (datetime.now().strftime(TS_FORMAT), window_start, event_count,
         severity, summary, source_file))
    con.commit()


def export_findings_json(con):
    """Write the latest findings to findings.json for the browser viewer.

    The browser cannot open a SQLite file, so the detector exports what the
    page needs. SQLite stays the record of truth; this is just the view feed.
    """
    rows = con.execute(
        "SELECT detected_at, summary, severity FROM findings"
        " ORDER BY id DESC LIMIT 50").fetchall()
    data = [{"time": r[0][11:19] or r[0], "summary": r[1], "severity": r[2]}
            for r in rows]
    with open(FINDINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(list(reversed(data)), f, indent=2)
    return len(data)


# --------------------------------------------------------------------------- #
#  reading the Sysmon export
# --------------------------------------------------------------------------- #
def load_events(path):
    """Read the CSV written by export_sysmon.ps1 into a list of events."""
    events, bad_timestamps = [], 0
    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "TimeCreated" not in reader.fieldnames:
            print("ERROR: '%s' does not look like a Sysmon export." % path)
            print("       Expected columns: TimeCreated, Id, Message")
            print("       Found: %s" % (reader.fieldnames,))
            print("       Re-create it with:  powershell -ExecutionPolicy Bypass"
                  " -File export_sysmon.ps1")
            sys.exit(1)
        for row in reader:
            raw = (row.get("TimeCreated") or "").strip()
            try:
                ts = datetime.strptime(raw[:19], TS_FORMAT)
            except ValueError:
                bad_timestamps += 1
                continue
            events.append({"ts": ts,
                           "id": (row.get("Id") or "").strip(),
                           "message": (row.get("Message") or "").strip()})

    if bad_timestamps and not events:
        print("ERROR: none of the timestamps in '%s' could be read." % path)
        print("       They must look like 2026-09-30 10:04:22")
        print("       This happens when the CSV was made with a plain")
        print("       Export-Csv, which writes your local date format.")
        print("       Fix it by re-exporting with export_sysmon.ps1, which")
        print("       formats the timestamp explicitly.")
        sys.exit(1)
    if bad_timestamps:
        print("note: skipped %d row(s) with unreadable timestamps" % bad_timestamps)

    events.sort(key=lambda e: e["ts"])
    return events


# --------------------------------------------------------------------------- #
#  the detection itself
# --------------------------------------------------------------------------- #
def find_bursts(events, window_seconds, threshold):
    """Group FileCreate events into fixed time buckets and return the buckets
    that contain at least `threshold` of them. Each one is a finding."""
    buckets = defaultdict(list)
    for e in events:
        if e["id"] != EVENT_FILE_CREATE:
            continue
        # integer-divide the timestamp into fixed buckets
        key = int(e["ts"].timestamp()) // window_seconds
        buckets[key].append(e)

    bursts = []
    for key in sorted(buckets):
        hits = buckets[key]
        if len(hits) >= threshold:
            bursts.append({"start": hits[0]["ts"], "count": len(hits),
                           "samples": [h["message"][:90] for h in hits[:3]]})
    return bursts


def processes_near(events, when, seconds=30):
    """Any process that started just before a burst - useful context for your
    report, because it is usually the thing doing the encrypting."""
    out = []
    for e in events:
        if e["id"] != EVENT_PROCESS_CREATE:
            continue
        delta = (when - e["ts"]).total_seconds()
        if 0 <= delta <= seconds:
            out.append(e["message"][:90])
    return out[:3]


def severity_for(count, threshold):
    if count >= threshold * 5:
        return "Critical"
    if count >= threshold * 2:
        return "High"
    return "Medium"


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="Detect a ransomware file-encryption burst in a Sysmon CSV export.")
    ap.add_argument("csvfile", help="sysmon_events.csv or sysmon_baseline.csv")
    ap.add_argument("--threshold", type=int, default=20,
                    help="FileCreate events in one window before it counts as a burst (default 20)")
    ap.add_argument("--window", type=int, default=10,
                    help="size of the time window in seconds (default 10)")
    ap.add_argument("--quiet", action="store_true", help="only print findings")
    args = ap.parse_args()

    if not os.path.exists(args.csvfile):
        print("ERROR: cannot find '%s'." % args.csvfile)
        print("       You are in: %s" % os.getcwd())
        print("       Run 'cd C:\\AtomicLab' first, then 'dir' to check it is there.")
        print("       If it does not exist yet, create it with:")
        print("         powershell -ExecutionPolicy Bypass -File export_sysmon.ps1")
        return 1

    events = load_events(args.csvfile)
    file_creates = sum(1 for e in events if e["id"] == EVENT_FILE_CREATE)

    if not args.quiet:
        print("Reading %s" % args.csvfile)
        print("  %d Sysmon events, of which %d are FileCreate (ID 11)"
              % (len(events), file_creates))
        print("  looking for %d or more FileCreate events within %d seconds"
              % (args.threshold, args.window))
        print("")

    bursts = find_bursts(events, args.window, args.threshold)
    con = db_connect()

    if not bursts:
        print("CLEAN: no encryption burst found in %s" % args.csvfile)
        if not args.quiet:
            print("       (for your baseline export, this is the CORRECT result -")
            print("        it is the negative control that proves the detector works)")
        con.close()
        return 0

    for b in bursts:
        sev = severity_for(b["count"], args.threshold)
        when = b["start"].strftime(TS_FORMAT)
        summary = ("Ransomware encryption burst: %d file writes in %ds from %s"
                   % (b["count"], args.window, when))
        print("CONFIRMED [%s]: %s" % (sev, summary))
        for s in b["samples"]:
            print("    file event: %s" % s)
        for pr in processes_near(events, b["start"]):
            print("    process just before: %s" % pr)
        save_finding(con, summary, sev, when, b["count"], args.csvfile)

    n = export_findings_json(con)
    con.close()
    print("")
    print("%d incident(s) stored in %s and exported to %s"
          % (len(bursts), DB_FILE, FINDINGS_FILE))
    print("Refresh http://localhost:8000/index.html to see them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
