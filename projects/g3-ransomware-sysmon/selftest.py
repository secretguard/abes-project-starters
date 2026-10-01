"""
selftest.py  --  RUN THIS FIRST, before you touch Sysmon or the VM's event log.

HOW TO RUN IT : put all the project files in one folder, then:
                    cd C:\\AtomicLab
                    python selftest.py

WHAT IT DOES  : builds two fake Sysmon exports of its own - one that looks
                like a ransomware encryption burst, one that looks like
                ordinary work - and checks your detector gets both right.
                It needs no Sysmon, no event log, no attack, no network.

WHY IT MATTERS: if this says ALL TESTS PASSED, your CODE is correct. Any
                problem after this point is your SETUP - Sysmon not running,
                PowerShell vs cmd, wrong folder, empty export - and never the
                code. That alone will save you hours of guessing.

It runs in a temporary folder, so it will not touch your real incidents.db
or findings.json.
"""
import os, sys, json, csv, shutil, sqlite3, tempfile, subprocess
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
TS = "%Y-%m-%d %H:%M:%S"
passed, failed = [], []


def check(name, condition, hint=""):
    if condition:
        passed.append(name)
        print("  PASS  " + name)
    else:
        failed.append((name, hint))
        print("  FAIL  " + name + (("\n        -> " + hint) if hint else ""))


def write_csv(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["TimeCreated", "Id", "Message"])
        w.writerows(rows)


print("=" * 68)
print("  SELF TEST - checking your ransomware detector")
print("=" * 68)

# ------------------------------------------------------------- files present
print("\n[1] Are all the files in this folder?")
print("    folder:", HERE)
need = ["detector.py", "index.html", "export_sysmon.ps1"]
for fn in need:
    check(fn + " is here", os.path.exists(os.path.join(HERE, fn)),
          "copy " + fn + " into this folder, then run selftest.py again")
if failed:
    print("\nStopping - put the missing files in this folder first.")
    sys.exit(1)

# ---------------------------------------------------------------- is it valid
print("\n[2] Is the Python valid (no typing mistakes)?")
import py_compile
try:
    py_compile.compile(os.path.join(HERE, "detector.py"), doraise=True)
    check("detector.py has no syntax errors", True)
except py_compile.PyCompileError as e:
    check("detector.py has no syntax errors", False,
          str(e).strip().splitlines()[-1])
    sys.exit(1)

# ------------------------------------------------- work in a temporary folder
work = tempfile.mkdtemp(prefix="abes_selftest_")
shutil.copy(os.path.join(HERE, "detector.py"), work)
cwd = os.getcwd()


def run_detector(*args):
    r = subprocess.run([sys.executable, "detector.py"] + list(args),
                       cwd=work, capture_output=True, text=True)
    return r.stdout, r.stderr, r.returncode


try:
    os.chdir(work)

    # ------------------------------------------------ build the two test files
    # align to a 10-second boundary so the burst lands in exactly ONE bucket
    # regardless of clock alignment - otherwise this test is flaky
    _raw = datetime(2026, 9, 30, 10, 0, 0)
    base = datetime.fromtimestamp((int(_raw.timestamp()) // 10) * 10)

    # (a) ransomware: 60 file writes inside 5 seconds, plus the process that did it
    attack = [((base - timedelta(seconds=4)).strftime(TS), "1",
               "Process Create: Image: C:\\AtomicLab\\encrypt_test.exe")]
    for i in range(60):
        attack.append(((base + timedelta(seconds=i % 5)).strftime(TS), "11",
                       "File created: C:\\Users\\Lab\\Documents\\file%03d.txt.locked" % i))
    write_csv("sysmon_events.csv", attack)

    # (c) a much bigger burst, to check the severity escalates to Critical
    huge = [((base + timedelta(seconds=i % 5)).strftime(TS), "11",
             "File created: C:\\Users\\Lab\\Documents\\big%03d.txt.locked" % i)
            for i in range(150)]
    write_csv("sysmon_huge.csv", huge)

    # (b) ordinary work: a handful of file writes spread over ten minutes
    normal = []
    for i in range(8):
        normal.append(((base + timedelta(minutes=i)).strftime(TS), "11",
                       "File created: C:\\Users\\Lab\\Documents\\report%d.docx" % i))
    normal.append((base.strftime(TS), "1", "Process Create: Image: WINWORD.EXE"))
    write_csv("sysmon_baseline.csv", normal)

    print("\n[3] Does it CONFIRM a ransomware burst? (60 file writes in 5s)")
    out, err, rc = run_detector("sysmon_events.csv")
    check("the detector ran without crashing", rc == 0 and not err.strip(),
          err.strip()[-300:] if err.strip() else "")
    check("it reports CONFIRMED", "CONFIRMED" in out,
          "60 FileCreate events in 5 seconds should be well over the threshold")
    check("it counts the file writes", "60 file writes" in out)
    check("the severity is High", "[High]" in out,
          "60 events is 3x the threshold of 20, which is High (5x would be Critical)")
    check("it names the process that caused it", "encrypt_test.exe" in out,
          "ProcessCreate events just before the burst are useful report context")
    check("it found exactly ONE burst", out.count("CONFIRMED") == 1,
          "the whole burst sits in one time window, so it is one finding")

    outH, errH, rcH = run_detector("sysmon_huge.csv", "--quiet")
    check("a much bigger burst escalates to Critical", "[Critical]" in outH,
          "150 events is over 5x the threshold")

    print("\n[4] Does it stay CLEAN on ordinary activity? (the negative control)")
    out2, err2, rc2 = run_detector("sysmon_baseline.csv")
    check("it ran without crashing", rc2 == 0 and not err2.strip())
    check("it reports CLEAN", "CLEAN" in out2,
          "8 file writes spread over 10 minutes is not a burst")
    check("it does NOT report CONFIRMED", "CONFIRMED" not in out2,
          "a false positive here would sink your project")

    print("\n[5] Did it store the incident properly?")
    check("incidents.db was created", os.path.exists("incidents.db"),
          "SQLite is your evidence store")
    if os.path.exists("incidents.db"):
        con = sqlite3.connect("incidents.db")
        rows = con.execute(
            "SELECT severity, event_count FROM findings ORDER BY id").fetchall()
        con.close()
        # two detections ran (the 60-event burst and the 150-event burst);
        # the CLEAN baseline run must NOT have added a row
        check("two incidents are stored, one per confirmed burst", len(rows) == 2,
              "found %d - the CLEAN baseline run must not add a row" % len(rows))
        check("the first is High with 60 events",
              len(rows) > 0 and rows[0] == ("High", 60), str(rows[:1]))
        check("the second is Critical with 150 events",
              len(rows) > 1 and rows[1] == ("Critical", 150), str(rows[1:2]))

    print("\n[6] Can the viewer read what it exported?")
    check("findings.json was created", os.path.exists("findings.json"),
          "index.html reads this file - without it the page stays empty")
    if os.path.exists("findings.json"):
        data = json.load(open("findings.json", encoding="utf-8"))
        check("it is a list holding both findings",
              isinstance(data, list) and len(data) == 2, "got %r" % (data,))
        check("each finding has time, summary and severity",
              bool(data) and all(k in data[0] for k in ("time", "summary", "severity")),
              "index.html expects exactly these three keys")
        check("the time looks like HH:MM:SS",
              bool(data) and len(data[0]["time"]) == 8 and data[0]["time"][2] == ":")

    print("\n[7] Does it survive a bad or empty export?")
    write_csv("empty.csv", [])
    out3, err3, rc3 = run_detector("empty.csv")
    check("an empty export does not crash it", rc3 == 0 and not err3.strip())
    check("an empty export reports CLEAN", "CLEAN" in out3)

    # the locale-format trap: dates like 30-09-2026 instead of 2026-09-30
    write_csv("wrongdate.csv", [("30-09-2026 10:00:00", "11", "File created: x")])
    out4, err4, rc4 = run_detector("wrongdate.csv")
    check("a wrong date format gives a clear error, not a silent 0 result",
          "timestamp" in out4.lower() or "could be read" in out4.lower(),
          "it should tell you to re-export with export_sysmon.ps1")

    out5, err5, rc5 = run_detector("does_not_exist.csv")
    check("a missing file gives a helpful error",
          "cannot find" in out5.lower() and rc5 != 0)

    print("\n[8] Is the viewer wired to the right file?")
    page = open(os.path.join(HERE, "index.html"), encoding="utf-8").read()
    check("index.html fetches findings.json", "findings.json" in page)
    check("index.html auto-refreshes", "setInterval" in page)
    check("index.html colours Critical and High", "#c0392b" in page and "#e74c3c" in page)

finally:
    os.chdir(cwd)
    shutil.rmtree(work, ignore_errors=True)

# --------------------------------------------------------------------- result
print("\n" + "=" * 68)
if failed:
    print("  %d of %d checks FAILED" % (len(failed), len(passed) + len(failed)))
    print("=" * 68)
    print("\nFix these, then run selftest.py again:\n")
    for name, hint in failed:
        print("  - " + name + (("\n      " + hint) if hint else ""))
    sys.exit(1)

print("  ALL TESTS PASSED (%d checks)" % len(passed))
print("=" * 68)
print("""
Your code is correct. From here, any problem is SETUP, not code.

Next steps, in order (full detail in START_HERE.txt):
  1. Confirm the VM is isolated and you have a snapshot.
  2. Check Sysmon is running:        sc query sysmon
  3. Run the T1486 atomic test (PowerShell as Administrator).
  4. Export the events (PowerShell):
         powershell -ExecutionPolicy Bypass -File export_sysmon.ps1
  5. The attack:                     python detector.py sysmon_events.csv
  6. The control:                    python detector.py sysmon_baseline.csv
  7. Serve the viewer:               python -m http.server 8000
  8. Open:                           http://localhost:8000/index.html
""")
