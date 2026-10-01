"""
selftest.py  --  RUN THIS FIRST, before you touch the VM or the network.

HOW TO RUN IT : put all the project files in one folder, then:
                    cd ~
                    python3 selftest.py

WHAT IT DOES  : checks your detector against a sample log that it creates
                itself. It needs no network, no second machine, no Flask -
                just Python.

WHY IT MATTERS: if this says ALL TESTS PASSED, your CODE is correct. Any
                problem after this point is your SETUP - wrong machine, wrong
                folder, app not running, VM not bridged - and never the code.
                That alone will save you hours of guessing.
"""
import os, sys, json, tempfile, shutil, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
passed, failed = [], []


def check(name, condition, hint=""):
    if condition:
        passed.append(name)
        print("  PASS  " + name)
    else:
        failed.append((name, hint))
        print("  FAIL  " + name + (("\n        -> " + hint) if hint else ""))


print("=" * 66)
print("  SELF TEST - checking your project code")
print("=" * 66)

# ---------------------------------------------------------------- files present
print("\n[1] Are all the files in this folder?")
print("    folder:", HERE)
expected = ["app_public.py", "app_local.py", "detector.py"]
for fn in expected:
    check(fn + " is here", os.path.exists(os.path.join(HERE, fn)),
          "copy " + fn + " into this folder, then run selftest.py again")

if failed:
    print("\nStopping - put the missing files in this folder first.")
    sys.exit(1)

# ------------------------------------------------------------ files are valid
print("\n[2] Is the Python valid (no typing mistakes)?")
import py_compile
for fn in expected:
    try:
        py_compile.compile(os.path.join(HERE, fn), doraise=True)
        check(fn + " has no syntax errors", True)
    except py_compile.PyCompileError as e:
        check(fn + " has no syntax errors", False, str(e).strip().splitlines()[-1])

# ------------------------------------------------------------- load detector
spec = importlib.util.spec_from_file_location("detector", os.path.join(HERE, "detector.py"))
detector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(detector)

# ------------------------------------------------- the detector's actual logic
print("\n[3] Does the detector make the right decision on each kind of line?")

external = "2026-10-01T10:14:22.101000 192.168.1.7 GET /public SECRET=FAKE-PUBLIC-1234"
local    = "2026-10-01T10:15:03.440000 127.0.0.1 GET /public SECRET=FAKE-PUBLIC-1234"
nosecret = "2026-10-01T10:16:11.900000 192.168.1.7 GET /about Welcome to the site"
broken   = "this line is nonsense"

r = detector.check_line(external)
check("an OUTSIDE request for a secret IS flagged", r is not None,
      "check SECRET_PATTERNS and LOCAL_IPS in detector.py")
check("   ...and it names the right IP", bool(r) and r["ip"] == "192.168.1.7")
check("   ...and it names the right path", bool(r) and r["path"] == "/public")

check("a LOCAL request for a secret is NOT flagged",
      detector.check_line(local) is None,
      "127.0.0.1 must be in LOCAL_IPS - this is your negative control")
check("an outside request with NO secret is NOT flagged",
      detector.check_line(nosecret) is None)
check("a malformed line does not crash it",
      detector.check_line(broken) is None)

# --------------------------------------------- the dashboard hand-off (file)
print("\n[4] Does it write findings where the dashboard can read them?")
tmp = tempfile.mkdtemp()
cwd = os.getcwd()
try:
    os.chdir(tmp)
    detector.save_finding("test finding from selftest", "High")
    ok = os.path.exists("findings.json")
    check("findings.json gets created", ok,
          "the dashboard reads this file - without it the page stays empty")
    if ok:
        data = json.load(open("findings.json"))
        check("it contains exactly one finding", len(data) == 1)
        check("each finding has time, summary and severity",
              all(k in data[0] for k in ("time", "summary", "severity")))
        check("the severity is High", data[0]["severity"] == "High")
finally:
    os.chdir(cwd)
    shutil.rmtree(tmp, ignore_errors=True)

# ------------------------------------------------- end to end over a real log
print("\n[5] End to end: a mixed log with one outside and one local request")
tmp = tempfile.mkdtemp()
try:
    os.chdir(tmp)
    with open("sample.log", "w") as f:
        f.write(external + "\n")
        f.write(local + "\n")
    hits = [detector.check_line(l) for l in open("sample.log")]
    hits = [h for h in hits if h]
    check("exactly ONE finding from the two lines", len(hits) == 1,
          "it should flag the outside request and ignore the local one")
    check("the one it flagged is the outside request",
          bool(hits) and hits[0]["ip"] == "192.168.1.7")
finally:
    os.chdir(cwd)
    shutil.rmtree(tmp, ignore_errors=True)

# ------------------------------------------------------------ flask installed
print("\n[6] Is Flask installed on this machine?")
try:
    import flask
    try:
        from importlib.metadata import version as _ver
        _v = _ver("flask")
    except Exception:
        _v = "unknown version"
    check("flask is installed (" + _v + ")", True)
except ImportError:
    check("flask is installed", False,
          "run:  sudo apt install -y python3-flask curl\n"
          "           do NOT use pip - on current Ubuntu it fails with\n"
          "           'error: externally-managed-environment'")

# --------------------------------------------------------------------- result
print("\n" + "=" * 66)
if failed:
    print("  %d of %d checks FAILED" % (len(failed), len(passed) + len(failed)))
    print("=" * 66)
    print("\nFix these, then run selftest.py again:\n")
    for name, hint in failed:
        print("  - " + name + (("\n      " + hint) if hint else ""))
    sys.exit(1)

print("  ALL TESTS PASSED (%d checks)" % len(passed))
print("=" * 66)
print("""
Your code is correct. From here, any problem is SETUP, not code.

Next steps, in order (full detail in START_HERE.txt):
  1. On the target VM:  python3 app_public.py        (terminal 1, leave open)
  2. On the target VM:  python3 app_local.py         (terminal 2, leave open)
  3. Find the VM's IP:  hostname -I | awk '{print $1}'
  4. From WSL2:         curl http://<that-ip>:5000/public      <- should work
  5. From WSL2:         curl http://<that-ip>:5001/internal    <- should FAIL
  6. On the target VM:  curl http://localhost:5000/public
  7. On the target VM:  cp access.log evidence.log
  8. On the target VM:  python3 detector.py evidence.log
  9. In the browser:    http://localhost:5000/dashboard
""")
