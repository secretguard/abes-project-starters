"""
app_public.py  --  the EXPOSED web service. This is the one being attacked.

WHERE THIS GOES : your home folder on the TARGET Ubuntu VM  (~)
HOW TO RUN IT   : open a Terminal on the target VM, then:
                      cd ~
                      python3 app_public.py
                  The terminal will then look frozen. THAT IS CORRECT - a web
                  server is supposed to sit there waiting. Leave this window
                  open and open a NEW terminal for your next command.

WHAT IT DOES    : 1. serves a fake secret at  /public   (reachable from anywhere)
                  2. writes one line into access.log for every request
                  3. serves your findings dashboard at  /dashboard
"""
from flask import Flask, request, render_template_string
import datetime, json, os

app = Flask("public_app")

LOG_FILE = "access.log"            # the evidence your detector reads
FINDINGS_FILE = "findings.json"    # written by detector.py, shown on /dashboard


@app.after_request
def log_request(response):
    """Runs after every request. Writes one evidence line into access.log.

    The line format is five pieces separated by single spaces:
        <timestamp> <who asked> <method> <what they asked for> <what we sent back>
    detector.py splits on those spaces, so the format matters.
    """
    if request.path.startswith("/dashboard"):
        # don't log the dashboard itself, or access.log fills up with HTML
        return response
    body = response.get_data(as_text=True)
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now().isoformat()} {request.remote_addr} "
                f"{request.method} {request.path} {body}\n")
    return response


@app.route("/public")
def public():
    """The deliberately exposed secret. This is what the attacker fetches."""
    return "SECRET=FAKE-PUBLIC-1234"


DASH_HTML = """
<html><head><title>Exposure Detector - Live Findings</title>
<meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;background:#f5f7fa;padding:24px">
  <h2 style="color:#1F4E78;margin-bottom:4px">Sensitive Data Exposure - Live Findings</h2>
  <p style="color:#667;margin-top:0">Detected by detector.py from access.log</p>
  <table cellpadding="8" style="border-collapse:collapse;background:#fff;box-shadow:0 1px 3px #0002">
    <tr style="background:#1F4E78;color:#fff">
      <th align="left">Time</th><th align="left">Finding</th><th align="left">Severity</th>
    </tr>
    {% for r in rows %}
    <tr style="border-top:1px solid #e3e8ee">
      <td>{{ r.time }}</td>
      <td>{{ r.summary }}</td>
      <td style="color:#fff;font-weight:bold;background:{{ '#e74c3c' if r.severity in ('Critical','High')
         else ('#f39c12' if r.severity == 'Medium' else '#95a5a6') }}">{{ r.severity }}</td>
    </tr>
    {% endfor %}
  </table>
  {% if not rows %}
  <p style="color:#888">No findings yet - run detector.py to populate this.</p>
  {% endif %}
</body></html>
"""


@app.route("/dashboard")
def dashboard():
    """Reads findings.json (written by detector.py) and shows it as a table.

    This is why the dashboard is REAL and not a mock-up: it displays nothing
    except what your own detector actually found in your own log file.
    """
    rows = []
    if os.path.exists(FINDINGS_FILE):
        with open(FINDINGS_FILE) as f:
            rows = json.load(f)
    return render_template_string(DASH_HTML, rows=list(reversed(rows)))


if __name__ == "__main__":
    print("Serving on port 5000")
    print("  secret    : http://<this-vm-ip>:5000/public")
    print("  dashboard : http://localhost:5000/dashboard")
    print("Press Ctrl+C to stop.")
    # 0.0.0.0 means "answer on every network interface" - this is what makes
    # the endpoint reachable from another machine, i.e. exposed.
    app.run(host="0.0.0.0", port=5000)
