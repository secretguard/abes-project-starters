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
                  3. serves your dashboard at  /dashboard
                  4. serves the findings to that dashboard at /api/findings

THE THREE PIECES - this is what to explain in your demo:
    detector.py     finds an exposure and appends it to findings.json
    /api/findings   hands that file to the browser as JSON
    dashboard.html  asks for it every few seconds and draws it
  They never call each other's code. They share one file. That is the whole
  design, and it is why the screen can only ever show real findings.
"""
from flask import Flask, request, jsonify, send_from_directory
import datetime, json, os

app = Flask("public_app")

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = "access.log"            # the evidence your detector reads
FINDINGS_FILE = "findings.json"    # written by detector.py, shown on /dashboard


@app.after_request
def log_request(response):
    """Runs after every request. Writes one evidence line into access.log.

    The line format is five pieces separated by single spaces:
        <timestamp> <who asked> <method> <what they asked for> <what we sent back>
    detector.py splits on those spaces, so the format matters.

    The dashboard and its data feed are NOT logged, for two reasons. The
    dashboard would fill access.log with HTML. And /api/findings sends your
    findings back - which contain the text "SECRET=" - so logging it would
    plant fake evidence in your own log file and could make your detector
    report an exposure that never happened.
    """
    if request.path.startswith("/dashboard") or request.path.startswith("/api/"):
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


@app.route("/api/findings")
def api_findings():
    """Hand findings.json to the dashboard as JSON.

    This is why the dashboard is REAL and not a mock-up: it can only show what
    your own detector wrote into this file.
    """
    if not os.path.exists(FINDINGS_FILE):
        return jsonify([])            # nothing detected yet - an empty list
    try:
        with open(FINDINGS_FILE) as f:
            return jsonify(json.load(f))
    except (ValueError, OSError):
        # a half-written or corrupt file should not take the whole page down
        return jsonify([])


@app.route("/dashboard")
def dashboard():
    """Serve the dashboard page itself - plain HTML, no templating."""
    if not os.path.exists(os.path.join(HERE, "dashboard.html")):
        return ("dashboard.html is missing from " + HERE
                + " - copy it in next to app_public.py."), 500
    return send_from_directory(HERE, "dashboard.html")


if __name__ == "__main__":
    print("Serving on port 5000")
    print("  secret    : http://<this-vm-ip>:5000/public")
    print("  dashboard : http://localhost:5000/dashboard")
    print("Press Ctrl+C to stop.")
    # 0.0.0.0 means "answer on every network interface" - this is what makes
    # the endpoint reachable from another machine, i.e. exposed.
    app.run(host="0.0.0.0", port=5000)
