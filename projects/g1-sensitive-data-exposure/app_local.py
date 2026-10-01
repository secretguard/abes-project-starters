"""
app_local.py  --  your CONTROL service. This one is deliberately NOT reachable
                  from any other machine, and proving that is part of your marks.

WHERE THIS GOES : your home folder on the TARGET Ubuntu VM  (~)
HOW TO RUN IT   : open a SECOND Terminal on the target VM, then:
                      cd ~
                      python3 app_local.py
                  This window will also look frozen. That is correct. Leave it.

WHY IT EXISTS   : anyone can write a detector that always shouts ALERT. What
                  proves yours actually works is that it stays QUIET for this
                  service. app_public.py is reachable from outside and gets
                  flagged; this one is not reachable and does not. That contrast
                  is the most important thing in your demo.

WHY IT IS A SEPARATE FILE : a Flask app binds to ONE address. One app cannot be
                  public on some routes and private on others, so you need two.
"""
from flask import Flask

app = Flask("local_app")


@app.route("/internal")
def internal():
    """A different fake secret, served only to this machine."""
    return "SECRET=FAKE-LOCAL-9999"


if __name__ == "__main__":
    print("Serving on port 5001 - LOOPBACK ONLY")
    print("  reachable from THIS machine : http://localhost:5001/internal")
    print("  reachable from anywhere else: no - and that is the point")
    print("Press Ctrl+C to stop.")
    # 127.0.0.1 means "only this machine can reach me". Do not change this to
    # 0.0.0.0 - it would destroy your control and your negative test.
    app.run(host="127.0.0.1", port=5001)
