# ABES Project Starters

Working starter code for the ABES Engineering College cybersecurity project
engagement. Each folder under `projects/` is a complete, tested project: the
code, a self test, and a step-by-step `START_HERE.txt`.

These exist so that students who are stuck on *mechanics* — which machine, which
shell, which folder — can get to a working project and spend their remaining
time on the part that is actually assessed: understanding and explaining it.

> **Students: you still have to be able to explain this code.** It is commented
> for that reason. Read `START_HERE.txt` and the comments in your detector
> before your demo. "I was given it" is not an answer to "how does it work?"

---

## Quick start

**1. Get the files onto the machine where your project runs.**

```bash
git clone <this-repo-url>
cd abes-project-starters
```

**2. Run the populate script for that machine.**

On **Linux** (e.g. your Ubuntu target VM):

```bash
bash auto_populate.sh
```

On **Windows** (e.g. your isolated lab VM), in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File auto_populate.ps1
```

The script copies your files into place, creates an `evidence/` folder, checks
your prerequisites, runs the self test, and prints your next commands.

**3. Read your instructions.**

```
START_HERE.txt     # in the folder the script just populated
```

---

## Projects

| Folder | Topic | Runs on | Populate with |
|---|---|---|---|
| `projects/g1-sensitive-data-exposure` | Detect secrets leaked to an external client, via web server access logs | Ubuntu VM (+ WSL2 as the attacker) | `auto_populate.sh` |
| `projects/g3-ransomware-sysmon` | Detect a ransomware file-encryption burst (ATT&CK T1486) in Sysmon events | Windows VM, isolated | `auto_populate.ps1` |

Your trainer will tell you which folder is yours. To target one explicitly:

```bash
bash auto_populate.sh --project g1-sensitive-data-exposure
```

```powershell
powershell -ExecutionPolicy Bypass -File auto_populate.ps1 -Project g3-ransomware-sysmon
```

List what is available with `--list` (Linux) or `-List` (Windows).

---

## Run the self test first

Every project ships a `selftest.py` that checks the code against sample data it
generates itself. It needs no network, no second machine, and no attack.

```bash
python3 selftest.py      # Linux
python selftest.py       # Windows
```

If it says **ALL TESTS PASSED**, the code is correct — so anything that fails
after that is *setup*, not code. That single fact saves hours of editing
working code to fix a network fault.

---

## Safety — read before running the G3 project

`g3-ransomware-sysmon` runs a real ransomware **technique test** from
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), a standard
public security-testing framework. It is built for labs, but it does write and
encrypt files.

- Run it **only** inside a virtual machine, never on your own laptop.
- Set the VM's network to **Host-Only** or **Internal** — not Bridged.
- **Take a snapshot** of the clean VM before you run anything.
- Scope the Defender exclusion to the **lab folder only**, never the whole machine.
- Copy your evidence out, then **revert to the snapshot** when you are done.

`START_HERE.txt` for that project repeats this and will not let you miss it.

---

## What the populate scripts do and do not do

They **do**: copy files, create `evidence/`, check Python and project
prerequisites, run the self test, print next steps. If a file already exists and
differs from the one being installed, your version is renamed to
`<name>.bak-<timestamp>` first — **your work is never deleted**.

They **do not**: install anything without being asked, run any attack, or touch
anything outside the project folder. On Linux, `--install-deps` is the one flag
that will install packages (via `apt`), and only when you pass it.

---

## For the trainer: adding another project

1. `mkdir projects/<group>-<topic>` and drop in the code, a `selftest.py`, and a
   `START_HERE.txt`.
2. If it is set up on Linux, no script change is needed — students pass
   `--project <name>`. To make it the default for an OS, update `LINUX_PROJECT`
   in `auto_populate.sh` or `$WindowsProject` in `auto_populate.ps1`.

Keep student names, email addresses, and any lab credentials out of this
repository. Projects are named by group and topic for that reason.
