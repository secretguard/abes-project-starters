#!/usr/bin/env bash
# =============================================================================
#  auto_populate.sh  --  sets up an ABES project on a LINUX machine.
#
#  Run this on the machine where the project actually lives. For the
#  G1 Sensitive Data Exposure project that is your Ubuntu TARGET VM.
#
#  USAGE
#      bash auto_populate.sh --list                 # show available projects
#      bash auto_populate.sh --project NAME         # set up that project
#      bash auto_populate.sh --project NAME --install-deps
#      bash auto_populate.sh --project NAME --dir ~/work
#
#  --project is REQUIRED. The script will not guess which project is yours:
#  your project is decided by your assignment, not by the machine you are
#  sitting at. Run --list to see the names, or read your run guide.
#
#  WHAT IT DOES
#      1. copies your project files into your home folder
#      2. backs up anything it would overwrite (never deletes your work)
#      3. creates the evidence/ folder you save proof into
#      4. checks python3 and flask
#      5. runs the project's selftest
#      6. prints your next commands
# =============================================================================

set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECTS_DIR="$REPO_DIR/projects"

# This script sets up LINUX projects. Which project is NEVER guessed: the
# student passes --project, and each project's manifest declares the platform
# it belongs on. Guessing from the operating system was wrong - a student who
# has both a Linux VM and Windows would silently get whichever project matched
# the machine they happened to be typing on.
THIS_PLATFORM="linux"

TARGET_DIR=""
PROJECT=""
INSTALL_DEPS=0

GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m';  BOLD=$'\033[1m';   NC=$'\033[0m'

say()  { printf '%s\n' "$*"; }
ok()   { printf '%s  OK   %s %s\n' "$GREEN" "$NC" "$*"; }
bad()  { printf '%s  FAIL %s %s\n' "$RED" "$NC" "$*"; }
warn() { printf '%s  NOTE %s %s\n' "$YELLOW" "$NC" "$*"; }
head1(){ printf '\n%s%s%s\n' "$BOLD$CYAN" "$*" "$NC"; }

# read one key from a project's manifest
conf() {  # conf <project-dir> <key>
  [ -f "$1/project.conf" ] || return 0
  sed -n "s/^$2=//p" "$1/project.conf" | head -1
}

list_projects() {
  say ""
  say "${BOLD}Available projects${NC} - pick the one your trainer assigned you:"
  say ""
  for d in "$PROJECTS_DIR"/*/; do
    [ -d "$d" ] || continue
    nm="$(basename "$d")"
    ti="$(conf "$d" title)"; pf="$(conf "$d" platform)"; mc="$(conf "$d" machine)"
    say "  ${BOLD}$nm${NC}"
    [ -n "$ti" ] && say "      $ti"
    [ -n "$mc" ] && say "      runs on: $mc"
    if [ "$pf" = "$THIS_PLATFORM" ]; then
      say "      set up with:  ${GREEN}bash auto_populate.sh --project $nm${NC}"
    else
      say "      ${YELLOW}not a Linux project${NC} - use $(conf "$d" script) on Windows instead"
    fi
    say ""
  done
}

while [ $# -gt 0 ]; do
  case "$1" in
    --list)         list_projects; exit 0 ;;
    --project)      PROJECT="${2:-}"; shift 2 ;;
    --dir)          TARGET_DIR="${2:-}"; shift 2 ;;
    --install-deps) INSTALL_DEPS=1; shift ;;
    -h|--help)      sed -n '2,30p' "$0"; exit 0 ;;
    *) bad "unknown option: $1"; say "try: bash auto_populate.sh --help"; exit 1 ;;
  esac
done

say "=============================================================="
say "  ABES project setup (Linux)"
say "=============================================================="

# ----------------------------------------------------------------- sanity
if [ ! -d "$PROJECTS_DIR" ]; then
  bad "cannot find the projects folder next to this script."
  say "    Expected: $PROJECTS_DIR"
  say "    Run this script from inside the folder you cloned, e.g.:"
  say "        cd ~/abes-project-starters && bash auto_populate.sh"
  exit 1
fi

if [ -z "$PROJECT" ]; then
  bad "which project? I will not guess - you have to tell me."
  say "    Your project is NOT decided by which machine you are on. Two students"
  say "    on different projects can both be sitting at a Linux terminal."
  list_projects
  say "Nothing has been changed. Re-run with --project <name> from the list above."
  exit 2
fi

SRC="$PROJECTS_DIR/$PROJECT"
if [ ! -d "$SRC" ]; then
  bad "no such project: $PROJECT"
  list_projects
  exit 1
fi

# refuse to set up a project that belongs on another platform
PLATFORM="$(conf "$SRC" platform)"
if [ -n "$PLATFORM" ] && [ "$PLATFORM" != "$THIS_PLATFORM" ]; then
  bad "'$PROJECT' is a $PLATFORM project - this script sets up $THIS_PLATFORM projects."
  say "    That project runs on: $(conf "$SRC" machine)"
  say "    Set it up there with:  $(conf "$SRC" script)"
  say ""
  say "Nothing has been changed."
  exit 3
fi

# the project manifest decides where its files go
if [ -z "$TARGET_DIR" ]; then
  TARGET_DIR="$(conf "$SRC" target)"
  [ "$TARGET_DIR" = "\$HOME" ] && TARGET_DIR="$HOME"
  [ -z "$TARGET_DIR" ] && TARGET_DIR="$HOME"
fi

TITLE="$(conf "$SRC" title)"
[ -n "$TITLE" ] && say "  project: $TITLE"

# ------------------------------------------------------------- 1. the files
head1 "[1] Copying project files"
say "    from : $SRC"
say "    to   : $TARGET_DIR"

mkdir -p "$TARGET_DIR" || { bad "cannot create $TARGET_DIR"; exit 1; }

STAMP="$(date +%Y%m%d-%H%M%S)"
copied=0; backed_up=0
for f in "$SRC"/*; do
  [ -f "$f" ] || continue
  name="$(basename "$f")"
  # project.conf is metadata for this script, not something the student needs
  [ "$name" = "project.conf" ] && continue
  dest="$TARGET_DIR/$name"
  # compare ignoring line endings: this script converts copied files to LF,
  # so a byte compare would flag an untouched file as "changed" on every re-run
  if [ -f "$dest" ] && ! diff -q <(tr -d '\r' < "$f") <(tr -d '\r' < "$dest") >/dev/null 2>&1; then
    mv "$dest" "$dest.bak-$STAMP"
    warn "$name already existed and differed - saved yours as $name.bak-$STAMP"
    backed_up=$((backed_up + 1))
  fi
  cp "$f" "$dest" && copied=$((copied + 1))
done
# make sure line endings are Unix, in case the repo was cloned on Windows
for f in "$TARGET_DIR"/*.py "$TARGET_DIR"/*.txt; do
  [ -f "$f" ] && sed -i 's/\r$//' "$f" 2>/dev/null || true
done
ok "copied $copied file(s)$([ $backed_up -gt 0 ] && echo ", backed up $backed_up")"

# -------------------------------------------------------- 2. evidence folder
head1 "[2] Creating your evidence folder"
mkdir -p "$TARGET_DIR/evidence"
ok "$TARGET_DIR/evidence  (save every screenshot and output here)"

# ------------------------------------------------------------- 3. python
head1 "[3] Checking Python"
if command -v python3 >/dev/null 2>&1; then
  ok "$(python3 --version 2>&1)"
else
  bad "python3 is not installed"
  say "    fix:  sudo apt update && sudo apt install -y python3"
  exit 1
fi

# -------------------------------------------------------------- 4. flask
head1 "[4] Checking project dependencies"
need_flask=0
if python3 -c "import flask" >/dev/null 2>&1; then
  ok "flask is installed"
else
  need_flask=1
  if [ "$INSTALL_DEPS" -eq 1 ]; then
    warn "flask missing - installing with apt (you may be asked for your password)"
    if sudo apt update && sudo apt install -y python3-flask curl; then
      ok "flask installed"
      need_flask=0
    else
      bad "apt install failed"
    fi
  else
    bad "flask is NOT installed"
    say "    fix:  sudo apt update && sudo apt install -y python3-flask curl"
    say ""
    say "    ${BOLD}Do NOT use pip install flask${NC} - on current Ubuntu it fails with"
    say "    'error: externally-managed-environment'. Use the apt command above."
    say ""
    say "    or re-run this script with:  bash auto_populate.sh --install-deps"
  fi
fi

if command -v curl >/dev/null 2>&1; then
  ok "curl is installed"
else
  warn "curl is missing - fix with:  sudo apt install -y curl"
fi

# --------------------------------------------------------------- 5. selftest
head1 "[5] Testing the project code"
if [ -f "$TARGET_DIR/selftest.py" ]; then
  if ( cd "$TARGET_DIR" && python3 selftest.py ); then
    ok "selftest passed"
    SELFTEST_OK=1
  else
    SELFTEST_OK=0
    warn "selftest reported problems - read its output above, fix, then run:"
    say  "        cd $TARGET_DIR && python3 selftest.py"
  fi
else
  SELFTEST_OK=0
  warn "no selftest.py in this project - skipping"
fi

# ------------------------------------------------------------- 6. next steps
say ""
say "=============================================================="
if [ "${SELFTEST_OK:-0}" -eq 1 ]; then
  say "  ${GREEN}SETUP COMPLETE${NC} - your code is in place and tested"
else
  say "  ${YELLOW}SETUP DONE, WITH THINGS TO FIX${NC} (see above)"
fi
say "=============================================================="
say ""
say "Your files are in: $TARGET_DIR"
say "Read the full instructions:"
say "        less $TARGET_DIR/START_HERE.txt     (press q to quit)"
say ""
if [ "$need_flask" -eq 1 ]; then
  say "${YELLOW}First, install flask:${NC}"
  say "        sudo apt install -y python3-flask curl"
  say ""
fi
say "Then, with THREE separate terminal windows:"
say "    terminal 1:   cd $TARGET_DIR && python3 app_public.py"
say "    terminal 2:   cd $TARGET_DIR && python3 app_local.py"
say "    terminal 3:   hostname -I | awk '{print \$1}'     <- note this IP"
say ""
say "Then from WSL2 on your Windows host, using that IP:"
say "        curl http://<that-ip>:5000/public      <- should return the secret"
say "        curl http://<that-ip>:5001/internal    <- should FAIL (that is correct)"
say ""
say "Full detail, including the dashboard, is in START_HERE.txt."
say ""
