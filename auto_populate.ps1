<#
=============================================================================
  auto_populate.ps1  --  sets up an ABES project on a WINDOWS machine.

  Run this on the machine where the project actually lives. For the
  G3 Ransomware/Sysmon project that is your isolated, snapshotted Windows VM.

  USAGE  (in PowerShell, from the folder you cloned)
      powershell -ExecutionPolicy Bypass -File auto_populate.ps1 -List
      powershell -ExecutionPolicy Bypass -File auto_populate.ps1 -Project NAME
      powershell -ExecutionPolicy Bypass -File auto_populate.ps1 -Project NAME -Dir C:\MyLab

  -Project is REQUIRED. The script will not guess which project is yours:
  your project is decided by your assignment, not by the machine you are
  sitting at. Run -List to see the names, or read your run guide.

  WHAT IT DOES
      1. copies your project files into the project folder (C:\AtomicLab)
      2. backs up anything it would overwrite (never deletes your work)
      3. creates the evidence\ folder you save proof into
      4. checks Python, and for the ransomware project checks Sysmon
      5. runs the project's selftest
      6. prints your next commands

  WHY -ExecutionPolicy Bypass : Windows blocks unsigned scripts by default.
      That flag allows this one run without changing any machine setting.
=============================================================================
#>

param(
    [string]$Project = "",
    [string]$Dir = "",
    [switch]$List
)

$ErrorActionPreference = "Stop"

$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectsDir = Join-Path $RepoDir "projects"

# This script sets up WINDOWS projects. Which project is NEVER guessed: the
# student passes -Project, and each project's manifest declares the platform it
# belongs on. Guessing from the operating system was wrong - a student who has
# a Linux VM *and* Windows would silently get whichever project matched the
# machine they happened to be typing on, which for the ransomware project could
# mean landing it on their own laptop.
$ThisPlatform = "windows"

function Say  { param($m) Write-Host $m }
function Ok   { param($m) Write-Host "  OK   " -ForegroundColor Green -NoNewline; Write-Host $m }
function Bad  { param($m) Write-Host "  FAIL " -ForegroundColor Red -NoNewline; Write-Host $m }
function Warn { param($m) Write-Host "  NOTE " -ForegroundColor Yellow -NoNewline; Write-Host $m }
function Head { param($m) Write-Host ""; Write-Host $m -ForegroundColor Cyan }

function Get-Conf {
    param($dir, $key)
    $f = Join-Path $dir "project.conf"
    if (-not (Test-Path $f)) { return "" }
    $line = Get-Content $f | Where-Object { $_ -match ("^" + [regex]::Escape($key) + "=") } |
            Select-Object -First 1
    if ($line) { return ($line -replace ("^" + [regex]::Escape($key) + "="), "") }
    return ""
}

function Show-Projects {
    Say ""
    Say "Available projects - pick the one your trainer assigned you:"
    Say ""
    foreach ($d in Get-ChildItem -Path $ProjectsDir -Directory) {
        $ti = Get-Conf $d.FullName "title"
        $pf = Get-Conf $d.FullName "platform"
        $mc = Get-Conf $d.FullName "machine"
        Write-Host ("  " + $d.Name) -ForegroundColor White
        if ($ti) { Say "      $ti" }
        if ($mc) { Say "      runs on: $mc" }
        if ($pf -eq $ThisPlatform) {
            Write-Host ("      set up with:  powershell -ExecutionPolicy Bypass -File auto_populate.ps1 -Project " + $d.Name) -ForegroundColor Green
        } else {
            Write-Host "      not a Windows project" -ForegroundColor Yellow -NoNewline
            Say (" - use " + (Get-Conf $d.FullName "script") + " on that machine instead")
        }
        Say ""
    }
}

Say "=============================================================="
Say "  ABES project setup (Windows)"
Say "=============================================================="

if (-not (Test-Path $ProjectsDir)) {
    Bad "cannot find the projects folder next to this script."
    Say "    Expected: $ProjectsDir"
    Say "    Run this from inside the folder you cloned, for example:"
    Say "        cd C:\abes-project-starters"
    Say "        powershell -ExecutionPolicy Bypass -File auto_populate.ps1"
    exit 1
}

if ($List) { Show-Projects; exit 0 }

if ([string]::IsNullOrWhiteSpace($Project)) {
    Bad "which project? I will not guess - you have to tell me."
    Say "    Your project is NOT decided by which machine you are on. Two students"
    Say "    on different projects can both be sitting at a Windows machine."
    Show-Projects
    Say "Nothing has been changed. Re-run with -Project <name> from the list above."
    exit 2
}

$Src = Join-Path $ProjectsDir $Project
if (-not (Test-Path $Src)) {
    Bad "no such project: $Project"
    Show-Projects
    exit 1
}

# refuse to set up a project that belongs on another platform
$platform = Get-Conf $Src "platform"
if ($platform -and $platform -ne $ThisPlatform) {
    Bad "'$Project' is a $platform project - this script sets up $ThisPlatform projects."
    Say ("    That project runs on: " + (Get-Conf $Src "machine"))
    Say ("    Set it up there with:  " + (Get-Conf $Src "script"))
    Say ""
    Say "Nothing has been changed."
    exit 3
}

# the project manifest decides where its files go
if ([string]::IsNullOrWhiteSpace($Dir)) {
    $Dir = Get-Conf $Src "target"
    if ([string]::IsNullOrWhiteSpace($Dir)) { $Dir = "C:\AtomicLab" }
}

$title = Get-Conf $Src "title"
if ($title) { Say "  project: $title" }

# ----------------------------------------------------------------- 1. files
Head "[1] Copying project files"
Say "    from : $Src"
Say "    to   : $Dir"

if (-not (Test-Path $Dir)) {
    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    Ok "created $Dir"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$copied = 0
$backed = 0
foreach ($f in Get-ChildItem -Path $Src -File) {
    # project.conf is metadata for this script, not something the student needs
    if ($f.Name -eq "project.conf") { continue }
    $dest = Join-Path $Dir $f.Name
    if (Test-Path $dest) {
        $same = $false
        try {
            $same = (Get-FileHash $dest).Hash -eq (Get-FileHash $f.FullName).Hash
        } catch { $same = $false }
        if (-not $same) {
            Move-Item $dest "$dest.bak-$stamp" -Force
            Warn "$($f.Name) already existed and differed - saved yours as $($f.Name).bak-$stamp"
            $backed++
        }
    }
    Copy-Item $f.FullName $dest -Force
    $copied++
}
$msg = "copied $copied file(s)"
if ($backed -gt 0) { $msg += ", backed up $backed" }
Ok $msg

# -------------------------------------------------------- 2. evidence folder
Head "[2] Creating your evidence folder"
$ev = Join-Path $Dir "evidence"
if (-not (Test-Path $ev)) { New-Item -ItemType Directory -Path $ev -Force | Out-Null }
Ok "$ev  (save every screenshot and output here)"

# ---------------------------------------------------------------- 3. python
Head "[3] Checking Python"
$py = $null
foreach ($cand in @("python", "py")) {
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if ($cmd) { $py = $cand; break }
}
if ($py) {
    $ver = & $py --version 2>&1
    Ok "$ver  (command: $py)"
} else {
    Bad "Python is not installed, or not on PATH"
    Say "    Install it from https://www.python.org/downloads/"
    Say "    IMPORTANT: tick 'Add python.exe to PATH' during setup."
    exit 1
}

# ------------------------------------------------- 4. project prerequisites
Head "[4] Checking project prerequisites"

Say "    This project needs no pip packages - detector.py uses only Python's"
Say "    built-in modules, and SQLite is built in too."

# feature detection: this project ships the Sysmon exporter
if (Test-Path (Join-Path $Src "export_sysmon.ps1")) {
    $svc = $null
    foreach ($n in @("sysmon", "sysmon64")) {
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($s) { $svc = $s; break }
    }
    if ($svc -and $svc.Status -eq "Running") {
        Ok "Sysmon service is running ($($svc.Name))"
    } elseif ($svc) {
        Warn "Sysmon is installed ($($svc.Name)) but is $($svc.Status)"
        Say  "    start it in PowerShell as Administrator:  Start-Service $($svc.Name)"
    } else {
        Warn "Sysmon does not appear to be installed"
        Say  "    Your detector reads Sysmon events, so you need it."
        Say  "    Install it in PowerShell as Administrator:"
        Say  "        cd $Dir"
        Say  "        .\Sysmon64.exe -accepteula -i"
    }

    # can we actually read the log? (needs admin)
    try {
        $null = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction Stop
        Ok "the Sysmon event log is readable from this shell"
    } catch {
        Warn "cannot read the Sysmon event log from this shell"
        Say  "    This is usually because PowerShell is not running as Administrator,"
        Say  "    or Sysmon has not logged anything yet. You will need an elevated"
        Say  "    PowerShell for export_sysmon.ps1."
    }

    $admin = ([Security.Principal.WindowsPrincipal] `
              [Security.Principal.WindowsIdentity]::GetCurrent()
             ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($admin) { Ok "running as Administrator" }
    else { Warn "not running as Administrator - you will need an elevated PowerShell for the export step" }
}

# --------------------------------------------------------------- 5. selftest
Head "[5] Testing the project code"
$selftest = Join-Path $Dir "selftest.py"
$selftestOk = $false
if (Test-Path $selftest) {
    Push-Location $Dir
    try {
        & $py selftest.py
        $selftestOk = ($LASTEXITCODE -eq 0)
    } finally { Pop-Location }
    if ($selftestOk) {
        Ok "selftest passed"
    } else {
        Warn "selftest reported problems - read its output above, fix, then run:"
        Say  "        cd $Dir"
        Say  "        $py selftest.py"
    }
} else {
    Warn "no selftest.py in this project - skipping"
}

# ------------------------------------------------------------- 6. next steps
Say ""
Say "=============================================================="
if ($selftestOk) {
    Write-Host "  SETUP COMPLETE" -ForegroundColor Green -NoNewline
    Say " - your code is in place and tested"
} else {
    Write-Host "  SETUP DONE, WITH THINGS TO FIX" -ForegroundColor Yellow -NoNewline
    Say " (see above)"
}
Say "=============================================================="
Say ""
Say "Your files are in: $Dir"
Say "Read the full instructions:"
Say "        notepad $Dir\START_HERE.txt"
Say ""

# feature detection: this project ships the Sysmon exporter
if (Test-Path (Join-Path $Src "export_sysmon.ps1")) {
    Write-Host "BEFORE YOU RUN THE ATTACK:" -ForegroundColor Yellow
    Say "   - this VM's network must be Host-Only or Internal, NOT Bridged"
    Say "   - TAKE A SNAPSHOT of the clean VM first (VirtualBox > Snapshots > Take)"
    Say "   - the Defender exclusion goes on $Dir ONLY, never the whole machine"
    Say ""
    Say "Then, in PowerShell AS ADMINISTRATOR:"
    Say "        cd $Dir"
    Say "        Get-Date -Format 'yyyy-MM-dd HH:mm:ss'      # write this down"
    Say "        Invoke-AtomicTest T1486 -GetPrereqs"
    Say "        Invoke-AtomicTest T1486"
    Say "        Get-Date -Format 'yyyy-MM-dd HH:mm:ss'      # write this down too"
    Say "        powershell -ExecutionPolicy Bypass -File export_sysmon.ps1"
    Say ""
    Say "Then, in Command Prompt or PowerShell:"
    Say "        $py detector.py sysmon_events.csv       # should CONFIRM a burst"
    Say "        $py detector.py sysmon_baseline.csv     # should stay CLEAN"
    Say "        $py -m http.server 8000                 # then open:"
    Say "        http://localhost:8000/index.html"
    Say ""
    Say "Full detail is in START_HERE.txt."
}
Say ""
