# =============================================================================
#  export_sysmon.ps1  --  pulls Sysmon events out of the Windows event log and
#                         writes them to a CSV that detector.py can read.
#
#  WHERE THIS GOES : C:\AtomicLab\  on your Windows VM (the snapshotted one)
#
#  HOW TO RUN IT   : this is a PowerShell script, NOT a cmd command.
#                    Open PowerShell as Administrator, then:
#
#                        cd C:\AtomicLab
#                        powershell -ExecutionPolicy Bypass -File export_sysmon.ps1
#
#  WHY A SCRIPT    : Get-WinEvent only exists in PowerShell. If you paste it
#                    into Command Prompt (cmd) you get
#                    "'Get-WinEvent' is not recognized" - which is the most
#                    common way to lose twenty minutes on this project.
#
#  WHAT YOU GET    : two files, which are your two test cases:
#                      sysmon_events.csv    the window your T1486 test ran in
#                      sysmon_baseline.csv  an earlier, ordinary window
# =============================================================================

param(
    # how many minutes back the attack window starts (default: last 15 min)
    [int]$AttackMinutes = 15,

    # the baseline window: from -BaselineFrom to -BaselineTo minutes ago.
    # Default = 30 to 40 minutes ago, i.e. before you ran the test.
    [int]$BaselineFrom = 40,
    [int]$BaselineTo = 30,

    [string]$LogName = "Microsoft-Windows-Sysmon/Operational"
)

$ErrorActionPreference = "Stop"

function Export-Window {
    param([datetime]$From, [datetime]$To, [string]$Path, [string]$Label)

    Write-Host ""
    Write-Host "--- $Label ---" -ForegroundColor Cyan
    Write-Host ("    from : " + $From.ToString("yyyy-MM-dd HH:mm:ss"))
    Write-Host ("    to   : " + $To.ToString("yyyy-MM-dd HH:mm:ss"))

    try {
        $events = Get-WinEvent -LogName $LogName -ErrorAction Stop |
                  Where-Object { $_.TimeCreated -ge $From -and $_.TimeCreated -le $To }
    } catch {
        Write-Host "    ERROR: could not read the Sysmon log." -ForegroundColor Red
        Write-Host "    Is Sysmon installed? Check with:  sc query sysmon" -ForegroundColor Yellow
        Write-Host "    Are you running PowerShell AS ADMINISTRATOR?" -ForegroundColor Yellow
        throw
    }

    $count = ($events | Measure-Object).Count
    if ($count -eq 0) {
        Write-Host "    WARNING: 0 events in this window." -ForegroundColor Yellow
        Write-Host "    Widen the window, e.g. -AttackMinutes 60" -ForegroundColor Yellow
    }

    # IMPORTANT: the timestamp is formatted explicitly as yyyy-MM-dd HH:mm:ss.
    # Without this, Export-Csv writes it in your machine's local format (for
    # example 30-09-2026) and detector.py cannot compare or sort it.
    $events |
        Select-Object @{Name = 'TimeCreated'; Expression = { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }},
                      'Id',
                      @{Name = 'Message';     Expression = { ($_.Message -replace "`r`n", ' ' -replace "`n", ' ') }} |
        Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8

    Write-Host ("    wrote $count events to " + $Path) -ForegroundColor Green
}

Write-Host "=============================================================="
Write-Host "  Sysmon export for the T1486 ransomware detection project"
Write-Host "=============================================================="

$now = Get-Date

# 1. the attack window - should contain your Atomic Red Team T1486 run
Export-Window -From $now.AddMinutes(-$AttackMinutes) -To $now `
              -Path "sysmon_events.csv" `
              -Label "ATTACK WINDOW (last $AttackMinutes minutes)"

# 2. the baseline window - ordinary activity from BEFORE the test.
#    This is your negative control and it is what proves your detector works.
Export-Window -From $now.AddMinutes(-$BaselineFrom) -To $now.AddMinutes(-$BaselineTo) `
              -Path "sysmon_baseline.csv" `
              -Label "BASELINE WINDOW ($BaselineFrom to $BaselineTo minutes ago)"

Write-Host ""
Write-Host "Done. Next, in Command Prompt or PowerShell:" -ForegroundColor Cyan
Write-Host "    python detector.py sysmon_events.csv     <- should CONFIRM a burst"
Write-Host "    python detector.py sysmon_baseline.csv   <- should stay CLEAN"
Write-Host ""
