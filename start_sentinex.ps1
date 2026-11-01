<#
.SYNOPSIS
    SentiNex: SDN Explainable AI Intrusion Detection Operations Control Center
    Single-Command Windows Launcher.

.DESCRIPTION
    1. Cleans stale Open vSwitch state and previous controller processes.
    2. Launches Ryu OpenFlow 1.3 Controller with REST stats API in WSL2.
    3. Launches SentiNex Mininet Daemon in WSL2 as root (without hardcoded passwords).
    4. Waits for Ryu ports 6653 (OFP) and 8080 (REST) to become ready.
    5. Starts the Windows Flask Dashboard on port 5000 and opens http://127.0.0.1:5000.
    6. Traps termination to cleanly stop all background processes without orphaned jobs.
#>

[CmdletBinding()]
param(
    [string]$Model = "rf",
    [int]$DashboardPort = 5000,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  SENTINEX: SDN Control Plane & Explainable AI Intrusion Detection   " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "[*] Active Model Backend Selection : $($Model.ToUpper())" -ForegroundColor Green
Write-Host "[*] Web Dashboard Port             : $DashboardPort" -ForegroundColor Green
Write-Host ""

$SentinexRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $SentinexRoot

# 1. Verify Prerequisites
Write-Host "[1/5] Verifying Windows & WSL Environments..." -ForegroundColor Yellow

$PythonWin = Join-Path $SentinexRoot "venv\Scripts\python.exe"
if (-not (Test-Path $PythonWin)) {
    $PythonWin = "python.exe"
}

# Check WSL
try {
    $wslCheck = wsl -u root echo "WSL_OK" 2>$null
    if ($wslCheck -ne "WSL_OK") {
        Write-Error "WSL is not available or root access failed. Please ensure WSL2 Ubuntu is installed."
        exit 1
    }
} catch {
    Write-Error "Could not invoke WSL: $_"
    exit 1
}

# 2. Cleanup Stale Processes & OVS bridges
Write-Host "[2/5] Cleaning stale controller and network state in WSL..." -ForegroundColor Yellow
wsl -u root bash -c "pkill -9 -f run_ryu.py 2>/dev/null; pkill -9 -f mininet_server.py 2>/dev/null; mn -c >/dev/null 2>&1"

# 3. Launch Ryu OpenFlow 1.3 Controller with REST API in WSL
Write-Host "[3/5] Starting Ryu OpenFlow 1.3 Controller in WSL..." -ForegroundColor Yellow
$wslRyuCmd = "cd /mnt/c/Users/asmin/SentiNex && export SENTINEX_MODEL=$Model && /home/asmin/SentiNex/venv_wsl/bin/python run_ryu.py ryu.app.ofctl_rest src/ryu_controller.py"

$ryuJob = Start-Process -FilePath "wsl" -ArgumentList "-u", "root", "bash", "-c", $wslRyuCmd -PassThru -WindowStyle Hidden

# Launch Mininet Daemon in WSL
$wslMnCmd = "cd /mnt/c/Users/asmin/SentiNex && /home/asmin/SentiNex/venv_wsl/bin/python src/mininet_server.py 8081"
$mnJob = Start-Process -FilePath "wsl" -ArgumentList "-u", "root", "bash", "-c", $wslMnCmd -PassThru -WindowStyle Hidden

# 4. Wait for Controller Readiness
Write-Host "[4/5] Waiting for Ryu Controller & REST API readiness (ports 6653 & 8080)..." -ForegroundColor Yellow
$ready = $false
$maxAttempts = 30
for ($i = 1; $i -le $maxAttempts; $i++) {
    Start-Sleep -Milliseconds 600
    try {
        $tcp6653 = Test-NetConnection -ComputerName "127.0.0.1" -Port 6653 -WarningAction SilentlyContinue
        $tcp8080 = Test-NetConnection -ComputerName "127.0.0.1" -Port 8080 -WarningAction SilentlyContinue
        if ($tcp6653.TcpTestSucceeded -and $tcp8080.TcpTestSucceeded) {
            $ready = $true
            break
        }
    } catch {
        # Keep waiting
    }
    Write-Host "  ... waiting for controller socket ($i/$maxAttempts)" -ForegroundColor DarkGray
}

if ($ready) {
    Write-Host "[+] Ryu Controller active on ports 6653 (OpenFlow) and 8080 (REST Stats)!" -ForegroundColor Green
} else {
    Write-Warning "[!] Ryu startup timed out on port 8080. Dashboard will start in fallback emulated mode."
}

# 5. Start Flask Operations Dashboard
Write-Host "[5/5] Starting SentiNex Web Operations Dashboard..." -ForegroundColor Yellow
$env:SENTINEX_MODEL = $Model
$env:SENTINEX_PORT = $DashboardPort

$dashUrl = "http://127.0.0.1:$DashboardPort"
if (-not $NoBrowser) {
    Start-Process $dashUrl
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  SENTINEX CONTROL CENTER IS LIVE: $dashUrl" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  * Live Operations   : Network topology, flow rules, telemetry KPIs"
Write-Host "  * Traffic Lab       : Mininet / Emulation configuration & packet injection"
Write-Host "  * XAI Inspector     : LIME and SHAP attributions with plain-English insights"
Write-Host "  * Model Switcher    : Toggle between RF and MLP neural network on the fly"
Write-Host ""
Write-Host "Press Ctrl+C in this console to cleanly shut down all services." -ForegroundColor Magenta
Write-Host "======================================================================" -ForegroundColor Cyan

try {
    # Run Flask in foreground so logs stream directly to operator
    & $PythonWin (Join-Path $SentinexRoot "dashboard\app.py")
} finally {
    Write-Host "`n[*] Shutting down SentiNex services..." -ForegroundColor Yellow
    wsl -u root bash -c "pkill -9 -f run_ryu.py 2>/dev/null; pkill -9 -f mininet_server.py 2>/dev/null; mn -c >/dev/null 2>&1"
    if ($ryuJob -and -not $ryuJob.HasExited) { Stop-Process -Id $ryuJob.Id -Force -ErrorAction SilentlyContinue }
    if ($mnJob -and -not $mnJob.HasExited) { Stop-Process -Id $mnJob.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "[+] Shutdown complete. All SDN bridges flushed." -ForegroundColor Green
}

