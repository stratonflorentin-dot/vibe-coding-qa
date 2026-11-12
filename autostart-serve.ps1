<#
  Vibe Coding QA - self-healing backend supervisor for the Windows auto-start task.

  Runs the backend in a loop: if the process ever exits (including the
  CTRL_C / 0xC000013A that Windows delivers to a console process when the
  interactive session changes), it is restarted within a few seconds, so the
  dashboard stays reachable on 127.0.0.1:8756. All output goes to a log file
  (dashboard/data/backend.log), which also lets `pythonw`-style silent crashes
  be diagnosed.

  Loads vcqa.local.ps1 for the login/DB config and REFUSES to serve without a
  configured credential, so the tunnel can never be exposed unauthenticated.

  Launched by the 'VibeCodingQA-Backend' scheduled task; you normally never run
  it by hand.
#>

$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot

$local = Join-Path $root 'vcqa.local.ps1'
if (Test-Path $local) { . $local }

if ([string]::IsNullOrWhiteSpace($env:VCQA_BASIC_AUTH)) {
    Write-Host 'Refusing to start: VCQA_BASIC_AUTH not set in vcqa.local.ps1.'
    exit 1
}

$env:VCQA_NO_BROWSER = '1'
$dataDir = Join-Path $root 'dashboard\data'
if (-not (Test-Path $dataDir)) { New-Item -ItemType Directory -Force -Path $dataDir | Out-Null }
$log = Join-Path $dataDir 'backend.log'

Set-Location -LiteralPath $root

while ($true) {
    # Free the port if a dead/previous instance is still holding it.
    $conn = Get-NetTCPConnection -LocalPort 8756 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($conn) {
        Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 800
    }

    "[$(Get-Date -Format o)] starting backend" | Out-File -Append -Encoding utf8 $log
    # Foreground: blocks until the backend exits. Output (incl. tracebacks) -> log.
    & python -m dashboard.backend *>> $log
    "[$(Get-Date -Format o)] backend exited (code $LASTEXITCODE); restarting in 3s" | Out-File -Append -Encoding utf8 $log
    Start-Sleep -Seconds 3
}
