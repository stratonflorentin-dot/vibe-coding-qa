<#
  Vibe Coding QA - backend entry point for the Windows auto-start task.

  Runs the backend in the FOREGROUND so the scheduled-task process stays alive
  together with it (unlike restart-backend.ps1, which spawns a window that does
  not survive an automated launcher). Loads vcqa.local.ps1 for the login and
  REFUSES to serve without one, so the public tunnel can never be exposed
  unauthenticated.

  This is launched by the 'VibeCodingQA-Backend' scheduled task at logon; you
  normally never run it by hand.
#>

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

$local = Join-Path $root 'vcqa.local.ps1'
if (Test-Path $local) { . $local }

if ([string]::IsNullOrWhiteSpace($env:VCQA_BASIC_AUTH)) {
    Write-Host 'Refusing to start: VCQA_BASIC_AUTH not set in vcqa.local.ps1.'
    exit 1
}

# Free port 8756 if a previous instance is still listening, then take over.
$conn = Get-NetTCPConnection -LocalPort 8756 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($conn) {
    Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 1000
}

Set-Location -LiteralPath $root
# Foreground: the task process IS the backend, so Task Scheduler keeps it alive.
python -m dashboard.backend
