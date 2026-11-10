<#
  Vibe Coding QA - safe backend restart (Windows / PowerShell)

  Restarts ONLY the backend on 127.0.0.1:8756. That one process serves the built
  dashboard (dist/) AND the API, and sits behind your Cloudflare tunnel, so this
  is what you run to deploy backend changes (and pick up a fresh `npm run build`).

  It loads vcqa.local.ps1 so your login (VCQA_BASIC_AUTH) and AI key are set, and
  it REFUSES to start when no login is configured - so the public tunnel can
  never be served without authentication.

  Usage (from this folder):
      .\restart-backend.ps1
  If PowerShell blocks scripts:
      powershell -ExecutionPolicy Bypass -File .\restart-backend.ps1
#>

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

# Load local secrets / config (gitignored): VCQA_BASIC_AUTH, AI key, etc.
$localConfig = Join-Path $root 'vcqa.local.ps1'
if (Test-Path $localConfig) {
    . $localConfig
} else {
    Write-Host 'No vcqa.local.ps1 found - copy vcqa.local.example.ps1 to vcqa.local.ps1 first.' -ForegroundColor Red
    exit 1
}

# Safety gate: never start the backend (and thus expose the tunnel) without a login.
if ([string]::IsNullOrWhiteSpace($env:VCQA_BASIC_AUTH)) {
    Write-Host ''
    Write-Host 'REFUSING TO START: VCQA_BASIC_AUTH is not set.' -ForegroundColor Red
    Write-Host 'Your public tunnel would have NO login. Open vcqa.local.ps1 and set:' -ForegroundColor Yellow
    Write-Host '    $env:VCQA_BASIC_AUTH = "vcqa:<your-password>"' -ForegroundColor Yellow
    Write-Host 'then run this script again.'
    exit 1
}

# Stop whatever is currently serving :8756 (the old backend).
$conn = Get-NetTCPConnection -LocalPort 8756 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($conn) {
    Write-Host ("Stopping current backend (PID {0}) on :8756 ..." -f $conn.OwningProcess)
    Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800
}

# Start the new backend in its own window; it inherits the VCQA_* env set above.
Write-Host 'Starting backend on http://127.0.0.1:8756 (login enabled) ...' -ForegroundColor Green
Start-Process powershell -ArgumentList @(
    '-NoExit', '-Command',
    "Set-Location -LiteralPath '$root'; python -m dashboard.backend"
)

Write-Host ''
Write-Host 'Backend is restarting. Your Cloudflare tunnel (pointing at :8756) reconnects on its own.' -ForegroundColor Cyan
Write-Host 'Give it ~5 seconds, then hard-refresh the dashboard (Ctrl+Shift+R).'
