<#
  Vibe Coding QA - local launcher (Windows / PowerShell)

  Starts both halves of the dashboard, each in its own window:
    - Backend  : python -m dashboard.backend   ->  http://127.0.0.1:8756
    - Frontend : npm run dev (Vite)            ->  http://127.0.0.1:5173

  Your AI provider API key is loaded from vcqa.local.ps1 (gitignored) if it
  exists, and passed to the BACKEND process only as VCQA_AI_API_KEY. It never
  reaches the browser, the built JS, or the database.

  Usage (from this folder):
      .\run-local.ps1
  If PowerShell blocks the script:
      powershell -ExecutionPolicy Bypass -File .\run-local.ps1
#>

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

# --- Load local, gitignored config (your AI key lives here) ------------------
$localConfig = Join-Path $root 'vcqa.local.ps1'
if (Test-Path $localConfig) {
    . $localConfig
    if ([string]::IsNullOrWhiteSpace($env:VCQA_AI_API_KEY)) {
        Write-Host '[vcqa] vcqa.local.ps1 loaded, but no AI key set - AI features stay off.' -ForegroundColor Yellow
        Write-Host '       Edit vcqa.local.ps1 and paste your key to enable AI.'
    } else {
        Write-Host '[vcqa] Loaded AI key from vcqa.local.ps1 (AI features enabled).' -ForegroundColor Green
    }
} else {
    Write-Host '[vcqa] No vcqa.local.ps1 found - starting without AI (everything else works).' -ForegroundColor Yellow
    Write-Host '       Copy vcqa.local.example.ps1 to vcqa.local.ps1 and add your key to enable AI.'
}

# --- Start the backend (child inherits the VCQA_* env vars set above) --------
Start-Process powershell -ArgumentList @(
    '-NoExit', '-Command',
    "Set-Location -LiteralPath '$root'; Write-Host 'Backend -> http://127.0.0.1:8756'; python -m dashboard.backend"
)

# --- Start the frontend dev server -------------------------------------------
$frontend = Join-Path $root 'dashboard\frontend'
Start-Process powershell -ArgumentList @(
    '-NoExit', '-Command',
    "Set-Location -LiteralPath '$frontend'; Write-Host 'Frontend -> http://127.0.0.1:5173'; npm run dev"
)

Write-Host ''
Write-Host '[vcqa] Opened two windows: backend (8756) and frontend (5173).' -ForegroundColor Cyan
Write-Host '[vcqa] Open the dashboard:  http://127.0.0.1:5173' -ForegroundColor Cyan
Write-Host '[vcqa] To stop, close those two windows (or press Ctrl+C in each).'
