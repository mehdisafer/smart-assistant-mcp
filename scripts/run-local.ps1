$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Repo

if (-not (Test-Path "config\runtime.json")) {
  throw "Missing config\runtime.json. Run scripts\bootstrap.ps1 first."
}
if (-not (Test-Path "config\identities.json")) {
  throw "Missing config\identities.json. Run scripts\bootstrap.ps1 first."
}

$env:SA_MCP_CONFIG = (Resolve-Path "config\runtime.json").Path

if (Test-Path ".venv\Scripts\python.exe") {
  & ".venv\Scripts\python.exe" -m smart_assistant_mcp.server
} else {
  python -m smart_assistant_mcp.server
}
