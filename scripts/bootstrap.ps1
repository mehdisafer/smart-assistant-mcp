param(
  [int]$TokenLifetimeDays = 365
)

$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Repo

New-Item -ItemType Directory -Force -Path "workspace","data","config" | Out-Null

if (-not (Test-Path "config\runtime.json")) {
  Copy-Item "config\runtime.example.json" "config\runtime.json"
}

$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$rng.Dispose()

$token = [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+","-").Replace("/","_")
$hasher = [System.Security.Cryptography.SHA256]::Create()
try {
  $sha = $hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($token))
} finally {
  $hasher.Dispose()
}
$shaHex = -join ($sha | ForEach-Object { $_.ToString("x2") })
$expires = [DateTimeOffset]::UtcNow.AddDays($TokenLifetimeDays).ToUnixTimeSeconds()

$identity = @{
  identities = @(
    @{
      owner = "local-operator"
      sha256 = $shaHex
      scopes = @(
        "mcp:use",
        "context:read",
        "maintenance:run",
        "workspace:read",
        "workspace:write",
        "process:read",
        "process:execute"
      )
      expires_at = $expires
      revoked = $false
    }
  )
}

$identity | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 "config\identities.json"

Write-Host ""
Write-Host "Bootstrap complete."
Write-Host "Bearer token (shown once):"
Write-Host $token
Write-Host ""
Write-Host "Store it in your MCP client/secret manager. Do not commit config\identities.json."