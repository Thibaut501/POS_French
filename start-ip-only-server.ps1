<#
.SYNOPSIS
    Start POS V3 without requiring Administrator permission.

.EXAMPLE
    .\start-ip-only-server.ps1

.NOTES
    Browser URL on the other computer:
    http://192.168.100.3:8080
#>

$script = Join-Path $PSScriptRoot "start-lan-server.ps1"

if (-not (Test-Path $script)) {
    throw "start-lan-server.ps1 was not found."
}

$targetPort = 8080
$portInUse = Get-NetTCPConnection -LocalPort $targetPort -State Listen -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Host "Port 8080 is already in use. Using port 8090 instead." -ForegroundColor Yellow
    $targetPort = 8090
}

Write-Host "Starting POS V3 for IP-only access without Administrator permission..." -ForegroundColor Cyan
Write-Host "Other computer URL: http://192.168.100.3:$targetPort" -ForegroundColor Green
Write-Host ""

& $script -Port $targetPort
