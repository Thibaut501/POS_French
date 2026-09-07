<#
.SYNOPSIS
    Start POS V3 so another computer on the same local network can connect.

.EXAMPLE
    .\start-lan-server.ps1

.EXAMPLE
    .\start-lan-server.ps1 -Port 8090

.EXAMPLE
    .\start-lan-server.ps1 -OpenFirewall
#>

param(
    [int]$Port = 8080,
    [string]$BindAddress = "0.0.0.0",
    [switch]$OpenFirewall,
    [switch]$AllowPublicNetwork
)

$ErrorActionPreference = "Stop"

Set-Location -Path $PSScriptRoot

function Get-LanIPv4Addresses {
    try {
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.AddressState -eq "Preferred" -and
                $_.IPAddress -notlike "127.*" -and
                $_.IPAddress -notlike "169.254.*" -and
                -not $_.SkipAsSource
            } |
            Select-Object -ExpandProperty IPAddress -Unique
    }
    catch {
        [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
            Where-Object {
                $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
                $_.IPAddressToString -notlike "127.*" -and
                $_.IPAddressToString -notlike "169.254.*"
            } |
            ForEach-Object { $_.IPAddressToString } |
            Select-Object -Unique
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PythonCommand {
    $explicitCandidates = @(
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "$env:ProgramFiles\Python312\python.exe",
        "$env:ProgramFiles\Python311\python.exe",
        "$env:ProgramFiles\Python\python.exe",
        "$env:LOCALAPPDATA\Microsoft\WindowsApps\python.exe"
    )

    foreach ($candidate in $explicitCandidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCmd) {
        return $pythonCmd.Source
    }

    $pyCmd = Get-Command py -ErrorAction SilentlyContinue
    if ($pyCmd) {
        return $pyCmd.Source
    }

    return $null
}

function Get-ActivePublicProfiles {
    @(Get-NetConnectionProfile -ErrorAction SilentlyContinue |
        Where-Object {
            $_.NetworkCategory -eq "Public" -and
            $_.IPv4Connectivity -ne "Disconnected"
        })
}

function Get-FirewallProfiles {
    $profiles = @("Domain", "Private")
    if ($AllowPublicNetwork) {
        $profiles += "Public"
    }

    return $profiles
}

function Show-ConnectionUrls {
    param([int]$UrlPort)

    $lanIps = @(Get-LanIPv4Addresses)

    Write-Host ""
    Write-Host "POS V3 network access" -ForegroundColor Green
    Write-Host "This computer: http://localhost:$UrlPort"

    if ($lanIps.Count -gt 0) {
        Write-Host "Other computer on the same Wi-Fi/LAN:"
        foreach ($ip in $lanIps) {
            Write-Host "  http://$($ip):$UrlPort" -ForegroundColor Cyan
        }
    }
    else {
        Write-Host "No active LAN IPv4 address was found." -ForegroundColor Yellow
        Write-Host "Connect this computer to Wi-Fi or Ethernet, then run this script again."
    }

    Write-Host ""
}

$PythonCommand = Get-PythonCommand
if (-not $PythonCommand) {
    throw "Python was not found. Install Python 3.10+ from python.org, then run this script again."
}

$requirementsPath = Join-Path $PSScriptRoot "requirements.txt"
if (-not (Test-Path $requirementsPath)) {
    $requirementsPath = Join-Path $PSScriptRoot "pos_v3_mauritius_professional_dashboard\requirements.txt"
}

$dependencyCheck = & $PythonCommand -c "import flask, waitress, schedule" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Python dependencies are missing." -ForegroundColor Yellow
    if (Test-Path $requirementsPath) {
        Write-Host "Run this first:"
        Write-Host "  & `"$PythonCommand`" -m pip install -r `"$requirementsPath`""
    }
    else {
        Write-Host "Run this first:"
        Write-Host "  & `"$PythonCommand`" -m pip install flask waitress schedule"
    }
    exit 1
}

if ($OpenFirewall) {
    $ruleName = "POS V3 LAN Server TCP $Port"
    $firewallProfiles = @(Get-FirewallProfiles)
    $activePublicProfiles = @(Get-ActivePublicProfiles)

    if (-not (Test-IsAdministrator)) {
        $openFirewallCommand = ".\start-lan-server.ps1 -OpenFirewall"
        if ($AllowPublicNetwork) {
            $openFirewallCommand = "$openFirewallCommand -AllowPublicNetwork"
        }

        Write-Host "Opening the Windows Firewall port needs Administrator PowerShell." -ForegroundColor Yellow
        Write-Host "Right-click PowerShell, choose 'Run as administrator', then run:"
        Write-Host "  cd `"$PSScriptRoot`""
        Write-Host "  $openFirewallCommand"
        Write-Host ""
    }
    else {
        if ($activePublicProfiles.Count -gt 0 -and -not $AllowPublicNetwork) {
            Write-Host "Your active network is marked Public." -ForegroundColor Yellow
            Write-Host "Recommended: change this Wi-Fi/Ethernet network to Private in Windows Settings."
            Write-Host "On a trusted network only, you can also run:"
            Write-Host "  .\start-lan-server.ps1 -OpenFirewall -AllowPublicNetwork"
            Write-Host ""
        }

        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($existingRule) {
            Set-NetFirewallRule `
                -DisplayName $ruleName `
                -Enabled True `
                -Action Allow `
                -Profile $firewallProfiles

            Write-Host "Windows Firewall rule updated for TCP port $Port." -ForegroundColor Green
        }
        else {
            New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction Inbound `
            -Action Allow `
            -Protocol TCP `
            -LocalPort $Port `
                -Profile $firewallProfiles |
            Out-Null

            Write-Host "Windows Firewall rule added for TCP port $Port." -ForegroundColor Green
        }

        Write-Host "Firewall profiles: $($firewallProfiles -join ', ')"
    }
}

$listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($listener) {
    Write-Host "Port $Port is already in use by process $($listener.OwningProcess)." -ForegroundColor Yellow
    Write-Host "If POS V3 is already running, use one of these URLs:"
    Show-ConnectionUrls -UrlPort $Port

    if (-not $OpenFirewall) {
        Write-Host "If another computer cannot connect, run this from Administrator PowerShell:"
        Write-Host "  .\start-lan-server.ps1 -OpenFirewall"
        Write-Host "If Windows says the network is Public, either set it to Private or use:"
        Write-Host "  .\start-lan-server.ps1 -OpenFirewall -AllowPublicNetwork"
        Write-Host ""
    }

    Write-Host "To start another server, use a different port, for example:"
    Write-Host "  .\start-lan-server.ps1 -Port 8090"
    exit 0
}

if (-not $env:FLASK_SECRET_KEY) {
    $env:FLASK_SECRET_KEY = [guid]::NewGuid().ToString("N").Substring(0, 32)
}

$env:HOST = $BindAddress
$env:PORT = [string]$Port
$env:USE_AZURE_AUTH = "false"
$env:APP_ENFORCE_BILLING = "false"
$env:BILLING_GRACE_DAYS = "7"
$env:LICENSE_ENFORCE = "false"

Show-ConnectionUrls -UrlPort $Port

Write-Host "Keep this PowerShell window open while using POS V3." -ForegroundColor Yellow
Write-Host "If the other computer cannot connect, run this script as Administrator with -OpenFirewall."
Write-Host ""

& $PythonCommand serve.py
