# build.ps1 — Package POS V3 as a standalone Windows executable
# ================================================================
# Prerequisites:
#   pip install pyinstaller pyarmor  (pyarmor is optional, for obfuscation)
#
# Usage:
#   .\build.ps1                  # standard build
#   .\build.ps1 -Obfuscate       # obfuscate source with PyArmor first
#   .\build.ps1 -Clean           # remove previous build artefacts then build
#
# Output: dist\pos_v3\pos_v3.exe  (one-folder bundle, self-contained)
# ─────────────────────────────────────────────────────────────────────────────

param(
    [switch]$Obfuscate,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot

Set-Location $Root

# ── Optional cleanup ──────────────────────────────────────────────────────────
if ($Clean) {
    Write-Host "Cleaning previous build artefacts..." -ForegroundColor Cyan
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "build", "dist", "__pycache__", "pos_v3.spec"
}

# ── Optional obfuscation via PyArmor ─────────────────────────────────────────
$EntryPoint = "serve.py"

if ($Obfuscate) {
    Write-Host "Obfuscating source with PyArmor..." -ForegroundColor Cyan
    $ObfuscateDir = "dist_obfuscated"
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $ObfuscateDir

    # Obfuscate the main modules
    pyarmor gen --output $ObfuscateDir serve.py app.py license_manager.py keygen.py
    if ($LASTEXITCODE -ne 0) { Write-Error "PyArmor obfuscation failed"; exit 1 }

    # Use the obfuscated entry point
    $EntryPoint = "$ObfuscateDir\serve.py"
    Write-Host "Obfuscation complete -> $ObfuscateDir" -ForegroundColor Green
}

# ── PyInstaller build ─────────────────────────────────────────────────────────
Write-Host "Building executable with PyInstaller..." -ForegroundColor Cyan

$HiddenImports = @(
    "waitress",
    "flask",
    "schedule",
    "cryptography",
    "cryptography.hazmat.primitives",
    "cryptography.hazmat.primitives.asymmetric",
    "cryptography.hazmat.primitives.asymmetric.padding",
    "cryptography.hazmat.primitives.asymmetric.rsa",
    "cryptography.hazmat.primitives.hashes",
    "cryptography.hazmat.primitives.serialization",
    "cryptography.hazmat.primitives.kdf.pbkdf2",
    "cryptography.hazmat.backends",
    "cryptography.fernet",
    "barcode",
    "pyzbar",
    "PIL",
    "stripe",
    "sqlalchemy",
    "alembic",
    "pyodbc",
    "email",
    "smtplib",
    "sqlite3",
    "uuid",
    "subprocess",
    "platform"
)

$HiddenImportArgs = $HiddenImports | ForEach-Object { "--hidden-import=$_" }

# Data files to bundle (templates, static assets, database schema)
$DataArgs = @(
    "--add-data=templates;templates",
    "--add-data=static;static",
    "--add-data=database;database"
)

pyinstaller `
    --noconfirm `
    --name pos_v3 `
    --onedir `
    --console `
    @HiddenImportArgs `
    @DataArgs `
    --exclude-module tkinter `
    --exclude-module matplotlib `
    --exclude-module numpy `
    --exclude-module pandas `
    $EntryPoint

if ($LASTEXITCODE -ne 0) { Write-Error "PyInstaller build failed"; exit 1 }

# ── Post-build: copy runtime files ────────────────────────────────────────────
Write-Host "Copying runtime files to dist\pos_v3..." -ForegroundColor Cyan
$DistDir = "dist\pos_v3"

# Copy .env.example so operators know what vars to configure
if (Test-Path ".env.example") {
    Copy-Item ".env.example" "$DistDir\.env.example" -Force
}

# Copy start script
if (Test-Path "start.ps1") {
    Copy-Item "start.ps1" "$DistDir\start.ps1" -Force
}

# Remind operator: vendor_private.pem must NOT be included in distribution
Write-Host ""
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host " BUILD COMPLETE: dist\pos_v3\pos_v3.exe" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "Before distributing to a customer:" -ForegroundColor Cyan
Write-Host "  1. Obtain the customer's hardware fingerprint:"
Write-Host "       python keygen.py fingerprint   (run on customer machine)"
Write-Host "  2. Issue a license:"
Write-Host "       python keygen.py issue --company ""Acme"" --company-id ""acme-001"" --days 365 --hardware-fp <fp>"
Write-Host "  3. Place license_<company-id>.key in dist\pos_v3\ and rename to license.key"
Write-Host "  4. Set BACKUP_ENCRYPTION_KEY in the customer's .env (optional)"
Write-Host "  5. Do NOT include vendor_private.pem in the distribution package"
Write-Host ""
Write-Host "Files in dist\pos_v3\ are ready to ship." -ForegroundColor Green
