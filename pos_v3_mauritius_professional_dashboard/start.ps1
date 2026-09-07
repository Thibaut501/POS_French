<#
.SYNOPSIS
    Plug-and-play launch script for POS V3.
    Fill in the values below, then run:  .\start.ps1

.NOTES
    Requires Python and the packages in requirements.txt.
    Install deps first:  pip install -r requirements.txt
#>

# ── Flask ─────────────────────────────────────────────────────
$env:FLASK_SECRET_KEY   = "CHANGE-ME-32-char-random-string"

# ── Server ────────────────────────────────────────────────────
$env:HOST = "0.0.0.0"
$env:PORT = "8080"

# ── Azure AD B2C ──────────────────────────────────────────────
# Set to "true" to enable Azure login; leave "false" for local auth.
$env:USE_AZURE_AUTH      = "false"

# e.g. https://<tenant>.b2clogin.com/<tenant>.onmicrosoft.com/<policy>/v2.0
$env:OIDC_AUTHORITY      = ""

# From Azure portal → App registrations → your app → Overview
$env:OIDC_CLIENT_ID      = ""

# From Azure portal → App registrations → Certificates & secrets
$env:OIDC_CLIENT_SECRET  = ""

# Must match a Redirect URI registered in Azure portal
$env:OIDC_REDIRECT_URI   = "http://localhost:8080/auth/callback"

$env:OIDC_SCOPE          = "openid profile email"

# ── Billing / Stripe ──────────────────────────────────────────
$env:APP_ENFORCE_BILLING      = "false"
$env:BILLING_GRACE_DAYS       = "7"
$env:STRIPE_SECRET_KEY        = "sk_test_..."
$env:STRIPE_DEFAULT_PRICE_ID  = "price_..."
$env:STRIPE_WEBHOOK_SECRET    = "whsec_..."

# ── License ───────────────────────────────────────────────────
# Set to "false" to skip license checks (local dev only).
# Set to "true" and place license.key in this folder for production.
$env:LICENSE_ENFORCE            = "false"

# Path to the license key file (default: license.key in this folder)
$env:LICENSE_FILE               = "license.key"

# Optional: URL of your license heartbeat server (leave blank if none)
$env:LICENSE_SERVER_URL         = ""

# Optional: override the backup encryption passphrase
$env:BACKUP_ENCRYPTION_KEY      = ""

# ── Start ─────────────────────────────────────────────────────
Write-Host "Starting POS V3 on http://$($env:HOST):$($env:PORT)" -ForegroundColor Cyan
python serve.py
