# POS V3 Mauritius - Installation Manual

For Josea Outsourcing Ltd staff.

**Software:** POS V3 Mauritius  
**Scope:** VAT, stock, sales, barcode, cash controls, licensing, backups, and optional billing  
**Document version:** 1.1 - June 2026

## Contents

1. Prerequisites
2. On-premises Windows installation
3. License issuing and activation
4. Post-install checks
5. Cloud installation on Azure
6. Backup and recovery
7. Troubleshooting
8. Quick reference

## 1. Prerequisites

### Staff checklist

- Full application folder or release ZIP
- Python 3.11 or 3.12 installer if the client PC does not already have Python
- `keygen.py` and `vendor_private.pem` on the vendor laptop only
- Client company name and company ID, for example `client-001`
- Client contact email for backup or system notifications
- Optional: Azure subscription details for cloud deployments
- Optional: Stripe account details if billing enforcement is required

### Client PC requirements

- Windows 10 or Windows 11, 64-bit
- 4 GB RAM minimum
- 10 GB free disk space minimum
- Modern browser: Chrome, Edge, or Firefox
- Local network access if the POS must be opened by other devices
- Internet access during dependency installation

## 2. On-Premises Windows Installation

### A. Install Python

1. Download Python from `https://python.org/downloads`.
2. Run the installer.
3. Tick `Add Python to PATH`.
4. Open PowerShell and verify:

```powershell
python --version
```

Use Python 3.11.x or 3.12.x.

### B. Copy the application

Recommended location:

```text
C:\POS\pos_v3_mauritius\
```

The application folder should include:

```text
app.py
serve.py
start.ps1
license_manager.py
keygen.py
vendor_public.pem
templates\
static\
database\
backups\
pos_v3_mauritius_professional_dashboard\requirements.txt
```

Important: do not copy `vendor_private.pem` to the client PC. It stays on the vendor laptop only.

### C. Create a virtual environment

```powershell
cd C:\POS\pos_v3_mauritius
python -m venv .venv
.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.venv\Scripts\Activate.ps1
```

### D. Install dependencies

If the release has `requirements.txt` in the application root:

```powershell
pip install -r requirements.txt
```

If using the current repository layout:

```powershell
pip install -r pos_v3_mauritius_professional_dashboard\requirements.txt
```

Verify the core packages:

```powershell
python -c "import flask, waitress, stripe, barcode, pyzbar, cryptography; print('OK')"
```

## 3. License Issuing and Activation

### A. Get the client machine fingerprint

Command-line method:

```powershell
python keygen.py fingerprint
```

Alternative from the app:

1. Temporarily run without enforcement:

```powershell
$env:LICENSE_ENFORCE = "false"
$env:FLASK_SECRET_KEY = "temp-setup-key"
python serve.py
```

2. Open `http://localhost:8080`.
3. Log in with `admin` / `admin123`.
4. Open License.
5. Copy the machine fingerprint.
6. Stop the server with `Ctrl+C`.

### B. Issue the license on the vendor laptop

Run this on the vendor laptop, in the folder containing `keygen.py` and `vendor_private.pem`:

```powershell
python keygen.py issue `
  --company "Client Company Name" `
  --company-id "client-001" `
  --days 365 `
  --hardware-fp 0618156cdb42803153d506332562d4fb
```

This creates a file like:

```text
license_client-001.key
```

### C. Activate on the client PC

1. Copy the issued file to the application folder.
2. Rename it to:

```text
license.key
```

3. In `start.ps1`, set:

```powershell
$env:LICENSE_ENFORCE = "true"
$env:LICENSE_FILE = "license.key"
```

4. Generate a strong Flask secret:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

5. Paste it into `start.ps1`:

```powershell
$env:FLASK_SECRET_KEY = "paste-generated-key-here"
```

6. Verify the license:

```powershell
python keygen.py verify license.key
```

Expected result: license is valid and shows company, license ID, and expiry.

### D. Renew a license

Issue a fresh license with the same company ID and a new duration:

```powershell
python keygen.py issue --company "Client Company Name" --company-id "client-001" --days 365 --hardware-fp <fingerprint>
```

Replace the old `license.key` with the new one and restart the app.

## 4. Post-Install Checks

Start the app:

```powershell
.\start.ps1
```

Open:

```text
http://localhost:8080
```

Check the following:

- Login works with `admin` / `admin123`.
- Admin password is changed immediately.
- License page shows a valid license.
- Products page can create a test product.
- Barcode page can show/download a barcode for the test product.
- Sales page can add the test product by SKU/barcode.
- Receipt page opens after checkout and prints from the browser.
- Purchases page can record stock-in.
- Stock page reflects product quantities.
- Physical Stock and Stock Variance screens open.
- Float and Takings screens save expected cash records.
- Daily Sales, Daily Purchases, and Daily Takings reports open.
- VAT report shows standard, zero, and exempt sales behavior.
- Database Maintenance can download an encrypted backup.
- Email Settings are configured if automatic emails are required.
- Users page can create cashier accounts.
- Audit Logs record login and user-management actions.

## 5. Cloud Installation on Azure

### A. Provision resources

Typical resources:

- Azure App Service
- Azure Storage account for hosted license files and backups
- Optional Azure SQL database if the deployment uses SQL Server instead of local SQLite
- Optional custom domain and managed certificate

### B. Prepare deployment ZIP

From the application folder:

```powershell
Compress-Archive -Path `
  app.py, serve.py, license_manager.py, keygen.py, vendor_public.pem, `
  templates, static, database, pos_v3_mauritius_professional_dashboard `
  -DestinationPath pos_v3_deploy.zip
```

Do not include:

- `vendor_private.pem`
- `.venv\`
- local backup archives
- client data unless intentionally migrating

### C. Deploy to App Service

```powershell
az login
az webapp deployment source config-zip `
  --resource-group pos-v3-prod `
  --name pos-v3-clientname `
  --src pos_v3_deploy.zip
```

Set the startup command:

```text
python serve.py
```

### D. Configure application settings

In Azure Portal, open App Service > Configuration > Application settings.

| Name | Value |
|------|-------|
| `FLASK_SECRET_KEY` | Strong random value from `secrets.token_hex(32)` |
| `HOST` | `0.0.0.0` |
| `PORT` | `8080` |
| `LICENSE_ENFORCE` | `true` |
| `LICENSE_FILE` | `license.key` or an HTTPS Blob SAS URL |
| `APP_ENFORCE_BILLING` | `false` unless Stripe billing is enabled |
| `SCM_DO_BUILD_DURING_DEPLOYMENT` | `true` |

If Stripe billing is enabled, also configure the Stripe secret key, price ID, webhook secret, and customer portal settings used by the deployment.

### E. Use Azure Blob for cloud licenses

The current `license_manager.py` supports local files and HTTPS license URLs.

1. Temporarily set `LICENSE_ENFORCE=false`.
2. Browse to the app and copy the fingerprint from License.
3. Issue the license on the vendor laptop.
4. Upload the license file to Azure Blob Storage.
5. Generate a read-only SAS URL expiring no earlier than the license period.
6. Set `LICENSE_FILE` to the full SAS URL.
7. Set `LICENSE_ENFORCE=true`.
8. Restart the App Service.

Example SAS generation:

```powershell
az storage blob generate-sas `
  --account-name posv3licenses `
  --container-name licenses `
  --name client-001.key `
  --permissions r `
  --expiry 2027-06-03T23:59:00Z `
  --https-only `
  --full-uri `
  --output tsv
```

### F. Verify cloud deployment

- Open `https://pos-v3-clientname.azurewebsites.net`.
- Confirm login works.
- Confirm License is valid.
- Create a product and test a sale.
- Confirm receipts, reports, barcode tools, and backup behavior.
- Check logs if startup fails:

```powershell
az webapp log tail --name pos-v3-clientname --resource-group pos-v3-prod
```

## 6. Backup and Recovery

### Backup

- Manual backup: Database Maintenance > Download Backup.
- Backups are encrypted `.zip.enc` archives.
- The backup encryption key is derived from the license ID and company ID.
- Store backups with the related client/license metadata.

### Restore

1. Stop the application.
2. Decrypt the backup on the vendor machine:

```python
from license_manager import decrypt_backup

decrypt_backup(
    "pos_v3_backup_20260603_020000.zip.enc",
    "restored_backup.zip",
    "LICENSEID|company-id"
)
```

3. Extract `restored_backup.zip`.
4. Copy the restored `pos_v3.db` into the application folder.
5. Restart the application.
6. Verify products, sales, purchases, users, and reports.

## 7. Troubleshooting

### PowerShell will not activate the virtual environment

Run:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then activate again.

### App starts but browser cannot open it

Check:

- `HOST` and `PORT` in `start.ps1`
- Windows Firewall for the selected port
- Whether another process already uses the port

### Barcode scan does not add product

Check:

- Product SKU exactly matches the scanned barcode value.
- Scanner is in keyboard/HID mode.
- Cursor is in the Sales barcode field.
- The product is enabled and has valid price/VAT settings.

### Barcode image decoding fails

Check:

- `pyzbar` and image dependencies installed successfully.
- The uploaded image is clear and the barcode is not cropped.
- The decoded value matches an existing product SKU.

### License invalid

Check:

- The license was issued for the displayed machine fingerprint.
- `LICENSE_FILE` points to the right local file or HTTPS URL.
- The file was not renamed incorrectly.
- The license has not expired.
- For cloud SAS URLs, the SAS has not expired and has read permission.

### Backup download fails

Check:

- License is valid.
- Database file exists.
- The `backups` folder is writable.
- Email settings are complete if sending backup emails.

## 8. Quick Reference

### Default credentials

| Username | Password |
|----------|----------|
| `admin` | `admin123` |

Change the password immediately after installation.

### Common commands

```powershell
cd C:\POS\pos_v3_mauritius
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python keygen.py fingerprint
python keygen.py verify license.key
.\start.ps1
```

### URLs

| Environment | URL |
|-------------|-----|
| Local development | `http://127.0.0.1:5000` |
| On-prem production | `http://localhost:8080` |
| Local network | `http://<server-ip>:8080` |
| Azure | `https://pos-v3-clientname.azurewebsites.net` |

### Sensitive files

| File | Rule |
|------|------|
| `vendor_private.pem` | Vendor only; never ship to clients |
| `vendor_public.pem` | Safe to ship with the app |
| `license.key` | Client-specific; keep with deployment records |
| `pos_v3.db` | Client data; back up regularly |
| backup `.zip.enc` files | Store securely with license metadata |

---

Document maintained by Josea Outsourcing Ltd for internal staff use.

