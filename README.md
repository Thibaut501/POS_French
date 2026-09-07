# Mauritius POS V3 - VAT, Stock, Cash, and Barcode Dashboard

Mauritius POS V3 is a Flask-based point-of-sale dashboard for Josea Outsourcing Ltd clients. It supports Mauritius VAT handling, stock movement, cashier activity, barcode workflows, daily cash controls, encrypted backups, license enforcement, and optional Stripe billing.

## Current Feature Set

- Admin dashboard with sales, purchases, VAT, stock, and activity summaries
- Product master list with SKU/barcode values, VAT type, selling price, and stock thresholds
- Cart-based sales screen for keyboard, USB, or Bluetooth barcode scanners
- Printable receipt page after checkout
- Purchases and stock-in recording
- Automatic stock-on-hand calculation
- Low stock alerts and stock reports
- Physical stock take and stock variance review
- Barcode label generation for products
- Barcode image decoder for uploaded product/package photos
- Fidelity client registration and sales association
- Float register and daily takings controls
- Daily sales, daily purchases, and daily takings reports
- CSV exports and saved report snapshots
- Mauritius VAT output/input VAT reporting with exempt-sales apportionment
- Cashier login and per-sale activity tracking
- User administration for admin/cashier accounts
- Audit logs for login and account-management actions
- Email settings for operational notifications
- Database maintenance, encrypted backup download, and old-log purging
- License status page with machine fingerprint display
- Optional Stripe subscription billing page and webhook support

## Install

For a full client installation, use [INSTALL.md](INSTALL.md).

For local development:

```powershell
cd C:\path\to\pos_v3_mauritius_professional_dashboard
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r pos_v3_mauritius_professional_dashboard\requirements.txt
```

If you are running from the packaged application folder, install from that folder's `requirements.txt`.

## Run

Development mode from the repository root:

```powershell
python app.py
```

Production-style local run:

```powershell
.\start.ps1
```

LAN run for another computer on the same Wi-Fi/Ethernet:

```powershell
.\start-lan-server.ps1
```

The LAN launcher prints the URL to open on the other computer, such as
`http://192.168.100.3:8080`. See [LAN_ACCESS.md](LAN_ACCESS.md) for firewall
and troubleshooting steps.

Default local URLs:

```text
http://127.0.0.1:5000
http://localhost:8080
```

The exact port depends on whether you start `app.py`, `serve.py`, or `start.ps1`.

## Default Login

Default administrator account:

```text
Username: admin
Password: admin123
```

Change this password immediately after installation from the Account page.

Admin users can:

- Create cashier/admin accounts
- Reset passwords
- Enable or disable users
- Review audit logs
- Configure email settings
- Manage database backups and purge old operational data
- View billing and license status

Cashier users can access the daily operational screens assigned to them, including sales, fidelity clients, stock lookup, float, and takings.

## Barcode Scanner Workflow

1. Open Products and create or edit the product.
2. Set the product SKU to the barcode value.
3. Open Sales.
4. Click the "Scan barcode / type SKU" field.
5. Scan each item with a USB/Bluetooth scanner in keyboard/HID mode.
6. Review the cart.
7. Finalize the sale and print the receipt.

Scanners that behave like keyboards need no SDK. They enter the barcode into the focused field and the app adds the matching product to the cart.

## Barcode Generation and Decoding

- Open Barcodes to view products and download printable barcode labels.
- Use generated labels for items without manufacturer barcodes, such as prepared food or in-house products.
- Open Decode Barcode to upload an image and look up a product from a barcode visible in that image.
- The decoder is useful when checking items photographed by phone or camera.

## Scanner SDK Integration

If a scanner or mobile app posts directly to the POS, use:

```text
POST /api/scanner-sale
Content-Type: application/json
```

Example body:

```json
{
  "barcode": "1234567890123",
  "qty": 1,
  "date": "2026-04-30"
}
```

Notes:

- `barcode` matches the product SKU in the database.
- `qty` is optional and defaults to `1`.
- `date` is optional and defaults to the current date.

## VAT Logic

- Standard-rated sales: output VAT at 15%.
- Zero-rated sales: no output VAT.
- Exempt sales: no output VAT.
- Standard and zero-rated purchases: input VAT is claimable before apportionment.
- Exempt purchases: input VAT is not claimable.
- Adjusted Input VAT = Raw Input VAT x Taxable Sales / Total Sales.

## Database and Backups

- SQLite data is stored in `pos_v3.db`.
- Manual encrypted backups are available from Database Maintenance.
- Automatic backup behavior depends on the configured production environment.
- Backup encryption uses license-linked company data, so keep the license record with the client's backup archive.

## Licensing

The app supports local license files and HTTPS-hosted license files, including Azure Blob SAS URLs.

Common settings:

```powershell
$env:LICENSE_ENFORCE = "true"
$env:LICENSE_FILE = "license.key"
```

Use the License page to see the current license status and machine fingerprint.

## Key Files

| File | Purpose |
|------|---------|
| `app.py` | Main Flask application |
| `serve.py` | Waitress production entry point |
| `start.ps1` | Windows startup script |
| `pos_v3_mauritius_professional_dashboard\requirements.txt` | Python dependencies |
| `license_manager.py` | License, heartbeat, and backup encryption helpers |
| `keygen.py` | Vendor-side fingerprint/license utility |
| `vendor_public.pem` | Public key shipped with the app |
| `vendor_private.pem` | Private signing key; vendor only, never ship to clients |
| `pos_v3.db` | Local SQLite database |
