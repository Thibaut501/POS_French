"""
Production server entry point using Waitress (Windows-compatible WSGI server).

Usage:
    python serve.py

Environment variables (set before running):
    FLASK_SECRET_KEY          — required in production, e.g. a 32-char random string
    PORT                      — optional, defaults to 8080
    HOST                      — optional, defaults to 0.0.0.0 (all interfaces)
    LICENSE_FILE              — path to license.key (default: license.key)
    LICENSE_ENFORCE           — set to "false" to disable license checks (dev only)
    LICENSE_SERVER_URL        — URL of your license heartbeat server (optional)
    BACKUP_ENCRYPTION_KEY     — override backup passphrase (default: derived from license)
    VENDOR_PUBLIC_KEY_PEM     — override embedded public key (optional)

Example (PowerShell):
    $env:FLASK_SECRET_KEY = "change-this-to-a-long-random-string"
    $env:PORT = "8080"
    python serve.py
"""

import os
import threading
import schedule
import time

from waitress import serve
from app import (
    app, init_db, init_license, schedule_backup_email,
    LICENSE_ENFORCE, LICENSE_MODULE_AVAILABLE,
    _license_status, _license_on_heartbeat_failure,
)

# Ensure the secret key is set to something secure in production
if os.environ.get("FLASK_SECRET_KEY", "dev-pos-secret-change-me") == "dev-pos-secret-change-me":
    print("WARNING: FLASK_SECRET_KEY is not set. Set it via environment variable before going live.")

# Initialise the database on startup
init_db()

# ── License check ─────────────────────────────────────────────────────────────
init_license()

if LICENSE_ENFORCE and LICENSE_MODULE_AVAILABLE:
    if _license_status["valid"]:
        payload = _license_status["payload"] or {}
        print(
            f"License OK — {payload.get('company', 'Unknown')} "
            f"(ID: {payload.get('license_id', '?')}, "
            f"expires: {payload.get('expiry', '?')})"
        )
        # Start heartbeat thread — will call _license_on_heartbeat_failure on expiry
        try:
            from license_manager import start_heartbeat_thread
            start_heartbeat_thread(on_failure=_license_on_heartbeat_failure)
        except Exception as exc:
            import traceback
            print(f"LICENSE WARNING during heartbeat startup: {exc}")
            traceback.print_exc()
    else:
        print(f"LICENSE WARNING: {_license_status['error']}")
        print("License enforcement is enabled but no valid license was found.")
        print("All requests will be blocked by the license check until a valid license.key is provided.")
else:
    print("License enforcement is DISABLED (dev mode).")

# ── Backup scheduler ──────────────────────────────────────────────────────────
schedule.every().day.at("02:00").do(schedule_backup_email)
scheduler_thread = threading.Thread(target=lambda: _run_scheduler(), daemon=True)
scheduler_thread.start()


def _run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(60)


host = os.environ.get("HOST", "0.0.0.0")
port = int(os.environ.get("PORT", "8080"))

print(f"Starting POS V3 on http://{host}:{port}")
serve(app, host=host, port=port, threads=4)
