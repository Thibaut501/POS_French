from flask import Flask, render_template, request, redirect, url_for, Response, jsonify, session, send_file, g
import sqlite3
import csv
import io
import os
import hashlib
import json
import urllib.parse
import urllib.request
import urllib.error
import base64
from functools import wraps
from datetime import datetime, timedelta
import zipfile
import shutil
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import threading
import schedule
import time

try:
    from license_manager import (
        check_license, start_heartbeat_thread,
        LicenseError, encrypt_backup, get_hardware_fingerprint,
    )
    LICENSE_MODULE_AVAILABLE = True
except ImportError:
    LICENSE_MODULE_AVAILABLE = False
    LicenseError = Exception  # fallback type alias

# Set to "false" to disable license enforcement (dev/testing only)
LICENSE_ENFORCE = os.getenv("LICENSE_ENFORCE", "false").strip().lower() in ("1", "true", "yes")

# Passphrase used to encrypt backup files.
# Defaults to a value derived from the license at init time; override via env.
BACKUP_PASSPHRASE: str = os.getenv("BACKUP_ENCRYPTION_KEY", "")

# Live license status — updated by init_license() and the heartbeat thread
_license_status: dict = {"valid": False, "error": "License not yet verified", "payload": None}

try:
    import barcode  # type: ignore
    from barcode.writer import ImageWriter  # type: ignore
    BARCODE_ENABLED = True
except ImportError:
    BARCODE_ENABLED = False

try:
    from pyzbar.pyzbar import decode  # type: ignore
    from PIL import Image  # type: ignore
    BARCODE_READER_ENABLED = True
except ImportError:
    BARCODE_READER_ENABLED = False

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-pos-secret-change-me")

DB_NAME = "pos_v3.db"
VAT_RATE = 0.15

USE_AZURE_AUTH = os.getenv("USE_AZURE_AUTH", "false").strip().lower() in ("1", "true", "yes")
APP_ENFORCE_BILLING = os.getenv("APP_ENFORCE_BILLING", "false").strip().lower() in (
    "1",
    "true",
    "yes",
)
BILLING_GRACE_DAYS = int(os.getenv("BILLING_GRACE_DAYS", "7"))

OIDC_AUTHORITY = os.getenv("OIDC_AUTHORITY", "").strip()
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "").strip()
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "").strip()


# ─── License Init & Enforcement ──────────────────────────────────────────────

def init_license() -> None:
    """
    Verify the license at startup and populate _license_status.
    Also derives the backup passphrase from the license payload if not
    already set via BACKUP_ENCRYPTION_KEY.
    Call this once before starting the server.
    """
    global BACKUP_PASSPHRASE
    if not LICENSE_ENFORCE or not LICENSE_MODULE_AVAILABLE:
        _license_status.update({"valid": True, "error": None, "payload": None})
        return

    try:
        payload = check_license()
        _license_status.update({"valid": True, "error": None, "payload": payload})
        # Derive a default backup passphrase from the license if not set
        if not BACKUP_PASSPHRASE:
            BACKUP_PASSPHRASE = (
                payload.get("license_id", "") + "|" + payload.get("company_id", "")
            )
    except LicenseError as exc:
        _license_status.update({"valid": False, "error": str(exc), "payload": None})


def _license_on_heartbeat_failure(message: str) -> None:
    """Called by the heartbeat thread when the license becomes invalid."""
    _license_status.update({"valid": False, "error": message, "payload": None})


@app.before_request
def enforce_license():
    """Block all requests when LICENSE_ENFORCE=true and the license is invalid."""
    if not LICENSE_ENFORCE or not LICENSE_MODULE_AVAILABLE:
        return
    # Always allow static files and the license-status admin endpoint
    if request.endpoint in ("static", "license_status", "terms", "privacy", None):
        return
    if not _license_status["valid"]:
        error = _license_status.get("error", "License invalid or not found")
        if request.is_json or request.path.startswith("/api/"):
            return jsonify({"error": f"License error: {error}"}), 403
        return render_template("license_error.html", error=error), 403
OIDC_REDIRECT_URI = os.getenv("OIDC_REDIRECT_URI", "").strip()
OIDC_SCOPE = os.getenv("OIDC_SCOPE", "openid profile email").strip()


def oidc_is_configured():
    return all([OIDC_AUTHORITY, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI])


def fetch_oidc_metadata():
    discovery_url = OIDC_AUTHORITY.rstrip("/") + "/.well-known/openid-configuration"
    with urllib.request.urlopen(discovery_url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def _b64_decode(segment):
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode((segment + padding).encode("utf-8"))


def _jwt_header_and_payload(jwt_token):
    parts = jwt_token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT: expected 3 parts")
    header = json.loads(_b64_decode(parts[0]))
    payload = json.loads(_b64_decode(parts[1]))
    return header, payload, parts


def _fetch_jwks(jwks_uri):
    with urllib.request.urlopen(jwks_uri, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def _rsa_verify(jwt_token, jwk_key):
    """Verify RS256 JWT signature using the matching JWK public key."""
    try:
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        # cryptography package not installed - skip signature verification and warn.
        import warnings
        warnings.warn(
            "JWT signature NOT verified: install 'cryptography' package for full OIDC security.",
            stacklevel=2,
        )
        return True

    def _b64int(val):
        return int.from_bytes(_b64_decode(val), "big")

    header, _, parts = _jwt_header_and_payload(jwt_token)
    n = _b64int(jwk_key["n"])
    e = _b64int(jwk_key["e"])
    pub_key = RSAPublicNumbers(e, n).public_key(default_backend())
    message = f"{parts[0]}.{parts[1]}".encode("utf-8")
    signature = _b64_decode(parts[2])
    alg = header.get("alg", "RS256")
    if alg == "RS256":
        hash_alg = hashes.SHA256()
    elif alg == "RS384":
        hash_alg = hashes.SHA384()
    elif alg == "RS512":
        hash_alg = hashes.SHA512()
    else:
        raise ValueError(f"Unsupported JWT algorithm: {alg}")
    pub_key.verify(signature, message, rsa_padding.PKCS1v15(), hash_alg)
    return True


def validate_id_token(id_token, nonce, metadata):
    """Validate Azure B2C id_token claims and signature.

    Verifies: header alg, issuer, audience, expiry, iat, nonce, and RSA signature.
    Returns validated claims dict.
    """
    header, claims, _ = _jwt_header_and_payload(id_token)

    alg = header.get("alg", "")
    if alg not in ("RS256", "RS384", "RS512"):
        raise ValueError(f"Unexpected JWT algorithm '{alg}' — expected RS256")

    now = datetime.utcnow().timestamp()
    exp = claims.get("exp", 0)
    iat = claims.get("iat", 0)
    if now > exp:
        raise ValueError("id_token has expired")
    if now < iat - 300:  # 5 min clock-skew tolerance
        raise ValueError("id_token issued in the future")

    issuer = claims.get("iss", "")
    expected_issuer = metadata.get("issuer", OIDC_AUTHORITY.rstrip("/"))
    if issuer != expected_issuer:
        raise ValueError(f"id_token issuer mismatch: got '{issuer}'")

    aud = claims.get("aud", "")
    aud_list = aud if isinstance(aud, list) else [aud]
    if OIDC_CLIENT_ID not in aud_list:
        raise ValueError(f"id_token audience does not contain client_id")

    if nonce and claims.get("nonce", "") != nonce:
        raise ValueError("id_token nonce mismatch — possible replay attack")

    jwks_uri = metadata.get("jwks_uri", "")
    if jwks_uri:
        kid = header.get("kid", "")
        jwks = _fetch_jwks(jwks_uri)
        matching = [
            k for k in jwks.get("keys", [])
            if k.get("kty") == "RSA" and (not kid or k.get("kid") == kid)
        ]
        if not matching:
            raise ValueError(f"No matching JWK found for kid='{kid}'")
        _rsa_verify(id_token, matching[0])

    return claims


def utcnow():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def db():
    if "db" not in g:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def log_audit(conn, actor_user_id, action, target_username=None, details=None):
    conn.execute(
        """
        INSERT INTO audit_logs(event_time, actor_user_id, action, target_username, details)
        VALUES (?,?,?,?,?)
    """,
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            actor_user_id,
            action,
            target_username,
            details,
        ),
    )


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    conn = db()
    return conn.execute(
        "SELECT id, username, full_name, is_admin, is_active FROM users WHERE id=?",
        (user_id,),
    ).fetchone()


def get_db_size_mb():
    """Get database file size in MB."""
    if os.path.exists(DB_NAME):
        return os.path.getsize(DB_NAME) / (1024 * 1024)
    return 0


def should_show_db_warning():
    """Check if database size warning should be shown (> 50 MB)."""
    return get_db_size_mb() > 50


@app.context_processor
def inject_user():
    subscription = None
    company_id = session.get("company_id")
    if company_id:
        subscription = get_subscription(company_id)
    return {
        "current_user": get_current_user(),
        "db_size_warning": should_show_db_warning(),
        "db_size_mb": get_db_size_mb(),
        "subscription": subscription,
        "billing_enforced": APP_ENFORCE_BILLING,
        "now": datetime.utcnow(),
    }


def get_subscription(company_id):
    if not company_id:
        return None
    conn = db()
    try:
        return conn.execute(
            """
            SELECT status, current_period_end, grace_until, updated_at
            FROM subscriptions
            WHERE company_id=?
            ORDER BY id DESC
            LIMIT 1
        """,
            (company_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return None


def is_subscription_access_allowed(company_id):
    if not APP_ENFORCE_BILLING:
        return True, None
    subscription = get_subscription(company_id)
    if not subscription:
        return False, "No active subscription found"

    status = (subscription["status"] or "").lower()
    if status in ("active", "trialing"):
        return True, None

    if status == "past_due":
        grace_until = subscription["grace_until"]
        if grace_until:
            try:
                grace_until_dt = datetime.strptime(grace_until, "%Y-%m-%d %H:%M:%S")
                if datetime.utcnow() <= grace_until_dt:
                    return True, None
            except ValueError:
                pass

    return False, f"Subscription status '{status}' does not allow full access"


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        current_user = get_current_user()
        if not current_user or not current_user["is_active"]:
            session.clear()
            return redirect(url_for("login"))

        exempt_endpoints = {
            "billing",
            "create_checkout_session",
            "create_portal_session",
        }
        if request.endpoint not in exempt_endpoints:
            allowed, reason = is_subscription_access_allowed(session.get("company_id"))
            if not allowed:
                return redirect(url_for("billing", reason=reason or "Billing required"))

        return view_func(*args, **kwargs)

    return wrapped


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        current_user = get_current_user()
        if not current_user or not current_user["is_admin"]:
            return "Forbidden", 403
        return view_func(*args, **kwargs)

    return wrapped


def get_email_settings():
    """Retrieve email configuration from database."""
    conn = db()
    settings = {}
    rows = conn.execute("SELECT key, value FROM app_settings WHERE key LIKE 'email_%'").fetchall()
    for row in rows:
        settings[row['key']] = row['value']
    return settings


def send_email(subject, body, recipients, attachment_path=None):
    """Send an email with optional attachment."""
    try:
        settings = get_email_settings()
        
        smtp_server = settings.get('email_smtp_server', '').strip()
        smtp_port = int(settings.get('email_smtp_port', 587))
        sender_email = settings.get('email_sender', '').strip()
        sender_password = settings.get('email_password', '').strip()
        
        if not all([smtp_server, sender_email, sender_password]):
            return False, "Email not configured"
        
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        if attachment_path and os.path.exists(attachment_path):
            part = MIMEBase('application', 'octet-stream')
            with open(attachment_path, 'rb') as attachment:
                part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename= {os.path.basename(attachment_path)}')
            msg.attach(part)
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        
        return True, "Email sent successfully"
    except Exception as e:
        return False, str(e)


def scheduler_worker():
    """Background scheduler for automatic backups."""
    while True:
        schedule.run_pending()
        time.sleep(60)


def schedule_backup_email():
    """Send scheduled daily backup email with an encrypted backup attached."""
    try:
        backup_dir = "backups"
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_name = f"pos_v3_backup_{timestamp}.zip"
        zip_path = os.path.join(backup_dir, zip_name)

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(DB_NAME, arcname=DB_NAME)

        # Encrypt the zip if a passphrase is available
        if BACKUP_PASSPHRASE and LICENSE_MODULE_AVAILABLE:
            enc_name = zip_name + ".enc"
            enc_path = os.path.join(backup_dir, enc_name)
            encrypt_backup(zip_path, enc_path, BACKUP_PASSPHRASE)
            os.remove(zip_path)
            attachment = enc_path
            subject_suffix = " (encrypted)"
        else:
            attachment = zip_path
            subject_suffix = ""

        settings = get_email_settings()
        backup_email = settings.get('email_backup_recipients', '').strip()

        if backup_email:
            recipients = [e.strip() for e in backup_email.split(',') if e.strip()]
            send_email(
                subject=f"POS Backup{subject_suffix} - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                body="Automated database backup attached. Use the restore tool to decrypt.",
                recipients=recipients,
                attachment_path=attachment,
            )
    except Exception as e:
        print(f"Backup email error: {str(e)}")




def init_db():
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1
        )
    """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sku TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            brand TEXT NOT NULL DEFAULT '',
            lodgement TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL CHECK(category IN ('Standard','Zero','Exempt')),
            cost_price REAL NOT NULL DEFAULT 0,
            selling_price REAL NOT NULL DEFAULT 0,
            low_stock_level INTEGER NOT NULL DEFAULT 5
        )
    """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS purchases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            product_id INTEGER NOT NULL,
            qty INTEGER NOT NULL,
            unit_cost REAL NOT NULL,
            amount_ex_vat REAL NOT NULL DEFAULT 0,
            vat_amount REAL NOT NULL DEFAULT 0,
            total REAL NOT NULL,
            input_vat REAL NOT NULL,
            supplier_name TEXT NOT NULL DEFAULT '',
            invoice_number TEXT NOT NULL DEFAULT '',
            expiry_date TEXT NOT NULL DEFAULT '',
            contact_person TEXT NOT NULL DEFAULT '',
            contact_email TEXT NOT NULL DEFAULT '',
            contact_phone TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sales_receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            cashier_user_id INTEGER NOT NULL,
            subtotal REAL NOT NULL DEFAULT 0,
            output_vat REAL NOT NULL DEFAULT 0,
            total REAL NOT NULL DEFAULT 0,
            payment_method TEXT NOT NULL DEFAULT 'Cash',
            payment_reference TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(cashier_user_id) REFERENCES users(id)
        )
    """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            product_id INTEGER NOT NULL,
            qty INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            total REAL NOT NULL,
            output_vat REAL NOT NULL,
            receipt_id INTEGER,
            cashier_user_id INTEGER,
            FOREIGN KEY(product_id) REFERENCES products(id),
            FOREIGN KEY(receipt_id) REFERENCES sales_receipts(id),
            FOREIGN KEY(cashier_user_id) REFERENCES users(id)
        )
    """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            actor_user_id INTEGER,
            action TEXT NOT NULL,
            target_username TEXT,
            details TEXT,
            FOREIGN KEY(actor_user_id) REFERENCES users(id)
        )
    """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cash_float_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            cashier_user_id INTEGER NOT NULL,
            opening_float REAL NOT NULL DEFAULT 0,
            closing_float REAL,
            opened_at TEXT NOT NULL,
            closed_at TEXT,
            FOREIGN KEY(cashier_user_id) REFERENCES users(id)
        )
    """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS physical_stock_counts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            product_id INTEGER NOT NULL,
            physical_qty INTEGER NOT NULL,
            count_notes TEXT NOT NULL DEFAULT '',
            counted_by_user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(product_id) REFERENCES products(id),
            FOREIGN KEY(counted_by_user_id) REFERENCES users(id)
        )
    """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS companies (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL
        )
    """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS company_users (
            id TEXT PRIMARY KEY,
            company_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL DEFAULT 'cashier',
            is_active INTEGER NOT NULL DEFAULT 1,
            UNIQUE(company_id, user_id),
            FOREIGN KEY(company_id) REFERENCES companies(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS subscriptions (
            id TEXT PRIMARY KEY,
            company_id TEXT NOT NULL,
            provider TEXT NOT NULL DEFAULT 'stripe',
            provider_customer_id TEXT,
            provider_subscription_id TEXT,
            status TEXT NOT NULL DEFAULT 'trialing',
            current_period_end TEXT,
            cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
            grace_until TEXT,
            updated_at TEXT NOT NULL,
            UNIQUE(provider, provider_subscription_id),
            FOREIGN KEY(company_id) REFERENCES companies(id)
        )
    """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS billing_events (
            id TEXT PRIMARY KEY,
            company_id TEXT,
            provider TEXT NOT NULL DEFAULT 'stripe',
            provider_event_id TEXT NOT NULL UNIQUE,
            event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            processed_at TEXT,
            success INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(company_id) REFERENCES companies(id)
        )
    """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_identities (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            provider TEXT NOT NULL,
            provider_subject TEXT NOT NULL,
            email TEXT,
            last_login_at TEXT,
            UNIQUE(provider, provider_subject),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """
    )

    # Backward-compatible schema updates for old databases.
    try:
        conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE sales ADD COLUMN receipt_id INTEGER")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE sales ADD COLUMN cashier_user_id INTEGER")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE products ADD COLUMN brand TEXT NOT NULL DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE products ADD COLUMN lodgement TEXT NOT NULL DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE sales_receipts ADD COLUMN payment_method TEXT NOT NULL DEFAULT 'Cash'")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE sales_receipts ADD COLUMN payment_reference TEXT NOT NULL DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE purchases ADD COLUMN amount_ex_vat REAL NOT NULL DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE purchases ADD COLUMN vat_amount REAL NOT NULL DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE purchases ADD COLUMN supplier_name TEXT NOT NULL DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE purchases ADD COLUMN invoice_number TEXT NOT NULL DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE purchases ADD COLUMN expiry_date TEXT NOT NULL DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE purchases ADD COLUMN contact_person TEXT NOT NULL DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE purchases ADD COLUMN contact_email TEXT NOT NULL DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE purchases ADD COLUMN contact_phone TEXT NOT NULL DEFAULT ''")
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS physical_stock_counts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                product_id INTEGER NOT NULL,
                physical_qty INTEGER NOT NULL,
                count_notes TEXT NOT NULL DEFAULT '',
                counted_by_user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(product_id) REFERENCES products(id),
                FOREIGN KEY(counted_by_user_id) REFERENCES users(id)
            )
        """
        )
    except sqlite3.OperationalError:
        pass

    existing_admin = conn.execute(
        "SELECT id FROM users WHERE username='admin'"
    ).fetchone()
    if not existing_admin:
        conn.execute(
            "INSERT INTO users(username, password_hash, full_name, is_admin, is_active) VALUES (?,?,?,?,?)",
            ("admin", hash_password("admin123"), "Administrator", 1, 1),
        )
    else:
        conn.execute(
            "UPDATE users SET is_admin=1, is_active=1 WHERE username='admin'"
        )

    default_company = conn.execute("SELECT id FROM companies ORDER BY created_at LIMIT 1").fetchone()
    if not default_company:
        default_company_id = "company_default"
        conn.execute(
            "INSERT INTO companies(id, name, status, created_at) VALUES (?,?,?,?)",
            (default_company_id, "Default Company", "active", utcnow()),
        )
    else:
        default_company_id = default_company["id"]

    all_users = conn.execute("SELECT id, is_admin FROM users").fetchall()
    for user in all_users:
        exists = conn.execute(
            "SELECT id FROM company_users WHERE company_id=? AND user_id=?",
            (default_company_id, user["id"]),
        ).fetchone()
        if not exists:
            role = "admin" if user["is_admin"] else "cashier"
            conn.execute(
                "INSERT INTO company_users(id, company_id, user_id, role, is_active) VALUES (?,?,?,?,1)",
                (f"cu_{default_company_id}_{user['id']}", default_company_id, user["id"], role),
            )

    sub_exists = conn.execute(
        "SELECT id FROM subscriptions WHERE company_id=?",
        (default_company_id,),
    ).fetchone()
    if not sub_exists:
        grace_until = (datetime.utcnow() + timedelta(days=BILLING_GRACE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            """
            INSERT INTO subscriptions(id, company_id, provider, status, grace_until, updated_at)
            VALUES (?,?,?,?,?,?)
        """,
            ("sub_default", default_company_id, "stripe", "trialing", grace_until, utcnow()),
        )

    conn.commit()
    conn.close()


def current_stock(product_id):
    conn = db()
    bought = conn.execute(
        "SELECT COALESCE(SUM(qty),0) FROM purchases WHERE product_id=?",
        (product_id,),
    ).fetchone()[0]
    sold = conn.execute(
        "SELECT COALESCE(SUM(qty),0) FROM sales WHERE product_id=?",
        (product_id,),
    ).fetchone()[0]
    return int(bought - sold)


def stock_at_date(product_id, as_of_date):
    """Calculate stock at end of a specific date."""
    conn = db()
    bought = conn.execute(
        "SELECT COALESCE(SUM(qty),0) FROM purchases WHERE product_id=? AND date <= ?",
        (product_id, as_of_date),
    ).fetchone()[0]
    sold = conn.execute(
        "SELECT COALESCE(SUM(qty),0) FROM sales WHERE product_id=? AND date <= ?",
        (product_id, as_of_date),
    ).fetchone()[0]
    return int(bought - sold)


def dashboard_values():
    conn = db()
    total_sales = conn.execute("SELECT COALESCE(SUM(total),0) FROM sales").fetchone()[0]
    output_vat = conn.execute("SELECT COALESCE(SUM(output_vat),0) FROM sales").fetchone()[0]
    raw_input_vat = conn.execute("SELECT COALESCE(SUM(input_vat),0) FROM purchases").fetchone()[0]

    taxable_sales = conn.execute(
        """
        SELECT COALESCE(SUM(s.total),0)
        FROM sales s
        JOIN products p ON p.id = s.product_id
        WHERE p.category IN ('Standard','Zero')
    """
    ).fetchone()[0]

    apportionment_ratio = taxable_sales / total_sales if total_sales else 0
    adjusted_input_vat = raw_input_vat * apportionment_ratio
    vat_payable = output_vat - adjusted_input_vat

    purchase_cost = conn.execute("SELECT COALESCE(SUM(total),0) FROM purchases").fetchone()[0]
    estimated_cogs = conn.execute(
        """
        SELECT COALESCE(SUM(s.qty * p.cost_price),0)
        FROM sales s
        JOIN products p ON p.id = s.product_id
    """
    ).fetchone()[0]
    gross_profit = total_sales - estimated_cogs

    return {
        "total_sales": total_sales,
        "taxable_sales": taxable_sales,
        "output_vat": output_vat,
        "raw_input_vat": raw_input_vat,
        "apportionment_ratio": apportionment_ratio,
        "adjusted_input_vat": adjusted_input_vat,
        "vat_payable": vat_payable,
        "purchase_cost": purchase_cost,
        "estimated_cogs": estimated_cogs,
        "gross_profit": gross_profit,
    }


def create_sale(conn, product, qty, date, cashier_user_id=None, receipt_id=None, commit=True):
    available = current_stock(product["id"])
    if qty <= 0:
        raise ValueError("Quantity must be positive")
    if available < qty:
        raise ValueError(f"Not enough stock. Available: {available}")

    unit_price = float(product["selling_price"])
    total = qty * unit_price
    output_vat = total * VAT_RATE if product["category"] == "Standard" else 0

    conn.execute(
        """
        INSERT INTO sales(date, product_id, qty, unit_price, total, output_vat, receipt_id, cashier_user_id)
        VALUES (?,?,?,?,?,?,?,?)
    """,
        (date, product["id"], qty, unit_price, total, output_vat, receipt_id, cashier_user_id),
    )
    if commit:
        conn.commit()
    return {"total": total, "output_vat": output_vat, "unit_price": unit_price}


def get_or_create_cart():
    if "sales_cart" not in session:
        session["sales_cart"] = []
    return session["sales_cart"]


def find_product(conn, barcode, product_id_raw):
    if barcode:
        return conn.execute("SELECT * FROM products WHERE sku=?", (barcode,)).fetchone()
    if product_id_raw:
        return conn.execute("SELECT * FROM products WHERE id=?", (int(product_id_raw),)).fetchone()
    return None


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    init_db()
    error = None

    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if USE_AZURE_AUTH:
        if not oidc_is_configured():
            return "Azure authentication is enabled but OIDC env variables are missing", 500
        try:
            metadata = fetch_oidc_metadata()
            state = hashlib.sha256(os.urandom(24)).hexdigest()
            nonce = hashlib.sha256(os.urandom(24)).hexdigest()
            session["oidc_state"] = state
            session["oidc_nonce"] = nonce

            params = {
                "client_id": OIDC_CLIENT_ID,
                "response_type": "code",
                "redirect_uri": OIDC_REDIRECT_URI,
                "response_mode": "query",
                "scope": OIDC_SCOPE,
                "state": state,
                "nonce": nonce,
            }
            auth_url = metadata["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)
            return redirect(auth_url)
        except Exception as exc:
            return f"OIDC authorization redirect failed: {exc}", 500

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not request.form.get("terms_accepted"):
            error = "You must accept the Terms of Use and Privacy Policy to continue."
            return render_template("login.html", error=error)

        conn = db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=? AND password_hash=? AND is_active=1",
            (username, hash_password(password)),
        ).fetchone()

        if not user:
            error = "Invalid username or password"
        else:
            session["user_id"] = user["id"]
            session["sales_cart"] = []
            log_audit(conn, user["id"], "login", user["username"], "User logged in (terms accepted)")
            conn.commit()
            return redirect(url_for("dashboard"))

    return render_template("login.html", error=error)


def upsert_oidc_user(oidc_claims):
    provider_subject = oidc_claims.get("oid") or oidc_claims.get("sub")
    if not provider_subject:
        raise ValueError("OIDC token does not contain oid/sub claim")

    email = oidc_claims.get("email")
    if not email:
        emails = oidc_claims.get("emails")
        if isinstance(emails, list) and emails:
            email = emails[0]
    username = (email or f"user_{provider_subject[:8]}").lower()
    full_name = oidc_claims.get("name") or username

    conn = db()
    identity = conn.execute(
        "SELECT user_id FROM auth_identities WHERE provider='azure_b2c' AND provider_subject=?",
        (provider_subject,),
    ).fetchone()

    if identity:
        user_id = identity["user_id"]
        conn.execute(
            "UPDATE auth_identities SET email=?, last_login_at=? WHERE provider='azure_b2c' AND provider_subject=?",
            (email or "", utcnow(), provider_subject),
        )
    else:
        existing = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if existing:
            user_id = existing["id"]
        else:
            conn.execute(
                "INSERT INTO users(username, password_hash, full_name, is_admin, is_active) VALUES (?,?,?,?,1)",
                (username, hash_password(hashlib.sha256(os.urandom(16)).hexdigest()), full_name, 0),
            )
            user_id = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]

        conn.execute(
            """
            INSERT INTO auth_identities(id, user_id, provider, provider_subject, email, last_login_at)
            VALUES (?,?,?,?,?,?)
        """,
            (f"aid_{provider_subject[:18]}", user_id, "azure_b2c", provider_subject, email or "", utcnow()),
        )

    company = conn.execute("SELECT id FROM companies ORDER BY created_at LIMIT 1").fetchone()
    if not company:
        raise ValueError("No company configured")
    company_id = company["id"]

    company_user = conn.execute(
        "SELECT role FROM company_users WHERE company_id=? AND user_id=? AND is_active=1",
        (company_id, user_id),
    ).fetchone()
    if not company_user:
        conn.execute(
            "INSERT INTO company_users(id, company_id, user_id, role, is_active) VALUES (?,?,?,?,1)",
            (f"cu_{company_id}_{user_id}", company_id, user_id, "cashier"),
        )
        role = "cashier"
    else:
        role = company_user["role"]

    conn.commit()
    return user_id, company_id, role


@app.route("/auth/callback")
def auth_callback():
    if not USE_AZURE_AUTH:
        return redirect(url_for("login"))

    state = request.args.get("state", "")
    code = request.args.get("code", "")
    if not state or not code or state != session.get("oidc_state"):
        session.clear()
        return "Invalid OIDC callback state", 400

    try:
        metadata = fetch_oidc_metadata()
        payload = urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "client_id": OIDC_CLIENT_ID,
                "client_secret": OIDC_CLIENT_SECRET,
                "redirect_uri": OIDC_REDIRECT_URI,
                "code": code,
            }
        ).encode("utf-8")
        token_request = urllib.request.Request(
            metadata["token_endpoint"],
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(token_request, timeout=15) as response:
            token_response = json.loads(response.read().decode("utf-8"))

        id_token = token_response.get("id_token")
        if not id_token:
            return "OIDC token response missing id_token", 400

        saved_nonce = session.get("oidc_nonce", "")
        claims = validate_id_token(id_token, saved_nonce, metadata)
        user_id, company_id, role = upsert_oidc_user(claims)
        session["user_id"] = user_id
        session["company_id"] = company_id
        session["role"] = role
        session.pop("oidc_state", None)
        session.pop("oidc_nonce", None)
        return redirect(url_for("dashboard"))
    except urllib.error.HTTPError as http_err:
        return f"OIDC token exchange failed: {http_err}", 400
    except Exception as exc:
        return f"Authentication failed: {exc}", 500


@app.route("/logout")
def logout():
    user = get_current_user()
    if user:
        conn = db()
        log_audit(conn, user["id"], "logout", user["username"], "User logged out")
        conn.commit()
    session.clear()

    if USE_AZURE_AUTH and oidc_is_configured():
        try:
            metadata = fetch_oidc_metadata()
            post_logout = urllib.parse.urlencode({"post_logout_redirect_uri": url_for("login", _external=True)})
            return redirect(metadata.get("end_session_endpoint", url_for("login", _external=True)) + "?" + post_logout)
        except Exception:
            pass

    return redirect(url_for("login"))


@app.route("/billing")
@login_required
def billing():
    company_id = session.get("company_id")
    subscription = get_subscription(company_id)
    reason = request.args.get("reason", "")
    return render_template("billing.html", subscription=subscription, reason=reason)


@app.route("/billing/create-checkout-session", methods=["POST"])
@login_required
@admin_required
def create_checkout_session():
    stripe_key = os.getenv("STRIPE_SECRET_KEY", "").strip()
    if not stripe_key:
        return jsonify({"ok": False, "error": "STRIPE_SECRET_KEY is not configured"}), 500

    price_id = request.form.get("price_id", "").strip()
    if not price_id:
        price_id = os.getenv("STRIPE_DEFAULT_PRICE_ID", "").strip()
    if not price_id:
        return jsonify({"ok": False, "error": "No Stripe price_id provided and STRIPE_DEFAULT_PRICE_ID not set"}), 400

    try:
        import stripe  # type: ignore
        stripe.api_key = stripe_key

        company_id = session.get("company_id")
        sub_row = get_subscription(company_id)
        customer_id = None
        if sub_row and sub_row["provider_customer_id"] if hasattr(sub_row, 'keys') and 'provider_customer_id' in sub_row.keys() else None:
            customer_id = sub_row["provider_customer_id"]

        checkout_params = {
            "mode": "subscription",
            "line_items": [{"price": price_id, "quantity": 1}],
            "success_url": url_for("billing", _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
            "cancel_url": url_for("billing", _external=True),
            "allow_promotion_codes": True,
            "billing_address_collection": "auto",
        }
        if customer_id:
            checkout_params["customer"] = customer_id
        else:
            current_user = get_current_user()
            if current_user:
                checkout_params["customer_email"] = current_user["username"]

        checkout_session = stripe.checkout.Session.create(**checkout_params)
        return redirect(checkout_session.url, code=303)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/billing/create-portal-session", methods=["POST"])
@login_required
@admin_required
def create_portal_session():
    stripe_key = os.getenv("STRIPE_SECRET_KEY", "").strip()
    if not stripe_key:
        return jsonify({"ok": False, "error": "STRIPE_SECRET_KEY is not configured"}), 500

    company_id = session.get("company_id")
    sub_row = get_subscription(company_id)

    customer_id = None
    if sub_row:
        try:
            customer_id = sub_row["provider_customer_id"]
        except (KeyError, TypeError):
            pass

    if not customer_id:
        return jsonify({"ok": False, "error": "No Stripe customer found for this company. Complete a checkout first."}), 400

    try:
        import stripe  # type: ignore
        stripe.api_key = stripe_key
        portal_session = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=url_for("billing", _external=True),
        )
        return redirect(portal_session.url, code=303)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    stripe_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
    payload = request.data.decode("utf-8")
    signature = request.headers.get("Stripe-Signature", "")

    if not stripe_secret:
        return jsonify({"ok": False, "error": "STRIPE_WEBHOOK_SECRET is not configured"}), 500

    try:
        import stripe  # type: ignore
    except ImportError:
        return jsonify({"ok": False, "error": "stripe package is not installed"}), 500

    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=signature, secret=stripe_secret)
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Invalid Stripe signature: {exc}"}), 400

    conn = db()
    event_id = event.get("id")
    event_type = event.get("type")

    existing = conn.execute(
        "SELECT id FROM billing_events WHERE provider='stripe' AND provider_event_id=?",
        (event_id,),
    ).fetchone()
    if existing:
        return jsonify({"ok": True, "deduplicated": True})

    obj = event.get("data", {}).get("object", {})
    subscription_id = obj.get("subscription") or obj.get("id")
    customer_id = obj.get("customer")
    status = obj.get("status")
    current_period_end = obj.get("current_period_end")

    company = conn.execute("SELECT id FROM companies ORDER BY created_at LIMIT 1").fetchone()
    company_id = company["id"] if company else None

    conn.execute(
        """
        INSERT INTO billing_events(id, company_id, provider, provider_event_id, event_type, payload_json, processed_at, success)
        VALUES (?,?,?,?,?,?,?,0)
    """,
        (f"be_{event_id[:20]}", company_id, "stripe", event_id, event_type, payload, utcnow()),
    )

    if company_id and event_type in (
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "checkout.session.completed",
        "invoice.payment_failed",
        "invoice.paid",
    ):
        if event_type == "invoice.payment_failed":
            status = "past_due"
        elif event_type == "invoice.paid" and status != "active":
            status = "active"

        grace_until = None
        if status == "past_due":
            grace_until = (datetime.utcnow() + timedelta(days=BILLING_GRACE_DAYS)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        existing_sub = conn.execute(
            "SELECT id FROM subscriptions WHERE provider='stripe' AND provider_subscription_id=?",
            (subscription_id,),
        ).fetchone()
        if existing_sub:
            conn.execute(
                """
                UPDATE subscriptions
                SET provider_customer_id=?, status=?, current_period_end=?, grace_until=?, updated_at=?
                WHERE id=?
            """,
                (
                    customer_id,
                    status or "active",
                    datetime.utcfromtimestamp(current_period_end).strftime("%Y-%m-%d %H:%M:%S")
                    if isinstance(current_period_end, int)
                    else None,
                    grace_until,
                    utcnow(),
                    existing_sub["id"],
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO subscriptions(id, company_id, provider, provider_customer_id, provider_subscription_id,
                    status, current_period_end, grace_until, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?)
            """,
                (
                    f"sub_{event_id[:18]}",
                    company_id,
                    "stripe",
                    customer_id,
                    subscription_id,
                    status or "active",
                    datetime.utcfromtimestamp(current_period_end).strftime("%Y-%m-%d %H:%M:%S")
                    if isinstance(current_period_end, int)
                    else None,
                    grace_until,
                    utcnow(),
                ),
            )

    conn.execute(
        "UPDATE billing_events SET success=1, processed_at=? WHERE provider='stripe' AND provider_event_id=?",
        (utcnow(), event_id),
    )
    conn.commit()
    return jsonify({"ok": True})


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    error = None
    success = None
    current_user = get_current_user()

    if request.method == "POST":
        try:
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            if len(new_password) < 6:
                raise ValueError("New password must be at least 6 characters")
            if new_password != confirm_password:
                raise ValueError("New password and confirmation do not match")

            conn = db()
            user = conn.execute(
                "SELECT * FROM users WHERE id=? AND password_hash=?",
                (current_user["id"], hash_password(current_password)),
            ).fetchone()
            if not user:
                raise ValueError("Current password is incorrect")

            conn.execute(
                "UPDATE users SET password_hash=? WHERE id=?",
                (hash_password(new_password), current_user["id"]),
            )
            log_audit(
                conn,
                current_user["id"],
                "change_own_password",
                current_user["username"],
                "User changed own password",
            )
            conn.commit()
            success = "Password updated successfully"
        except Exception as e:
            error = str(e)

    return render_template("account.html", error=error, success=success)


@app.route("/users", methods=["GET", "POST"])
@login_required
@admin_required
def users():
    conn = db()
    error = None
    success = None

    if request.method == "POST":
        action = request.form.get("action", "create")
        try:
            if action == "create":
                username = request.form.get("username", "").strip()
                full_name = request.form.get("full_name", "").strip()
                password = request.form.get("password", "")
                is_admin = 1 if request.form.get("is_admin") == "on" else 0

                if not username or not full_name:
                    raise ValueError("Username and full name are required")
                if len(password) < 6:
                    raise ValueError("Password must be at least 6 characters")

                conn.execute(
                    """
                    INSERT INTO users(username, password_hash, full_name, is_admin, is_active)
                    VALUES (?,?,?,?,1)
                """,
                    (username, hash_password(password), full_name, is_admin),
                )
                actor = get_current_user()
                role_text = "admin" if is_admin else "cashier"
                log_audit(
                    conn,
                    actor["id"],
                    "create_user",
                    username,
                    f"Created {role_text} user",
                )
                conn.commit()
                success = f"User '{username}' created"

            elif action == "reset_password":
                user_id = int(request.form.get("user_id") or 0)
                new_password = request.form.get("new_password", "")
                if len(new_password) < 6:
                    raise ValueError("New password must be at least 6 characters")

                target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
                if not target:
                    raise ValueError("User not found")

                conn.execute(
                    "UPDATE users SET password_hash=? WHERE id=?",
                    (hash_password(new_password), user_id),
                )
                actor = get_current_user()
                log_audit(
                    conn,
                    actor["id"],
                    "reset_password",
                    target["username"],
                    "Admin reset user password",
                )
                conn.commit()
                success = f"Password reset for {target['username']}"

            elif action == "toggle_active":
                user_id = int(request.form.get("user_id") or 0)
                target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
                if not target:
                    raise ValueError("User not found")

                current_user = get_current_user()
                if target["id"] == current_user["id"]:
                    raise ValueError("You cannot disable your own account")

                new_active = 0 if target["is_active"] else 1
                if target["is_admin"] and new_active == 0:
                    active_admin_count = conn.execute(
                        "SELECT COUNT(*) FROM users WHERE is_admin=1 AND is_active=1"
                    ).fetchone()[0]
                    if active_admin_count <= 1:
                        raise ValueError("At least one active admin is required")

                conn.execute("UPDATE users SET is_active=? WHERE id=?", (new_active, user_id))
                actor = get_current_user()
                log_audit(
                    conn,
                    actor["id"],
                    "toggle_user_status",
                    target["username"],
                    "Enabled user" if new_active == 1 else "Disabled user",
                )
                conn.commit()
                success = (
                    f"User {target['username']} disabled"
                    if new_active == 0
                    else f"User {target['username']} enabled"
                )
        except sqlite3.IntegrityError:
            error = "Username already exists"
        except Exception as e:
            error = str(e)

    user_rows = conn.execute(
        "SELECT id, username, full_name, is_admin, is_active FROM users ORDER BY username"
    ).fetchall()
    return render_template("users.html", user_rows=user_rows, error=error, success=success)


@app.route("/audit-logs")
@login_required
@admin_required
def audit_logs():
    conn = db()
    rows = conn.execute(
        """
        SELECT a.event_time, a.action, a.target_username, a.details, u.username AS actor_username
        FROM audit_logs a
        LEFT JOIN users u ON u.id=a.actor_user_id
        ORDER BY a.id DESC
        LIMIT 500
    """
    ).fetchall()
    return render_template("audit_logs.html", rows=rows)


@app.route("/barcodes")
@login_required
def barcodes():
    conn = db()
    products = conn.execute("SELECT * FROM products ORDER BY name").fetchall()
    return render_template("barcodes.html", products=products, barcode_enabled=BARCODE_ENABLED)


@app.route("/barcode/<int:product_id>")
@login_required
def generate_barcode(product_id):
    """Generate and return barcode image for a product."""
    if not BARCODE_ENABLED:
        return "Barcode generation not available", 503

    conn = db()
    product = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    if not product:
        return "Product not found", 404

    sku = product["sku"]
    format_type = request.args.get("format", "png")  # png or pdf

    try:
        output = io.BytesIO()
        code = barcode.get_barcode_class("code128")(sku, writer=ImageWriter())
        code.write(output, options={"module_height": 10})
        output.seek(0)

        mimetype = "image/png" if format_type == "png" else "application/pdf"
        return send_file(
            output,
            mimetype=mimetype,
            as_attachment=True,
            download_name=f"barcode_{sku}.png",
        )
    except Exception as e:
        return f"Error generating barcode: {str(e)}", 500


@app.route("/barcode-decoder", methods=["GET", "POST"])
@login_required
def barcode_decoder():
    """Decode barcode from uploaded image."""
    result = None
    error = None
    product = None

    if request.method == "POST" and BARCODE_READER_ENABLED:
        if "barcode_image" not in request.files:
            error = "No image uploaded"
        else:
            try:
                file = request.files["barcode_image"]
                if file.filename == "":
                    error = "No file selected"
                else:
                    image = Image.open(file)
                    barcodes_found = decode(image)

                    if not barcodes_found:
                        error = "No barcode detected in image"
                    else:
                        sku = barcodes_found[0].data.decode("utf-8")
                        conn = db()
                        product = conn.execute(
                            "SELECT * FROM products WHERE sku=?", (sku,)
                        ).fetchone()

                        if not product:
                            error = f"No product found for barcode: {sku}"
                        else:
                            result = {
                                "sku": product["sku"],
                                "name": product["name"],
                                "category": product["category"],
                                "selling_price": product["selling_price"],
                            }
            except Exception as e:
                error = f"Error processing image: {str(e)}"

    elif request.method == "POST" and not BARCODE_READER_ENABLED:
        error = "Barcode decoder not available (pyzbar library not installed)"

    return render_template(
        "barcode_decoder.html",
        result=result,
        error=error,
        barcode_reader_enabled=BARCODE_READER_ENABLED,
    )


@app.route("/")
@login_required
def dashboard():
    conn = db()
    values = dashboard_values()
    products = conn.execute("SELECT * FROM products ORDER BY name").fetchall()
    stock_rows = []
    for p in products:
        stock_qty = current_stock(p["id"])
        stock_rows.append(
            {
                "sku": p["sku"],
                "name": p["name"],
                "category": p["category"],
                "stock": stock_qty,
                "low": stock_qty <= p["low_stock_level"],
            }
        )

    recent_sales = conn.execute(
        """
        SELECT s.date, p.name, s.qty, s.total, s.output_vat, u.username AS cashier_username, s.receipt_id
        FROM sales s
        JOIN products p ON p.id=s.product_id
        LEFT JOIN users u ON u.id=s.cashier_user_id
        ORDER BY s.id DESC LIMIT 8
    """
    ).fetchall()
    return render_template(
        "dashboard.html",
        values=values,
        stock_rows=stock_rows,
        recent_sales=recent_sales,
    )


@app.route("/products", methods=["GET", "POST"])
@login_required
def products():
    conn = db()
    error = None

    if request.method == "POST":
        try:
            sku = request.form["sku"].strip()
            name = request.form["name"].strip()
            brand = request.form.get("brand", "").strip()
            lodgement = request.form.get("lodgement", "").strip()
            category = request.form["category"]
            cost_price = float(request.form["cost_price"])
            selling_price = float(request.form["selling_price"])
            low_stock_level = int(request.form["low_stock_level"])

            conn.execute(
                """
                INSERT INTO products(sku, name, brand, lodgement, category, cost_price, selling_price, low_stock_level)
                VALUES (?,?,?,?,?,?,?,?)
            """,
                (sku, name, brand, lodgement, category, cost_price, selling_price, low_stock_level),
            )
            conn.commit()
            return redirect(url_for("products"))
        except Exception as e:
            error = f"Could not add product: {e}"

    rows = conn.execute(
        """
        SELECT p.*,
               (SELECT COUNT(*) FROM sales s WHERE s.product_id = p.id) AS sales_count,
               (SELECT COUNT(*) FROM purchases pu WHERE pu.product_id = p.id) AS purchases_count
        FROM products p
        ORDER BY p.name
    """
    ).fetchall()
    return render_template("products.html", products=rows, error=error)


@app.route("/products/<int:product_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit_product(product_id):
    conn = db()
    product = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    if not product:
        return "Product not found", 404

    error = None
    if request.method == "POST":
        try:
            sku = request.form["sku"].strip()
            name = request.form["name"].strip()
            brand = request.form.get("brand", "").strip()
            lodgement = request.form.get("lodgement", "").strip()
            category = request.form["category"]
            cost_price = float(request.form["cost_price"])
            selling_price = float(request.form["selling_price"])
            low_stock_level = int(request.form["low_stock_level"])

            conn.execute(
                """
                UPDATE products SET sku=?, name=?, brand=?, lodgement=?, category=?, cost_price=?, selling_price=?, low_stock_level=?
                WHERE id=?
            """,
                (sku, name, brand, lodgement, category, cost_price, selling_price, low_stock_level, product_id),
            )
            conn.commit()
            return redirect(url_for("products"))
        except sqlite3.IntegrityError:
            error = "SKU already used by another product"
        except Exception as e:
            error = f"Could not update product: {e}"

    return render_template("edit_product.html", product=product, error=error)


@app.route("/products/<int:product_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_product(product_id):
    conn = db()
    product = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    if not product:
        return "Product not found", 404

    # Prevent deletion if product has any sales or purchases
    sales_count = conn.execute(
        "SELECT COUNT(*) FROM sales WHERE product_id=?", (product_id,)
    ).fetchone()[0]
    purchases_count = conn.execute(
        "SELECT COUNT(*) FROM purchases WHERE product_id=?", (product_id,)
    ).fetchone()[0]

    if sales_count > 0 or purchases_count > 0:
        rows = conn.execute(
            """
            SELECT p.*,
                   (SELECT COUNT(*) FROM sales s WHERE s.product_id = p.id) AS sales_count,
                   (SELECT COUNT(*) FROM purchases pu WHERE pu.product_id = p.id) AS purchases_count
            FROM products p
            ORDER BY p.name
        """
        ).fetchall()
        return render_template(
            "products.html",
            products=rows,
            error=f"Cannot delete '{product['name']}' — it has {sales_count} sale(s) and {purchases_count} purchase(s) on record.",
        )

    conn.execute("DELETE FROM products WHERE id=?", (product_id,))
    conn.commit()
    return redirect(url_for("products"))


@app.route("/sales", methods=["GET", "POST"])
@login_required
def sales():
    conn = db()
    error = None
    cart = get_or_create_cart()

    if request.method == "POST":
        action = request.form.get("action", "add")
        date = request.form.get("date") or datetime.today().strftime("%Y-%m-%d")

        try:
            if action == "clear":
                session["sales_cart"] = []
                session.modified = True
                return redirect(url_for("sales"))

            if action == "remove":
                product_id_to_remove = int(request.form.get("remove_product_id") or 0)
                session["sales_cart"] = [i for i in cart if i["product_id"] != product_id_to_remove]
                session.modified = True
                return redirect(url_for("sales"))

            if action == "finalize":
                if not cart:
                    raise ValueError("Cart is empty")

                product_totals = {}
                for item in cart:
                    product_totals[item["product_id"]] = (
                        product_totals.get(item["product_id"], 0) + int(item["qty"])
                    )

                for product_id, qty in product_totals.items():
                    available = current_stock(product_id)
                    if available < qty:
                        product = conn.execute(
                            "SELECT name FROM products WHERE id=?", (product_id,)
                        ).fetchone()
                        name = product["name"] if product else f"ID {product_id}"
                        raise ValueError(
                            f"Not enough stock for {name}. Requested: {qty}, Available: {available}"
                        )

                cashier_user_id = session.get("user_id")
                payment_method = request.form.get("payment_method", "Cash").strip()
                payment_reference = request.form.get("payment_reference", "").strip()
                receipt_cursor = conn.execute(
                    """
                    INSERT INTO sales_receipts(date, cashier_user_id, subtotal, output_vat, total, payment_method, payment_reference)
                    VALUES (?,?,?,?,?,?,?)
                """,
                    (date, cashier_user_id, 0, 0, 0, payment_method, payment_reference),
                )
                receipt_id = receipt_cursor.lastrowid

                subtotal = 0
                output_vat = 0
                for item in cart:
                    product = conn.execute(
                        "SELECT * FROM products WHERE id=?", (item["product_id"],)
                    ).fetchone()
                    if not product:
                        raise ValueError("Product in cart no longer exists")

                    result = create_sale(
                        conn,
                        product,
                        int(item["qty"]),
                        date,
                        cashier_user_id=cashier_user_id,
                        receipt_id=receipt_id,
                        commit=False,
                    )
                    subtotal += result["total"]
                    output_vat += result["output_vat"]

                conn.execute(
                    "UPDATE sales_receipts SET subtotal=?, output_vat=?, total=? WHERE id=?",
                    (subtotal, output_vat, subtotal, receipt_id),
                )
                conn.commit()

                session["sales_cart"] = []
                session.modified = True
                return redirect(url_for("receipt", receipt_id=receipt_id))

            barcode = request.form.get("barcode", "").strip()
            product_id_raw = request.form.get("product_id", "").strip()
            qty = int(request.form.get("qty") or 1)

            product = find_product(conn, barcode, product_id_raw)
            if not product:
                raise ValueError("Product not found for scanned barcode/SKU")
            if qty <= 0:
                raise ValueError("Quantity must be positive")

            for item in cart:
                if item["product_id"] == product["id"]:
                    item["qty"] += qty
                    break
            else:
                cart.append(
                    {
                        "product_id": product["id"],
                        "sku": product["sku"],
                        "name": product["name"],
                        "brand": product["brand"] if product["brand"] else "",
                        "lodgement": product["lodgement"] if product["lodgement"] else "",
                        "category": product["category"],
                        "unit_price": float(product["selling_price"]),
                        "qty": qty,
                    }
                )

            session["sales_cart"] = cart
            session.modified = True
            return redirect(url_for("sales"))
        except Exception as e:
            error = str(e)

    products = conn.execute("SELECT * FROM products ORDER BY name").fetchall()
    rows = conn.execute(
        """
        SELECT s.*, p.name, p.sku, p.category, u.username AS cashier_username
        FROM sales s
        JOIN products p ON p.id=s.product_id
        LEFT JOIN users u ON u.id=s.cashier_user_id
        ORDER BY s.id DESC LIMIT 50
    """
    ).fetchall()

    cart_rows = []
    cart_total = 0
    cart_vat = 0
    for item in cart:
        line_total = item["qty"] * float(item["unit_price"])
        line_vat = line_total * VAT_RATE if item["category"] == "Standard" else 0
        cart_total += line_total
        cart_vat += line_vat
        cart_rows.append(
            {
                "product_id": item["product_id"],
                "sku": item["sku"],
                "name": item["name"],
                "brand": item.get("brand", ""),
                "lodgement": item.get("lodgement", ""),
                "qty": item["qty"],
                "unit_price": item["unit_price"],
                "line_total": line_total,
                "line_vat": line_vat,
            }
        )

    return render_template(
        "sales.html",
        products=products,
        rows=rows,
        error=error,
        today=datetime.today().strftime("%Y-%m-%d"),
        cart_rows=cart_rows,
        cart_total=cart_total,
        cart_vat=cart_vat,
        payment_methods=PAYMENT_METHODS,
    )


@app.route("/receipt/<int:receipt_id>")
@login_required
def receipt(receipt_id):
    conn = db()
    receipt_row = conn.execute(
        """
        SELECT r.*, u.username, u.full_name
        FROM sales_receipts r
        JOIN users u ON u.id=r.cashier_user_id
        WHERE r.id=?
    """,
        (receipt_id,),
    ).fetchone()

    if not receipt_row:
        return "Receipt not found", 404

    items = conn.execute(
        """
        SELECT s.qty, s.unit_price, s.total, s.output_vat,
               p.sku, p.name, p.brand, p.lodgement, p.category
        FROM sales s
        JOIN products p ON p.id=s.product_id
        WHERE s.receipt_id=?
        ORDER BY s.id
    """,
        (receipt_id,),
    ).fetchall()

    return render_template("receipt.html", receipt=receipt_row, items=items)


@app.route("/api/scanner-sale", methods=["POST"])
@login_required
def scanner_sale():
    """API hook for custom scanner SDK integrations.

    Expected JSON body:
    {"barcode": "123456789", "qty": 1, "date": "YYYY-MM-DD"}
    """
    conn = db()
    payload = request.get_json(silent=True) or {}

    try:
        barcode = str(payload.get("barcode", "")).strip()
        qty = int(payload.get("qty") or 1)
        date = payload.get("date") or datetime.today().strftime("%Y-%m-%d")

        if not barcode:
            return jsonify({"ok": False, "error": "barcode is required"}), 400

        product = conn.execute("SELECT * FROM products WHERE sku=?", (barcode,)).fetchone()
        if not product:
            return jsonify({"ok": False, "error": "Product not found for barcode/SKU"}), 404

        cashier_user_id = session.get("user_id")
        receipt_cursor = conn.execute(
            """
            INSERT INTO sales_receipts(date, cashier_user_id, subtotal, output_vat, total, payment_method, payment_reference)
            VALUES (?,?,?,?,?,?,?)
        """,
            (date, cashier_user_id, 0, 0, 0, "Cash", ""),
        )
        receipt_id = receipt_cursor.lastrowid

        result = create_sale(
            conn,
            product,
            qty,
            date,
            cashier_user_id=cashier_user_id,
            receipt_id=receipt_id,
            commit=False,
        )
        conn.execute(
            "UPDATE sales_receipts SET subtotal=?, output_vat=?, total=? WHERE id=?",
            (result["total"], result["output_vat"], result["total"], receipt_id),
        )
        conn.commit()

        return jsonify(
            {
                "ok": True,
                "receipt_id": receipt_id,
                "product": {
                    "id": product["id"],
                    "sku": product["sku"],
                    "name": product["name"],
                },
                "qty": qty,
                "date": date,
                "unit_price": result["unit_price"],
                "total": result["total"],
                "output_vat": result["output_vat"],
                "cashier": get_current_user()["username"],
            }
        )
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": f"Unexpected error: {e}"}), 500


@app.route("/purchases", methods=["GET", "POST"])
@login_required
def purchases():
    conn = db()
    error = None

    if request.method == "POST":
        try:
            product_id = int(request.form["product_id"])
            qty = int(request.form["qty"])
            date = request.form["date"] or datetime.today().strftime("%Y-%m-%d")
            product = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
            if not product:
                raise ValueError("Product not found")
            if qty <= 0:
                raise ValueError("Quantity must be positive")

            unit_cost = float(request.form["unit_cost"] or product["cost_price"])
            total = qty * unit_cost
            input_vat = total * VAT_RATE if product["category"] in ("Standard", "Zero") else 0
            amount_ex_vat = total - input_vat
            vat_amount = input_vat

            supplier_name = request.form.get("supplier_name", "").strip()
            invoice_number = request.form.get("invoice_number", "").strip()
            expiry_date = request.form.get("expiry_date", "").strip()
            contact_person = request.form.get("contact_person", "").strip()
            contact_email = request.form.get("contact_email", "").strip()
            contact_phone = request.form.get("contact_phone", "").strip()

            conn.execute(
                """
                INSERT INTO purchases(date, product_id, qty, unit_cost, amount_ex_vat, vat_amount,
                    total, input_vat, supplier_name, invoice_number, expiry_date,
                    contact_person, contact_email, contact_phone)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
                (date, product_id, qty, unit_cost, amount_ex_vat, vat_amount,
                 total, input_vat, supplier_name, invoice_number, expiry_date,
                 contact_person, contact_email, contact_phone),
            )
            conn.commit()
            return redirect(url_for("purchases"))
        except Exception as e:
            error = str(e)

    products = conn.execute("SELECT * FROM products ORDER BY name").fetchall()
    rows = conn.execute(
        """
        SELECT pu.*, p.name, p.sku, p.category
        FROM purchases pu JOIN products p ON p.id=pu.product_id
        ORDER BY pu.id DESC LIMIT 30
    """
    ).fetchall()
    return render_template(
        "purchases.html",
        products=products,
        rows=rows,
        error=error,
        today=datetime.today().strftime("%Y-%m-%d"),
    )


@app.route("/stock")
@login_required
def stock():
    conn = db()
    products = conn.execute("SELECT * FROM products ORDER BY name").fetchall()
    rows = []
    for p in products:
        qty = current_stock(p["id"])
        rows.append(
            {
                "product": p,
                "stock": qty,
                "low": qty <= p["low_stock_level"],
                "negative": qty < 0,
            }
        )
    return render_template("stock.html", rows=rows)


@app.route("/vat")
@login_required
def vat():
    return render_template("vat.html", values=dashboard_values())


@app.route("/reports")
@login_required
def reports():
    conn = db()
    today = datetime.today().strftime("%Y-%m-%d")
    from_date = request.args.get("from_date") or today
    to_date = request.args.get("to_date") or today

    # Sales summary
    sales_summary = conn.execute(
        """
        SELECT p.sku, p.name, p.category,
               SUM(s.qty) AS total_qty,
               SUM(s.total) AS total_revenue,
               SUM(s.output_vat) AS total_vat
        FROM sales s
        JOIN products p ON p.id=s.product_id
        WHERE s.date BETWEEN ? AND ?
        GROUP BY p.id
        ORDER BY total_revenue DESC
        """,
        (from_date, to_date),
    ).fetchall()

    sales_totals = conn.execute(
        """
        SELECT COALESCE(SUM(s.total),0) AS grand_total,
               COALESCE(SUM(s.output_vat),0) AS grand_vat,
               COALESCE(SUM(s.qty),0) AS grand_qty,
               COUNT(DISTINCT s.receipt_id) AS receipt_count
        FROM sales s
        WHERE s.date BETWEEN ? AND ?
        """,
        (from_date, to_date),
    ).fetchone()

    # Purchases summary
    purchases_summary = conn.execute(
        """
        SELECT p.sku, p.name, pu.supplier_name,
               SUM(pu.qty) AS total_qty,
               SUM(pu.amount_ex_vat) AS total_ex_vat,
               SUM(pu.vat_amount) AS total_vat,
               SUM(pu.total) AS total_incl_vat
        FROM purchases pu
        JOIN products p ON p.id=pu.product_id
        WHERE pu.date BETWEEN ? AND ?
        GROUP BY p.id, pu.supplier_name
        ORDER BY total_incl_vat DESC
        """,
        (from_date, to_date),
    ).fetchall()

    purchases_totals = conn.execute(
        """
        SELECT COALESCE(SUM(pu.amount_ex_vat),0) AS grand_ex_vat,
               COALESCE(SUM(pu.vat_amount),0) AS grand_vat,
               COALESCE(SUM(pu.total),0) AS grand_total
        FROM purchases pu
        WHERE pu.date BETWEEN ? AND ?
        """,
        (from_date, to_date),
    ).fetchone()

    # Stock report with date range: opening, receipts, sales, closing
    products_all = conn.execute("SELECT * FROM products ORDER BY name").fetchall()
    from_date_prev = datetime.strptime(from_date, "%Y-%m-%d")
    from_date_prev = (from_date_prev - timedelta(days=1)).strftime("%Y-%m-%d")
    
    stock_rows = []
    for p in products_all:
        opening_qty = stock_at_date(p["id"], from_date_prev)
        
        receipts_qty = conn.execute(
            "SELECT COALESCE(SUM(qty),0) FROM purchases WHERE product_id=? AND date BETWEEN ? AND ?",
            (p["id"], from_date, to_date)
        ).fetchone()[0]
        
        sales_qty = conn.execute(
            "SELECT COALESCE(SUM(qty),0) FROM sales WHERE product_id=? AND date BETWEEN ? AND ?",
            (p["id"], from_date, to_date)
        ).fetchone()[0]
        
        closing_qty = stock_at_date(p["id"], to_date)
        
        stock_rows.append({
            "sku": p["sku"],
            "name": p["name"],
            "category": p["category"],
            "cost_price": p["cost_price"],
            "selling_price": p["selling_price"],
            "opening": opening_qty,
            "receipts": receipts_qty,
            "sales": sales_qty,
            "closing": closing_qty,
            "low_stock_level": p["low_stock_level"],
            "low": closing_qty <= p["low_stock_level"],
            "negative": closing_qty < 0,
            "opening_value": opening_qty * p["cost_price"],
            "closing_value": closing_qty * p["cost_price"],
        })
    total_opening_value = sum(r["opening_value"] for r in stock_rows)
    total_closing_value = sum(r["closing_value"] for r in stock_rows)

    # Takings summary by payment method
    takings_summary = conn.execute(
        """
        SELECT r.payment_method,
               COUNT(*) AS receipt_count,
               SUM(r.total) AS total_amount,
               SUM(r.output_vat) AS total_vat,
               SUM(r.subtotal) AS total_subtotal
        FROM sales_receipts r
        WHERE r.date BETWEEN ? AND ?
        GROUP BY r.payment_method
        ORDER BY total_amount DESC
        """,
        (from_date, to_date),
    ).fetchall()

    takings_totals = conn.execute(
        """
        SELECT COUNT(*) AS receipt_count,
               COALESCE(SUM(r.total),0) AS grand_total,
               COALESCE(SUM(r.output_vat),0) AS grand_vat,
               COALESCE(SUM(r.subtotal),0) AS grand_subtotal
        FROM sales_receipts r
        WHERE r.date BETWEEN ? AND ?
        """,
        (from_date, to_date),
    ).fetchone()

    return render_template(
        "reports.html",
        from_date=from_date,
        to_date=to_date,
        sales_summary=sales_summary,
        sales_totals=sales_totals,
        purchases_summary=purchases_summary,
        purchases_totals=purchases_totals,
        stock_rows=stock_rows,
        total_opening_value=total_opening_value,
        total_closing_value=total_closing_value,
        takings_summary=takings_summary,
        takings_totals=takings_totals,
    )


@app.route("/physical-stock-take", methods=["GET", "POST"])
@login_required
@admin_required
def physical_stock_take():
    conn = db()
    current_user = get_current_user()
    error = None
    success = None

    if request.method == "POST":
        try:
            count_date = request.form.get("count_date") or datetime.today().strftime("%Y-%m-%d")
            
            # Clear previous counts for this date
            conn.execute("DELETE FROM physical_stock_counts WHERE date=?", (count_date,))
            
            # Process each product in the form
            products = conn.execute("SELECT id FROM products").fetchall()
            for p in products:
                qty_key = f"qty_{p['id']}"
                if qty_key in request.form:
                    qty_str = request.form.get(qty_key, "").strip()
                    if qty_str:
                        try:
                            physical_qty = int(qty_str)
                            notes = request.form.get(f"notes_{p['id']}", "").strip()
                            
                            conn.execute(
                                """
                                INSERT INTO physical_stock_counts(date, product_id, physical_qty, count_notes, counted_by_user_id, created_at)
                                VALUES (?,?,?,?,?,?)
                            """,
                                (count_date, p['id'], physical_qty, notes, current_user['id'], datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                            )
                        except ValueError:
                            pass
            
            log_audit(conn, current_user["id"], "stock_count", current_user["username"], f"Physical stock count for {count_date}")
            conn.commit()
            success = f"Physical stock count recorded for {count_date}"
        except Exception as e:
            error = str(e)

    products = conn.execute("SELECT * FROM products ORDER BY name").fetchall()
    today = datetime.today().strftime("%Y-%m-%d")
    
    # Load most recent counts for this date if they exist
    recent_counts = conn.execute(
        "SELECT product_id, physical_qty, count_notes FROM physical_stock_counts WHERE date=?",
        (today,)
    ).fetchall()
    counts_dict = {row["product_id"]: row for row in recent_counts}

    # Enrich products with ledger stock and variance data
    product_data = []
    for p in products:
        ledger_qty = stock_at_date(p["id"], today)
        count = counts_dict.get(p["id"])
        physical_qty = count["physical_qty"] if count else None
        
        ledger_value = ledger_qty * p["cost_price"]
        physical_value = physical_qty * p["cost_price"] if physical_qty is not None else None
        
        variance_qty = physical_qty - ledger_qty if physical_qty is not None else None
        variance_value = variance_qty * p["cost_price"] if variance_qty is not None else None
        
        product_data.append({
            "id": p["id"],
            "sku": p["sku"],
            "name": p["name"],
            "category": p["category"],
            "cost_price": p["cost_price"],
            "ledger_qty": ledger_qty,
            "ledger_value": ledger_value,
            "physical_qty": physical_qty,
            "physical_value": physical_value,
            "variance_qty": variance_qty,
            "variance_value": variance_value,
            "notes": count["count_notes"] if count else "",
        })

    return render_template(
        "physical_stock_take.html",
        products=product_data,
        today=today,
        error=error,
        success=success,
    )


@app.route("/stock-variance")
@login_required
@admin_required
def stock_variance():
    conn = db()
    count_date = request.args.get("date") or datetime.today().strftime("%Y-%m-%d")
    
    # Get all products with physical counts and ledger calculations
    products = conn.execute("SELECT * FROM products ORDER BY name").fetchall()
    variance_rows = []
    total_variance_qty = 0
    total_variance_value = 0
    
    for p in products:
        # Get physical count for this date
        physical_count = conn.execute(
            "SELECT physical_qty, count_notes FROM physical_stock_counts WHERE date=? AND product_id=?",
            (count_date, p["id"])
        ).fetchone()
        
        if physical_count:
            physical_qty = physical_count["physical_qty"]
            notes = physical_count["count_notes"]
            
            # Get ledger stock for the same date
            ledger_qty = stock_at_date(p["id"], count_date)
            
            # Calculate variance
            variance_qty = physical_qty - ledger_qty
            variance_value = variance_qty * p["cost_price"]
            total_variance_qty += variance_qty
            total_variance_value += variance_value
            
            variance_rows.append({
                "sku": p["sku"],
                "name": p["name"],
                "category": p["category"],
                "cost_price": p["cost_price"],
                "ledger_qty": ledger_qty,
                "physical_qty": physical_qty,
                "variance_qty": variance_qty,
                "variance_value": variance_value,
                "notes": notes,
                "variance_type": "overage" if variance_qty > 0 else "shortage" if variance_qty < 0 else "exact",
            })
    
    # Filter to only show products with counts
    variance_rows = [r for r in variance_rows if r is not None]
    
    return render_template(
        "stock_variance.html",
        count_date=count_date,
        variance_rows=variance_rows,
        total_variance_qty=total_variance_qty,
        total_variance_value=total_variance_value,
    )


@app.route("/database-maintenance")
@login_required
@admin_required
def database_maintenance():
    conn = db()
    db_size = get_db_size_mb()
    warning = db_size > 50
    
    # Count records in major tables
    sales_count = conn.execute("SELECT COUNT(*) FROM sales").fetchone()[0]
    purchases_count = conn.execute("SELECT COUNT(*) FROM purchases").fetchone()[0]
    audit_count = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    receipts_count = conn.execute("SELECT COUNT(*) FROM sales_receipts").fetchone()[0]
    
    return render_template(
        "database_maintenance.html",
        db_size=db_size,
        warning=warning,
        sales_count=sales_count,
        purchases_count=purchases_count,
        audit_count=audit_count,
        receipts_count=receipts_count,
    )


@app.route("/database-backup")
@login_required
@admin_required
def database_backup():
    """Create an encrypted backup of the database and send it as a download."""
    try:
        backup_dir = "backups"
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_name = f"pos_v3_backup_{timestamp}.zip"
        zip_path = os.path.join(backup_dir, zip_name)

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(DB_NAME, arcname=DB_NAME)

        # Encrypt if passphrase is available
        if BACKUP_PASSPHRASE and LICENSE_MODULE_AVAILABLE:
            enc_name = zip_name + ".enc"
            enc_path = os.path.join(backup_dir, enc_name)
            encrypt_backup(zip_path, enc_path, BACKUP_PASSPHRASE)
            os.remove(zip_path)
            download_name = enc_name
            download_path = enc_path
        else:
            download_name = zip_name
            download_path = zip_path

        current_user = get_current_user()
        conn = db()
        log_audit(
            conn, current_user["id"], "database_backup",
            current_user["username"],
            f"Database backup created: {download_name} (encrypted={bool(BACKUP_PASSPHRASE)})",
        )
        conn.commit()

        return send_file(download_path, as_attachment=True, download_name=download_name)
    except Exception as e:
        return f"Backup failed: {str(e)}", 500


@app.route("/database-purge", methods=["POST"])
@login_required
@admin_required
def database_purge():
    """Purge old records from database."""
    conn = db()
    error = None
    success = None
    
    try:
        purge_days = int(request.form.get("purge_days", 365))
        purge_date = (datetime.now() - timedelta(days=purge_days)).strftime("%Y-%m-%d")
        
        # Count records to be deleted
        audit_del = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE event_time < ?", (f"{purge_date} 00:00:00",)).fetchone()[0]
        
        # Delete old audit logs
        conn.execute("DELETE FROM audit_logs WHERE event_time < ?", (f"{purge_date} 00:00:00",))
        conn.commit()
        
        current_user = get_current_user()
        log_audit(conn, current_user["id"], "database_purge", current_user["username"], 
                  f"Purged {audit_del} audit records older than {purge_date}")
        conn.commit()
        
        success = f"Purged {audit_del} audit log records older than {purge_date}"
    except Exception as e:
        error = str(e)
    
    return redirect(url_for("database_maintenance"))


@app.route("/export/<kind>")
@login_required
def export(kind):
    conn = db()
    output = io.StringIO()
    writer = csv.writer(output)
    today = datetime.today().strftime("%Y-%m-%d")
    from_date = request.args.get("from_date") or "2000-01-01"
    to_date = request.args.get("to_date") or today

    if kind == "sales":
        rows = conn.execute(
            """
            SELECT s.date, p.sku, p.name, p.category, s.qty, s.unit_price, s.total, s.output_vat,
                   COALESCE(u.username, 'n/a') AS cashier
            FROM sales s
            JOIN products p ON p.id=s.product_id
            LEFT JOIN users u ON u.id=s.cashier_user_id
            WHERE s.date BETWEEN ? AND ?
            ORDER BY s.date DESC
            """,
            (from_date, to_date),
        ).fetchall()
        writer.writerow(["Date", "SKU", "Product", "Category", "Qty", "Unit Price", "Total", "Output VAT", "Cashier"])
    elif kind == "purchases":
        rows = conn.execute(
            """
            SELECT pu.date, p.sku, p.name, p.category, pu.qty, pu.unit_cost,
                   pu.amount_ex_vat, pu.vat_amount, pu.total, pu.input_vat,
                   pu.supplier_name, pu.invoice_number, pu.expiry_date,
                   pu.contact_person, pu.contact_email, pu.contact_phone
            FROM purchases pu
            JOIN products p ON p.id=pu.product_id
            WHERE pu.date BETWEEN ? AND ?
            ORDER BY pu.date DESC
            """,
            (from_date, to_date),
        ).fetchall()
        writer.writerow([
            "Date", "SKU", "Product", "Category", "Qty", "Unit Cost",
            "Amount Ex-VAT", "VAT Amount", "Total (incl. VAT)", "Input VAT",
            "Supplier", "Invoice No.", "Expiry Date", "Contact Person", "Email", "Phone",
        ])
    elif kind == "stock":
        products_all = conn.execute("SELECT * FROM products ORDER BY name").fetchall()
        writer.writerow(["SKU", "Product", "Category", "Cost Price", "Selling Price", "Current Stock", "Low Stock Level", "Stock Value"])
        for p in products_all:
            qty = current_stock(p["id"])
            writer.writerow([p["sku"], p["name"], p["category"], p["cost_price"], p["selling_price"], qty, p["low_stock_level"], round(qty * p["cost_price"], 2)])
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=stock.csv"},
        )
    elif kind == "takings":
        rows = conn.execute(
            """
            SELECT r.date, r.id AS receipt_id, r.payment_method, r.payment_reference,
                   r.subtotal, r.output_vat, r.total,
                   u.username AS cashier
            FROM sales_receipts r
            JOIN users u ON u.id=r.cashier_user_id
            WHERE r.date BETWEEN ? AND ?
            ORDER BY r.date DESC, r.id DESC
            """,
            (from_date, to_date),
        ).fetchall()
        writer.writerow(["Date", "Receipt #", "Payment Method", "Reference", "Subtotal (ex-VAT)", "Output VAT", "Total", "Cashier"])
    else:
        return "Invalid export", 400

    if kind in ("sales", "purchases", "takings"):
        for r in rows:
            writer.writerow(list(r))

    filename = f"{kind}_{from_date}_to_{to_date}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/float", methods=["GET", "POST"])
@login_required
def float_register():
    conn = db()
    current_user = get_current_user()
    error = None
    success = None

    # Find the open float session for this cashier today (no closing_float yet)
    open_session = conn.execute(
        """
        SELECT * FROM cash_float_sessions
        WHERE cashier_user_id=? AND closing_float IS NULL
        ORDER BY id DESC LIMIT 1
    """,
        (current_user["id"],),
    ).fetchone()

    if request.method == "POST":
        action = request.form.get("action")
        try:
            if action == "open":
                if open_session:
                    raise ValueError("A float session is already open. Please close it first.")
                opening_float = float(request.form.get("opening_float") or 0)
                if opening_float < 0:
                    raise ValueError("Opening float cannot be negative")
                conn.execute(
                    """
                    INSERT INTO cash_float_sessions(date, cashier_user_id, opening_float, opened_at)
                    VALUES (?,?,?,?)
                """,
                    (
                        datetime.now().strftime("%Y-%m-%d"),
                        current_user["id"],
                        opening_float,
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    ),
                )
                log_audit(
                    conn,
                    current_user["id"],
                    "open_float",
                    current_user["username"],
                    f"Opened float: Rs {opening_float:.2f}",
                )
                conn.commit()
                success = f"Float opened with Rs {opening_float:.2f}"
                open_session = conn.execute(
                    "SELECT * FROM cash_float_sessions WHERE cashier_user_id=? AND closing_float IS NULL ORDER BY id DESC LIMIT 1",
                    (current_user["id"],),
                ).fetchone()

            elif action == "close":
                if not open_session:
                    raise ValueError("No open float session found.")
                closing_float = float(request.form.get("closing_float") or 0)
                if closing_float < 0:
                    raise ValueError("Closing float cannot be negative")
                conn.execute(
                    """
                    UPDATE cash_float_sessions
                    SET closing_float=?, closed_at=?
                    WHERE id=?
                """,
                    (
                        closing_float,
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        open_session["id"],
                    ),
                )
                log_audit(
                    conn,
                    current_user["id"],
                    "close_float",
                    current_user["username"],
                    f"Closed float: Rs {closing_float:.2f} (opened: Rs {open_session['opening_float']:.2f})",
                )
                conn.commit()
                success = f"Float closed with Rs {closing_float:.2f}"
                open_session = None
        except Exception as e:
            error = str(e)

    # History: last 20 sessions for this cashier
    history = conn.execute(
        """
        SELECT f.*, u.username, u.full_name
        FROM cash_float_sessions f
        JOIN users u ON u.id=f.cashier_user_id
        WHERE f.cashier_user_id=?
        ORDER BY f.id DESC LIMIT 20
    """,
        (current_user["id"],),
    ).fetchall()

    return render_template(
        "float.html",
        open_session=open_session,
        history=history,
        error=error,
        success=success,
    )


PAYMENT_METHODS = ["Cash", "Credit Card - MCB", "Credit Card - SBM", "Credit Card - MauBank",
                   "Credit Card - AfrAsia", "JuiceApp", "Blink", "MyT Money", "Other"]


@app.route("/takings")
@login_required
def takings():
    conn = db()
    current_user = get_current_user()
    date_filter = request.args.get("date") or datetime.today().strftime("%Y-%m-%d")

    # Admins can filter by any cashier; cashiers only see their own data
    if current_user["is_admin"]:
        cashier_filter = request.args.get("cashier_id")
    else:
        cashier_filter = str(current_user["id"])

    base_where = "WHERE r.date = ?"
    params = [date_filter]
    if cashier_filter:
        base_where += " AND r.cashier_user_id = ?"
        params.append(cashier_filter)

    # Summary by payment method
    payment_summary = conn.execute(
        f"""
        SELECT r.payment_method,
               COUNT(*) AS receipt_count,
               SUM(r.total) AS total_amount,
               SUM(r.output_vat) AS total_vat,
               SUM(r.subtotal) AS total_subtotal
        FROM sales_receipts r
        {base_where}
        GROUP BY r.payment_method
        ORDER BY total_amount DESC
    """,
        params,
    ).fetchall()

    # All receipts for the day
    receipts = conn.execute(
        f"""
        SELECT r.id, r.date, r.payment_method, r.payment_reference,
               r.subtotal, r.output_vat, r.total,
               u.username, u.full_name
        FROM sales_receipts r
        JOIN users u ON u.id = r.cashier_user_id
        {base_where}
        ORDER BY r.id DESC
    """,
        params,
    ).fetchall()

    # Grand totals
    grand = conn.execute(
        f"""
        SELECT COUNT(*) AS receipt_count,
               COALESCE(SUM(r.total), 0) AS grand_total,
               COALESCE(SUM(r.output_vat), 0) AS grand_vat,
               COALESCE(SUM(r.subtotal), 0) AS grand_subtotal
        FROM sales_receipts r
        {base_where}
    """,
        params,
    ).fetchone()

    # Float session for the day
    float_session = conn.execute(
        """
        SELECT * FROM cash_float_sessions
        WHERE date=? AND cashier_user_id=?
        ORDER BY id DESC LIMIT 1
    """,
        (date_filter, cashier_filter or current_user["id"]),
    ).fetchone()

    cashiers = conn.execute(
        "SELECT id, username, full_name FROM users WHERE is_active=1 ORDER BY username"
    ).fetchall() if current_user["is_admin"] else []

    return render_template(
        "takings.html",
        payment_summary=payment_summary,
        receipts=receipts,
        grand=grand,
        date_filter=date_filter,
        cashier_filter=cashier_filter,
        cashiers=cashiers,
        float_session=float_session,
        current_user=current_user,
    )


@app.route("/help")
@login_required
def help_page():
    current_user = get_current_user()
    return render_template("help.html", current_user=current_user)


@app.route("/settings/email", methods=["GET", "POST"])
@login_required
@admin_required
def email_settings():
    conn = db()
    error = None
    success = None
    
    if request.method == "POST":
        try:
            smtp_server = request.form.get("smtp_server", "").strip()
            smtp_port = request.form.get("smtp_port", "587").strip()
            sender_email = request.form.get("sender_email", "").strip()
            sender_password = request.form.get("sender_password", "").strip()
            backup_recipients = request.form.get("backup_recipients", "").strip()
            
            # Update settings
            settings = [
                ("email_smtp_server", smtp_server),
                ("email_smtp_port", smtp_port),
                ("email_sender", sender_email),
                ("email_password", sender_password),
                ("email_backup_recipients", backup_recipients),
            ]
            
            for key, value in settings:
                conn.execute(
                    "INSERT OR REPLACE INTO app_settings(key, value) VALUES(?,?)",
                    (key, value)
                )
            
            log_audit(conn, get_current_user()["id"], "email_settings_updated", 
                     get_current_user()["username"], "Email settings updated")
            conn.commit()
            success = "Email settings saved successfully"
        except Exception as e:
            error = str(e)
    
    # Load current settings
    settings = get_email_settings()
    
    return render_template(
        "email_settings.html",
        settings=settings,
        error=error,
        success=success,
    )


@app.route("/save-report/<kind>", methods=["POST"])
@login_required
def save_report(kind):
    """Save report to server and optionally email it."""
    conn = db()
    error = None
    success = None
    
    try:
        today = datetime.today().strftime("%Y-%m-%d")
        from_date = request.form.get("from_date") or "2000-01-01"
        to_date = request.form.get("to_date") or today
        send_email_flag = request.form.get("send_email") == "on"
        recipient_email = request.form.get("recipient_email", "").strip()
        
        # Generate CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        if kind == "sales":
            rows = conn.execute(
                "SELECT s.date, p.sku, p.name, p.category, s.qty, s.unit_price, s.total, s.output_vat, "
                "COALESCE(u.username, 'n/a') AS cashier FROM sales s JOIN products p ON p.id=s.product_id "
                "LEFT JOIN users u ON u.id=s.cashier_user_id WHERE s.date BETWEEN ? AND ? ORDER BY s.date DESC",
                (from_date, to_date),
            ).fetchall()
            writer.writerow(["Date", "SKU", "Product", "Category", "Qty", "Unit Price", "Total", "Output VAT", "Cashier"])
        elif kind == "purchases":
            rows = conn.execute(
                "SELECT pu.date, p.sku, p.name, p.category, pu.qty, pu.unit_cost, pu.amount_ex_vat, pu.vat_amount, "
                "pu.total, pu.input_vat, pu.supplier_name, pu.invoice_number, pu.expiry_date, pu.contact_person, "
                "pu.contact_email, pu.contact_phone FROM purchases pu JOIN products p ON p.id=pu.product_id "
                "WHERE pu.date BETWEEN ? AND ? ORDER BY pu.date DESC",
                (from_date, to_date),
            ).fetchall()
            writer.writerow(["Date", "SKU", "Product", "Category", "Qty", "Unit Cost", "Amount Ex-VAT", "VAT Amount", 
                           "Total (incl. VAT)", "Input VAT", "Supplier", "Invoice No.", "Expiry Date", "Contact Person", "Email", "Phone"])
        elif kind == "takings":
            rows = conn.execute(
                "SELECT r.date, r.id AS receipt_id, r.payment_method, r.payment_reference, r.subtotal, r.output_vat, "
                "r.total, u.username AS cashier FROM sales_receipts r JOIN users u ON u.id=r.cashier_user_id "
                "WHERE r.date BETWEEN ? AND ? ORDER BY r.date DESC, r.id DESC",
                (from_date, to_date),
            ).fetchall()
            writer.writerow(["Date", "Receipt #", "Payment Method", "Reference", "Subtotal (ex-VAT)", "Output VAT", "Total", "Cashier"])
        else:
            return "Invalid report type", 400
        
        for r in rows:
            writer.writerow(list(r))
        
        # Save to reports folder
        reports_dir = "reports"
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
        
        filename = f"{kind}_{from_date}_to_{to_date}_{datetime.now().strftime('%H%M%S')}.csv"
        filepath = os.path.join(reports_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(output.getvalue())
        
        success = f"Report saved: {filename}"
        
        # Email if requested
        if send_email_flag and recipient_email:
            if send_email(
                subject=f"{kind.upper()} Report - {from_date} to {to_date}",
                body=f"Attached: {kind} report for {from_date} to {to_date}",
                recipients=[recipient_email],
                attachment_path=filepath
            )[0]:
                success += " and emailed"
            else:
                error = "Report saved but email failed"
        
        log_audit(conn, get_current_user()["id"], "report_saved", get_current_user()["username"], 
                 f"Saved {kind} report: {filename}")
        conn.commit()
        
    except Exception as e:
        error = str(e)
    
    return jsonify({"success": success, "error": error})


# ─── License Status (admin) ───────────────────────────────────────────────────

@app.route("/license-status")
@login_required
@admin_required
def license_status():
    """Admin page showing current license info and hardware fingerprint."""
    hardware_fp = ""
    if LICENSE_MODULE_AVAILABLE:
        try:
            hardware_fp = get_hardware_fingerprint()
        except Exception:
            hardware_fp = "unavailable"

    payload = _license_status.get("payload") or {}
    return render_template(
        "license_status.html",
        license_valid=_license_status["valid"],
        license_error=_license_status.get("error"),
        license_enforce=LICENSE_ENFORCE,
        hardware_fp=hardware_fp,
        company=payload.get("company", "—"),
        company_id=payload.get("company_id", "—"),
        license_id=payload.get("license_id", "—"),
        expiry=payload.get("expiry", "—"),
        issued_at=payload.get("issued_at", "—"),
    )


# Initialise license at module load so enforcement works under any WSGI runner
# (Gunicorn, Azure App Service, etc.) that imports app.py without going through
# serve.py or the __main__ block.
init_license()


if __name__ == "__main__":
    init_db()

    # Start scheduler thread for backups
    schedule.every().day.at("02:00").do(schedule_backup_email)
    scheduler_thread = threading.Thread(target=scheduler_worker, daemon=True)
    scheduler_thread.start()

    if LICENSE_ENFORCE and LICENSE_MODULE_AVAILABLE and _license_status["valid"]:
        try:
            start_heartbeat_thread(on_failure=_license_on_heartbeat_failure)
        except LicenseError as exc:
            print(f"LICENSE ERROR: {exc}")

    app.run(debug=True, use_reloader=False)
