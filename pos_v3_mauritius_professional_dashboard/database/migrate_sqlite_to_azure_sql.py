"""
migrate_sqlite_to_azure_sql.py
-------------------------------
Migrates all data from the local SQLite POS database to an Azure SQL Database.

Usage:
    python database/migrate_sqlite_to_azure_sql.py

Required environment variables:
    AZURE_SQL_CONNECTION_STRING
        Full pyodbc connection string, e.g.:
        Driver={ODBC Driver 18 for SQL Server};Server=tcp:<server>.database.windows.net,1433;
        Database=<db>;Uid=<user>;Pwd=<password>;Encrypt=yes;TrustServerCertificate=no;

    SQLITE_DB_PATH  (optional, defaults to pos_v3.db in the repo root)

Steps this script performs:
    1. Validate source (SQLite) and target (Azure SQL) connections.
    2. Run the Azure SQL schema DDL if tables don't exist yet.
    3. Migrate tables in dependency order:
       users, products, companies, company_users, subscriptions, billing_events,
       auth_identities, app_settings, sales_receipts, sales, purchases,
       audit_logs, cash_float_sessions, physical_stock_counts
    4. Print per-table counts and a reconciliation summary.
    5. Exit with a non-zero code on any fatal error.

Notes:
    - Safe to re-run: uses INSERT OR IGNORE / MERGE upsert style.
    - Does NOT delete existing Azure SQL data before inserting.
    - For large datasets (>100k rows per table) consider chunked batching
      by setting BATCH_SIZE env variable (default 500).
"""

import os
import sys
import sqlite3
import time
from pathlib import Path

try:
    import pyodbc
except ImportError:
    print("ERROR: pyodbc is not installed. Run: pip install pyodbc")
    sys.exit(1)

SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", "pos_v3.db")
AZURE_CONN_STR = os.getenv("AZURE_SQL_CONNECTION_STRING", "")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "500"))

DDL_FILE = Path(__file__).parent / "azure_subscription_schema.sql"


def check_env():
    if not AZURE_CONN_STR:
        print("ERROR: AZURE_SQL_CONNECTION_STRING is not set.")
        sys.exit(1)
    if not Path(SQLITE_DB_PATH).exists():
        print(f"ERROR: SQLite database not found at '{SQLITE_DB_PATH}'")
        sys.exit(1)


def open_sqlite():
    conn = sqlite3.connect(SQLITE_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def open_azure():
    print("Connecting to Azure SQL...")
    conn = pyodbc.connect(AZURE_CONN_STR, timeout=30)
    conn.autocommit = False
    print("Connected.")
    return conn


def apply_schema(az_conn):
    if not DDL_FILE.exists():
        print(f"WARNING: DDL file not found at {DDL_FILE} - skipping schema creation.")
        return
    print("Applying Azure SQL schema (CREATE TABLE IF NOT EXISTS equivalent via error handling)...")
    cursor = az_conn.cursor()
    ddl = DDL_FILE.read_text(encoding="utf-8")
    # Split on semicolons and execute each statement independently
    for statement in ddl.split(";"):
        stmt = statement.strip()
        if not stmt:
            continue
        try:
            cursor.execute(stmt)
        except pyodbc.ProgrammingError as e:
            if "There is already an object" in str(e) or "already exists" in str(e).lower():
                pass  # Table/index already created - safe to ignore
            else:
                raise
    az_conn.commit()
    print("Schema applied.")


def migrate_table(sl_conn, az_conn, table, columns, pk_columns, create_row=None):
    """
    Migrate a table from SQLite to Azure SQL using MERGE (upsert) semantics.

    Parameters:
        sl_conn    : sqlite3 connection
        az_conn    : pyodbc connection
        table      : table name (str)
        columns    : list of column names to migrate
        pk_columns : list of column names forming the unique key for upsert
        create_row : optional callable(dict) -> dict to transform a row before insert
    """
    cursor_sl = sl_conn.cursor()
    try:
        cursor_sl.execute(f"SELECT {', '.join(columns)} FROM {table}")
    except sqlite3.OperationalError as e:
        print(f"  SKIP {table}: {e}")
        return 0, 0

    rows = cursor_sl.fetchall()
    total = len(rows)
    if total == 0:
        print(f"  {table}: 0 rows (empty)")
        return 0, 0

    cursor_az = az_conn.cursor()
    inserted = 0
    skipped = 0
    batch_count = 0

    for row in rows:
        d = dict(zip(columns, row))
        if create_row:
            d = create_row(d)
        if d is None:
            skipped += 1
            continue

        col_list = list(d.keys())
        val_list = list(d.values())
        placeholders = ", ".join(["?" for _ in col_list])
        col_names = ", ".join(col_list)
        pk_check = " AND ".join([f"[{c}] = ?" for c in pk_columns])
        pk_vals = [d[c] for c in pk_columns]

        try:
            # Existence check before insert for idempotency
            cursor_az.execute(f"SELECT 1 FROM [{table}] WHERE {pk_check}", pk_vals)
            exists = cursor_az.fetchone()
            if exists:
                skipped += 1
            else:
                cursor_az.execute(
                    f"INSERT INTO [{table}] ({col_names}) VALUES ({placeholders})",
                    val_list,
                )
                inserted += 1
        except pyodbc.Error as e:
            print(f"  WARNING: row skipped in {table}: {e}")
            skipped += 1

        batch_count += 1
        if batch_count >= BATCH_SIZE:
            az_conn.commit()
            batch_count = 0

    if batch_count > 0:
        az_conn.commit()

    print(f"  {table}: {inserted} inserted, {skipped} skipped (of {total} total)")
    return inserted, skipped


def verify_counts(sl_conn, az_conn, tables):
    print("\nReconciliation summary:")
    print(f"{'Table':<35} {'SQLite':>10} {'Azure SQL':>10} {'Match':>8}")
    print("-" * 65)
    all_match = True
    for table in tables:
        try:
            sl_count = sl_conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except sqlite3.OperationalError:
            sl_count = 0
        try:
            az_cur = az_conn.cursor()
            az_cur.execute(f"SELECT COUNT(*) FROM [{table}]")
            az_count = az_cur.fetchone()[0]
        except pyodbc.Error:
            az_count = -1
        match = "OK" if sl_count == az_count else "MISMATCH"
        if match != "OK":
            all_match = False
        print(f"  {table:<33} {sl_count:>10} {az_count:>10} {match:>8}")
    print()
    if all_match:
        print("All counts match.")
    else:
        print("WARNING: Some counts do not match. Review skipped rows above.")
    return all_match


TABLES = [
    # (table_name, columns, pk_columns)
    ("users", [
        "id", "username", "password_hash", "full_name", "is_admin", "is_active"
    ], ["id"]),

    ("products", [
        "id", "sku", "name", "brand", "lodgement", "category",
        "cost_price", "selling_price", "low_stock_level"
    ], ["id"]),

    ("companies", [
        "id", "name", "status", "created_at"
    ], ["id"]),

    ("company_users", [
        "id", "company_id", "user_id", "role", "is_active"
    ], ["id"]),

    ("subscriptions", [
        "id", "company_id", "provider", "provider_customer_id",
        "provider_subscription_id", "status", "current_period_end",
        "cancel_at_period_end", "grace_until", "updated_at"
    ], ["id"]),

    ("billing_events", [
        "id", "company_id", "provider", "provider_event_id",
        "event_type", "payload_json", "processed_at", "success"
    ], ["id"]),

    ("auth_identities", [
        "id", "user_id", "provider", "provider_subject", "email", "last_login_at"
    ], ["id"]),

    ("app_settings", [
        "key", "value"
    ], ["key"]),

    ("sales_receipts", [
        "id", "date", "cashier_user_id", "subtotal", "output_vat",
        "total", "payment_method", "payment_reference"
    ], ["id"]),

    ("sales", [
        "id", "date", "product_id", "qty", "unit_price",
        "total", "output_vat", "receipt_id", "cashier_user_id"
    ], ["id"]),

    ("purchases", [
        "id", "date", "product_id", "qty", "unit_cost",
        "amount_ex_vat", "vat_amount", "total", "input_vat",
        "supplier_name", "invoice_number", "expiry_date",
        "contact_person", "contact_email", "contact_phone"
    ], ["id"]),

    ("audit_logs", [
        "id", "event_time", "actor_user_id", "action", "target_username", "details"
    ], ["id"]),

    ("cash_float_sessions", [
        "id", "date", "cashier_user_id", "opening_float",
        "closing_float", "opened_at", "closed_at"
    ], ["id"]),

    ("physical_stock_counts", [
        "id", "date", "product_id", "physical_qty",
        "count_notes", "counted_by_user_id", "created_at"
    ], ["id"]),
]


def main():
    check_env()
    print(f"Source SQLite: {SQLITE_DB_PATH}")
    print(f"Batch size:    {BATCH_SIZE}")
    print()

    sl_conn = open_sqlite()
    az_conn = open_azure()

    try:
        apply_schema(az_conn)
        print("\nMigrating tables...")
        start = time.time()

        for table, columns, pk_columns in TABLES:
            migrate_table(sl_conn, az_conn, table, columns, pk_columns)

        elapsed = time.time() - start
        print(f"\nMigration completed in {elapsed:.1f}s")

        all_match = verify_counts(sl_conn, az_conn, [t[0] for t in TABLES])
        sys.exit(0 if all_match else 1)

    except Exception as exc:
        print(f"\nFATAL ERROR: {exc}")
        try:
            az_conn.rollback()
        except Exception:
            pass
        sys.exit(1)
    finally:
        try:
            sl_conn.close()
        except Exception:
            pass
        try:
            az_conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
