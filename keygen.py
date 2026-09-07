"""
POS V3 — License Key Generator (Vendor Tool)
=============================================
Run this on the VENDOR side only. Keep vendor_private.pem secure and
never distribute it.

Commands
--------
  python keygen.py generate-keys
      Generate a fresh RSA-2048 key pair.
      Copy the printed public key block into license_manager.py
      (VENDOR_PUBLIC_KEY_PEM) or set the env-var before distributing.

  python keygen.py fingerprint
      Print the hardware fingerprint of the current machine.
      Send output to the customer and ask them to provide it before
      issuing a hardware-bound license.

  python keygen.py issue \\
      --company "Acme Ltd" --company-id "acme-001" \\
      --days 365 --hardware-fp <fingerprint>
      Issue a signed license file.  --hardware-fp is optional;
      omit it to issue a machine-independent license.

  python keygen.py inspect <license_file>
      Decode and display a license file (does NOT verify signature).

  python keygen.py verify <license_file>
      Fully verify a license file using the public key.
"""

import argparse
import json
import base64
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, load_pem_public_key
    )
except ImportError:
    print("ERROR: 'cryptography' package required.  Run:  pip install cryptography")
    sys.exit(1)

PRIVATE_KEY_FILE = "vendor_private.pem"
PUBLIC_KEY_FILE = "vendor_public.pem"


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _load_private_key():
    if not Path(PRIVATE_KEY_FILE).exists():
        print(f"ERROR: {PRIVATE_KEY_FILE} not found.  Run:  python keygen.py generate-keys")
        sys.exit(1)
    with open(PRIVATE_KEY_FILE, "rb") as fh:
        return load_pem_private_key(fh.read(), password=None, backend=default_backend())


def _load_public_key():
    if not Path(PUBLIC_KEY_FILE).exists():
        print(f"ERROR: {PUBLIC_KEY_FILE} not found.  Run:  python keygen.py generate-keys")
        sys.exit(1)
    with open(PUBLIC_KEY_FILE, "rb") as fh:
        return load_pem_public_key(fh.read(), backend=default_backend())


# ─── Commands ─────────────────────────────────────────────────────────────────

def cmd_generate_keys(_args):
    """Generate RSA-2048 key pair."""
    if Path(PRIVATE_KEY_FILE).exists():
        answer = input(f"⚠  {PRIVATE_KEY_FILE} already exists.  Overwrite? [y/N] ").strip().lower()
        if answer != "y":
            print("Aborted.")
            return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    with open(PRIVATE_KEY_FILE, "wb") as fh:
        fh.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(PUBLIC_KEY_FILE, "wb") as fh:
        fh.write(pub_pem)

    print(f"✓  Private key → {PRIVATE_KEY_FILE}  (KEEP SECURE — never distribute)")
    print(f"✓  Public key  → {PUBLIC_KEY_FILE}")
    print()
    print("Paste the following block into license_manager.py as VENDOR_PUBLIC_KEY_PEM")
    print("or set it via the VENDOR_PUBLIC_KEY_PEM environment variable:\n")
    print(pub_pem.decode())


def cmd_fingerprint(_args):
    """Print the hardware fingerprint of the current machine."""
    from license_manager import get_hardware_fingerprint
    fp = get_hardware_fingerprint()
    print(f"Hardware Fingerprint: {fp}")
    print("Provide this value to the customer and use it with --hardware-fp when issuing a license.")


def cmd_issue(args):
    """Issue a signed license key file."""
    private_key = _load_private_key()

    payload = {
        "license_id": args.license_id or str(uuid.uuid4())[:8].upper(),
        "company":    args.company,
        "company_id": args.company_id,
        "hardware_fp": args.hardware_fp or "",
        "issued_at":  datetime.utcnow().strftime("%Y-%m-%d"),
        "expiry":     (datetime.utcnow() + timedelta(days=args.days)).strftime("%Y-%m-%d"),
    }

    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    payload_b64 = _b64url_encode(payload_bytes)

    signature = private_key.sign(payload_bytes, asym_padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = _b64url_encode(signature)

    license_key = f"{payload_b64}.{sig_b64}"

    out_file = args.output or f"license_{args.company_id}.key"
    with open(out_file, "w") as fh:
        fh.write(license_key)

    print(f"✓  License issued")
    print(f"   Company     : {payload['company']} ({payload['company_id']})")
    print(f"   License ID  : {payload['license_id']}")
    print(f"   Issued      : {payload['issued_at']}")
    print(f"   Expiry      : {payload['expiry']} ({args.days} days)")
    print(f"   Hardware FP : {payload['hardware_fp'] or '(not bound — any machine)'}")
    print(f"   Saved to    : {out_file}")


def cmd_inspect(args):
    """Decode and display license payload (no signature check)."""
    path = args.license_file
    if not Path(path).exists():
        print(f"ERROR: File not found: {path}")
        sys.exit(1)
    content = Path(path).read_text().strip()
    parts = content.split(".")
    if len(parts) != 2:
        print("ERROR: Invalid license format")
        sys.exit(1)
    payload = json.loads(_b64url_decode(parts[0]).decode())
    print(json.dumps(payload, indent=2))


def cmd_verify(args):
    """Verify a license file using the public key."""
    try:
        from license_manager import verify_license, get_hardware_fingerprint, LicenseError
        import os
        os.environ["LICENSE_FILE"] = args.license_file
        # Load public key from file into env var for verification
        if Path(PUBLIC_KEY_FILE).exists():
            pub_pem = Path(PUBLIC_KEY_FILE).read_text()
            os.environ["VENDOR_PUBLIC_KEY_PEM"] = pub_pem
            import license_manager
            license_manager.VENDOR_PUBLIC_KEY_PEM = pub_pem
        payload = verify_license(args.license_file)
        print("✓  License is VALID")
        print(json.dumps(payload, indent=2))
        print(f"\nCurrent hardware fingerprint: {get_hardware_fingerprint()}")
    except Exception as exc:
        print(f"✗  License INVALID: {exc}")
        sys.exit(1)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="POS V3 License Key Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    sub.add_parser("generate-keys", help="Generate RSA-2048 key pair")
    sub.add_parser("fingerprint",   help="Print this machine's hardware fingerprint")

    p_issue = sub.add_parser("issue", help="Issue a signed license key")
    p_issue.add_argument("--company",     required=True, help="Customer company name")
    p_issue.add_argument("--company-id",  required=True, dest="company_id", help="Unique customer ID")
    p_issue.add_argument("--days",        type=int, default=365, help="License validity in days (default 365)")
    p_issue.add_argument("--hardware-fp", default="", dest="hardware_fp",
                         help="Hardware fingerprint to bind (leave empty for machine-independent)")
    p_issue.add_argument("--license-id",  default=None, dest="license_id",
                         help="Override auto-generated license ID")
    p_issue.add_argument("--output",      default=None, help="Output filename (default: license_<company-id>.key)")

    p_inspect = sub.add_parser("inspect", help="Decode license payload (no signature check)")
    p_inspect.add_argument("license_file", metavar="license.key")

    p_verify = sub.add_parser("verify", help="Fully verify a license file")
    p_verify.add_argument("license_file", metavar="license.key")

    args = parser.parse_args()
    dispatch = {
        "generate-keys": cmd_generate_keys,
        "fingerprint":   cmd_fingerprint,
        "issue":         cmd_issue,
        "inspect":       cmd_inspect,
        "verify":        cmd_verify,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
