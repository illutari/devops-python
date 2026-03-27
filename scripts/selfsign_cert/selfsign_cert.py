#!/usr/bin/env python3
"""
Enhanced self-signed certificate / CSR generator
- ECDSA or RSA keys
- Full X.509 subject fields via CLI or config file (JSON/YAML)
- Support for PKCS#12 with user choice of .p12 or .pfx extension
"""

import argparse
import getpass
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
    PrivateFormat,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates


def load_config_file(config_path: str) -> dict:
    """Load subject fields from JSON or YAML file."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(path, "r", encoding="utf-8") as f:
        if path.suffix.lower() == ".json":
            return json.load(f)
        elif path.suffix.lower() in (".yaml", ".yml"):
            return yaml.safe_load(f)
        else:
            raise ValueError("Config file must be .json, .yaml, or .yml")


def build_subject(subject_dict: dict) -> x509.Name:
    """Build x509.Name from a dictionary."""
    attrs = []
    mapping = {
        "common_name": NameOID.COMMON_NAME,
        "country": NameOID.COUNTRY_NAME,
        "state": NameOID.STATE_OR_PROVINCE_NAME,
        "locality": NameOID.LOCALITY_NAME,
        "organization": NameOID.ORGANIZATION_NAME,
        "ou": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "email": NameOID.EMAIL_ADDRESS,
        "serial": NameOID.SERIAL_NUMBER,
        "street": NameOID.STREET_ADDRESS,
        "postal_code": NameOID.POSTAL_CODE,
        "business_cat": NameOID.BUSINESS_CATEGORY,
    }
    for key, oid in mapping.items():
        value = subject_dict.get(key)
        if value:
            attrs.append(x509.NameAttribute(oid, str(value)))
    if not attrs or not subject_dict.get("common_name"):
        raise ValueError("At least 'common_name' is required")
    return x509.Name(attrs)


def generate_key(key_type: str, key_size: int | None, curve: str | None):
    """Generate RSA or ECDSA private key."""
    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size or 2048)
    elif key_type == "ecdsa":
        curve_map = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}
        return ec.generate_private_key(curve_map[curve or "P-256"]())
    raise ValueError("Invalid key type")


def generate_cert_or_csr(private_key, subject: x509.Name, mode: str, validity_days: int):
    """Return either self-signed cert or CSR."""
    if mode == "selfsigned":
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
            .sign(private_key, hashes.SHA256())
        )
        return cert, None
    else:  # csr
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())
        return None, csr


def save_certificate(cert, path: str, encoding=serialization.Encoding.PEM):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(encoding))
    print(f"✅ Certificate saved: {path}")


def save_private_key(key, path: str, password: str | None = None, pkcs8: bool = False):
    encryption = (
        BestAvailableEncryption(password.encode()) if password else NoEncryption()
    )
    fmt = PrivateFormat.PKCS8 if pkcs8 else PrivateFormat.TraditionalOpenSSL
    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=fmt,
                encryption_algorithm=encryption,
            )
        )
    print(f"✅ Private key saved: {path}")


def save_csr(csr, path: str):
    with open(path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    print(f"✅ CSR saved: {path}")


def save_pkcs12(
    cert: x509.Certificate,
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    path: str,
    password: str,
    friendly_name: str | None = None,
) -> None:
    """Export certificate + private key as PKCS#12 (.p12 or .pfx)."""
    name = friendly_name.encode("utf-8") if friendly_name else None

    p12_bytes = serialize_key_and_certificates(
        name=name,
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=BestAvailableEncryption(password.encode("utf-8")),
    )

    with open(path, "wb") as f:
        f.write(p12_bytes)
    print(f"✅ PKCS#12 bundle saved: {path}")


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced self-signed cert / CSR generator with PKCS#12 file type support",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # Key type
    parser.add_argument("--key-type", choices=["rsa", "ecdsa"], default="rsa", help="Key algorithm")
    parser.add_argument("--key-size", type=int, default=2048, help="RSA key size (ignored for ECDSA)")
    parser.add_argument("--curve", choices=["P-256", "P-384", "P-521"], default="P-256", help="ECDSA curve")

    # Config file (strict either/or)
    parser.add_argument("--config", "-c", help="Path to .json or .yaml file containing subject fields")

    # Subject fields (CLI fallback)
    parser.add_argument("--common-name", help="Common Name (CN)")
    parser.add_argument("--country", help="Country (C)")
    parser.add_argument("--state", help="State/Province (ST)")
    parser.add_argument("--locality", help="Locality/City (L)")
    parser.add_argument("--organization", help="Organization (O)")
    parser.add_argument("--ou", help="Organizational Unit (OU)")
    parser.add_argument("--email", help="Email Address")
    parser.add_argument("--serial", help="Subject Serial Number")
    parser.add_argument("--street", help="Street Address")
    parser.add_argument("--postal-code", help="Postal Code")
    parser.add_argument("--business-cat", help="Business Category")

    # Behavior
    parser.add_argument("--mode", choices=["selfsigned", "csr"], default="selfsigned")
    parser.add_argument("--validity-days", type=int, default=365)
    parser.add_argument("--output-dir", default=".", help="Output directory")
    parser.add_argument(
        "--cert-type",
        choices=["x509_pem", "x509_der", "pkcs12", "pkcs8"],
        default="x509_pem",
    )
    # NEW: File type for PKCS#12
    parser.add_argument(
        "--file-type",
        choices=["p12", "pfx"],
        default=None,
        help="File extension for PKCS#12 files (p12 or pfx). If not specified, user will be prompted."
    )
    parser.add_argument("--password", help="Encryption password (PKCS#12 / PKCS#8)")

    args = parser.parse_args()

    # === STRICT EITHER/OR VALIDATION ===
    subject_field_names = [
        "common_name", "country", "state", "locality", "organization",
        "ou", "email", "serial", "street", "postal_code", "business_cat",
    ]

    if args.config:
        provided_individual = [name for name in subject_field_names if getattr(args, name) is not None]
        if provided_individual:
            parser.error(f"--config cannot be combined with individual subject arguments: {', '.join(provided_individual)}")
        subject_dict = load_config_file(args.config)
        if not subject_dict.get("common_name"):
            parser.error("Config file must contain at least 'common_name'")
        subject = build_subject(subject_dict)
        base_name = str(subject_dict.get("common_name")).replace(" ", "_").replace("/", "_")
    else:
        if not args.common_name:
            parser.error("--common-name is required when --config is not used")
        subject_dict = {name: getattr(args, name) for name in subject_field_names if getattr(args, name)}
        subject = build_subject(subject_dict)
        base_name = args.common_name.replace(" ", "_").replace("/", "_")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    private_key = generate_key(args.key_type, args.key_size, args.curve)
    cert, csr = generate_cert_or_csr(private_key, subject, args.mode, args.validity_days)

    password = args.password
    if not password and args.cert_type in ("pkcs12", "pkcs8") and args.mode == "selfsigned":
        password = getpass.getpass("Enter encryption password: ")

    if args.mode == "csr":
        csr_path = out_dir / f"{base_name}.csr"
        key_path = out_dir / f"{base_name}.key"
        save_csr(csr, str(csr_path))
        save_private_key(private_key, str(key_path), password, pkcs8=(args.cert_type == "pkcs8"))
    else:
        if args.cert_type == "x509_pem":
            save_certificate(cert, str(out_dir / f"{base_name}.pem"))
            save_private_key(private_key, str(out_dir / f"{base_name}.key"), password)
        elif args.cert_type == "x509_der":
            save_certificate(cert, str(out_dir / f"{base_name}.cer"), serialization.Encoding.DER)
            save_private_key(private_key, str(out_dir / f"{base_name}.key"), password)
        elif args.cert_type == "pkcs12":
            # Determine file extension
            if args.file_type:
                ext = args.file_type
            else:
                # Prompt user to choose
                while True:
                    choice = input("Choose PKCS#12 file type (p12 or pfx): ").strip().lower()
                    if choice in ("p12", "pfx"):
                        ext = choice
                        break
                    print("Invalid choice. Please enter 'p12' or 'pfx'.")

            p12_path = out_dir / f"{base_name}.{ext}"
            if not password:
                password = getpass.getpass("PKCS#12 password: ")
            save_pkcs12(
                cert,
                private_key,
                str(p12_path),
                password,
                friendly_name=subject_dict.get("common_name") or base_name
            )
        elif args.cert_type == "pkcs8":
            save_certificate(cert, str(out_dir / f"{base_name}.pem"))
            save_private_key(private_key, str(out_dir / f"{base_name}.key"), password, pkcs8=True)

    print("\n🎉 Done!")


if __name__ == "__main__":
    main()