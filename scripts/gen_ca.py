"""Generate self-signed Root Certificate Authority using RSA and X.509."""
from __future__ import annotations

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_ca(ca_common_name: str, output_directory: Path) -> None:
    """Generate CA private key and self-signed certificate."""
    output_directory.mkdir(parents=True, exist_ok=True)

    # Generate RSA private key for CA
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # CA is both subject and issuer (self-signed)
    ca_subject = ca_issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, ca_common_name)]
    )
    current_time = datetime.datetime.utcnow()

    # Build self-signed CA certificate
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(current_time - datetime.timedelta(minutes=5))
        .not_valid_after(current_time + datetime.timedelta(days=3650))  # 10 years
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    # Define output file paths
    private_key_path = output_directory / "ca_key.pem"
    certificate_path = output_directory / "ca_cert.pem"

    # Serialize private key and certificate to PEM format
    private_key_pem = ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    certificate_pem = ca_certificate.public_bytes(encoding=serialization.Encoding.PEM)

    # Write to files
    private_key_path.write_bytes(private_key_pem)
    certificate_path.write_bytes(certificate_pem)

    print(f"[SUCCESS] CA private key written to: {private_key_path}")
    print(f"[SUCCESS] CA certificate written to: {certificate_path}")


def main() -> None:
    """Parse arguments and generate Root CA."""
    argument_parser = argparse.ArgumentParser(description="Generate Root Certificate Authority")
    argument_parser.add_argument("--name", required=True, help="Common Name for CA")
    argument_parser.add_argument(
        "--out",
        default="certs/ca",
        help="Output directory path (default: certs/ca)",
    )
    arguments = argument_parser.parse_args()

    generate_ca(arguments.name, Path(arguments.out))


if __name__ == "__main__":
    main()