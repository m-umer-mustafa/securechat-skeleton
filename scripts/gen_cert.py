"""Issue leaf certificates (server/client) signed by Root CA with SAN extension."""
from __future__ import annotations

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def load_ca(ca_directory: Path):
    """Load CA certificate and private key from directory."""
    ca_cert_data = (ca_directory / "ca_cert.pem").read_bytes()
    ca_key_data = (ca_directory / "ca_key.pem").read_bytes()
    
    ca_certificate = x509.load_pem_x509_certificate(ca_cert_data)
    ca_private_key = serialization.load_pem_private_key(ca_key_data, password=None)
    
    return ca_certificate, ca_private_key


def issue_cert(common_name: str, output_directory: Path, ca_directory: Path) -> None:
    """Generate and sign a leaf certificate using CA."""
    output_directory.mkdir(parents=True, exist_ok=True)

    # Load CA certificate and key
    ca_certificate, ca_private_key = load_ca(ca_directory)

    # Generate RSA key pair for leaf certificate
    leaf_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Set subject with provided common name
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    current_time = datetime.datetime.utcnow()

    # Create Subject Alternative Name extension with common name
    subject_alt_name = x509.SubjectAlternativeName([x509.DNSName(common_name)])

    # Build and sign leaf certificate
    leaf_certificate = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(ca_certificate.subject)
        .public_key(leaf_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(current_time - datetime.timedelta(minutes=5))
        .not_valid_after(current_time + datetime.timedelta(days=365))  # 1 year validity
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(subject_alt_name, critical=False)
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    # Define output paths
    private_key_path = output_directory / "key.pem"
    certificate_path = output_directory / "cert.pem"

    # Serialize to PEM format
    private_key_pem = leaf_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    certificate_pem = leaf_certificate.public_bytes(encoding=serialization.Encoding.PEM)

    # Write to files
    private_key_path.write_bytes(private_key_pem)
    certificate_path.write_bytes(certificate_pem)

    print(f"[SUCCESS] Leaf private key written to: {private_key_path}")
    print(f"[SUCCESS] Leaf certificate written to: {certificate_path}")


def main() -> None:
    """Parse arguments and issue leaf certificate."""
    argument_parser = argparse.ArgumentParser(description="Issue leaf certificate signed by CA")
    argument_parser.add_argument("--cn", required=True, help="Common Name / hostname for certificate")
    argument_parser.add_argument(
        "--out",
        required=True,
        help="Output directory for key/cert (e.g., certs/server)",
    )
    argument_parser.add_argument(
        "--ca-dir",
        default="certs/ca",
        help="CA directory containing ca_key.pem and ca_cert.pem",
    )
    arguments = argument_parser.parse_args()

    issue_cert(arguments.cn, Path(arguments.out), Path(arguments.ca_dir))


if __name__ == "__main__":
    main()