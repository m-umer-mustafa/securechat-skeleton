"""X.509 certificate validation utilities - CA signature, validity, and hostname checks."""
from __future__ import annotations

import datetime
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID


class BadCertificate(Exception):
    """Exception raised when certificate validation fails."""
    pass


def load_certificate_pem(certificate_path: str) -> x509.Certificate:
    """Load X.509 certificate from PEM file."""
    with open(certificate_path, "rb") as cert_file:
        certificate_data = cert_file.read()
    return x509.load_pem_x509_certificate(certificate_data)


def verify_cert_validity(certificate: x509.Certificate, check_time: Optional[datetime.datetime] = None):
    """Verify certificate is within its validity window."""
    current_time = datetime.datetime.now(datetime.timezone.utc)
    
    if current_time < certificate.not_valid_before_utc:
        raise BadCertificate("Certificate not yet valid")
    
    if current_time > certificate.not_valid_after_utc:
        raise BadCertificate("Certificate has expired")


def verify_cert_signed_by_ca(certificate: x509.Certificate, ca_certificate: x509.Certificate):
    """Verify certificate was signed by the given CA certificate."""
    ca_public_key_obj = ca_certificate.public_key()
    
    try:
        ca_public_key_obj.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
    except Exception as verification_error:
        raise BadCertificate("Certificate signature invalid - not signed by trusted CA") from verification_error


def _get_cert_hostnames(certificate: x509.Certificate) -> set[str]:
    """Extract all hostnames from certificate (SAN and CN)."""
    hostname_set: set[str] = set()
    
    # Extract from Subject Alternative Name (SAN) extension
    try:
        san_extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for dns_name in san_extension.value.get_values_for_type(x509.DNSName):
            hostname_set.add(dns_name)
    except x509.ExtensionNotFound:
        pass

    # Extract from Common Name (CN) as fallback
    for name_attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        hostname_set.add(name_attribute.value)

    return hostname_set


def verify_cert_hostname(certificate: x509.Certificate, expected_hostname: str):
    """Verify certificate hostname matches expected value."""
    valid_hostnames = _get_cert_hostnames(certificate)
    
    if expected_hostname not in valid_hostnames:
        raise BadCertificate(
            f"Hostname verification failed: '{expected_hostname}' not found in {sorted(valid_hostnames)}"
        )


def verify_peer_certificate(
    peer_certificate: x509.Certificate,
    ca_certificate: x509.Certificate,
    expected_hostname: str,
    check_time: Optional[datetime.datetime] = None,
) -> None:
    """Perform complete PKI validation: validity, CA signature, and hostname."""
    verify_cert_validity(peer_certificate, check_time=check_time)
    verify_cert_signed_by_ca(peer_certificate, ca_certificate)
    verify_cert_hostname(peer_certificate, expected_hostname)