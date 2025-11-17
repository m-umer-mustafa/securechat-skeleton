"""Offline verification tool for session receipts with signature validation."""
import struct
from hashlib import sha256

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

RECEIPT_FILE_PATH = "server_session_receipt.txt"  # or client_session_receipt.txt
CERTIFICATE_FILE_PATH = "certs/server/cert.pem"  # or certs/client/cert.pem


def extract_public_key(certificate_file_path: str):
    """Load public key from X.509 certificate file."""
    with open(certificate_file_path, "rb") as cert_file:
        certificate_data = cert_file.read()
    certificate = x509.load_pem_x509_certificate(certificate_data)
    return certificate.public_key()


def verify_session_receipt():
    """Verify integrity and authenticity of session receipt."""
    # Read and parse receipt file
    with open(RECEIPT_FILE_PATH, "r", encoding="utf-8") as receipt_file:
        receipt_lines = receipt_file.readlines()

    # Extract components from receipt
    transcript_content = []
    stored_hash_hex = None
    stored_signature_hex = None
    
    for line in receipt_lines:
        if line.startswith("HASH:"):
            stored_hash_hex = line.strip().split("HASH:")[1]
        elif line.startswith("SIG:"):
            stored_signature_hex = line.strip().split("SIG:")[1]
        elif line.startswith("TRANSCRIPT:") or not line.strip():
            continue
        else:
            transcript_content.append(line)

    if stored_hash_hex is None or stored_signature_hex is None:
        raise ValueError("Receipt file is missing HASH or SIG field")

    # Recompute transcript hash for verification
    transcript_bytes = "".join(transcript_content).encode("utf-8")
    recomputed_hash_digest = sha256(transcript_bytes).digest()
    stored_hash_digest = bytes.fromhex(stored_hash_hex)

    print("[VERIFICATION] Stored hash:    ", stored_hash_hex)
    print("[VERIFICATION] Recomputed hash:", recomputed_hash_digest.hex())
    print("[VERIFICATION] Hash match:", stored_hash_digest == recomputed_hash_digest)

    # Verify RSA signature on hash
    signature_bytes = bytes.fromhex(stored_signature_hex)
    public_key = extract_public_key(CERTIFICATE_FILE_PATH)

    public_key.verify(
        signature_bytes,
        stored_hash_digest,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    print("[VERIFICATION] Digital signature is VALID")


if __name__ == "__main__":
    verify_session_receipt()