"""Secure chat message formatting with encryption and digital signatures."""
import json
import time
import struct
import os
from hashlib import sha256

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def apply_pkcs7_padding(data: bytes, block_length: int = 16) -> bytes:
    """Add PKCS#7 padding to data."""
    padding_size = block_length - (len(data) % block_length)
    return data + bytes([padding_size] * padding_size)


def remove_pkcs7_padding(data: bytes, block_length: int = 16) -> bytes:
    """Remove and validate PKCS#7 padding from data."""
    if not data or len(data) % block_length != 0:
        raise ValueError("Data length invalid for PKCS#7 padding")
    
    padding_size = data[-1]
    if padding_size < 1 or padding_size > block_length:
        raise ValueError(f"PKCS#7 padding size out of range: {padding_size}")
    
    if data[-padding_size:] != bytes([padding_size] * padding_size):
        raise ValueError("PKCS#7 padding bytes are corrupted")
    
    return data[:-padding_size]


def encrypt_with_aes_cbc(encryption_key: bytes, plaintext: bytes, init_vector: bytes) -> bytes:
    """Encrypt data using AES in CBC mode."""
    cipher_instance = Cipher(algorithms.AES(encryption_key), modes.CBC(init_vector))
    encryptor = cipher_instance.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt_with_aes_cbc(decryption_key: bytes, ciphertext: bytes, init_vector: bytes) -> bytes:
    """Decrypt data using AES in CBC mode."""
    cipher_instance = Cipher(algorithms.AES(decryption_key), modes.CBC(init_vector))
    decryptor = cipher_instance.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def load_private_key(filepath: str):
    """Load RSA private key from PEM file."""
    with open(filepath, "rb") as key_file:
        private_key_data = key_file.read()
    return serialization.load_pem_private_key(private_key_data, password=None)


def create_digital_signature(rsa_private_key, message_digest: bytes) -> bytes:
    """Create RSA signature over message digest using PKCS1v15."""
    return rsa_private_key.sign(
        message_digest,
        asy_padding.PKCS1v15(),
        hashes.SHA256(),
    )


def validate_digital_signature(rsa_public_key, message_digest: bytes, signature: bytes) -> None:
    """Verify RSA signature over message digest using PKCS1v15."""
    rsa_public_key.verify(
        signature,
        message_digest,
        asy_padding.PKCS1v15(),
        hashes.SHA256(),
    )


def build_chat_message(sequence_number: int, session_encryption_key: bytes, signing_key, message_text: str) -> bytes:
    """
    Construct a signed and encrypted chat message with length framing.
    
    Wire format: [4-byte length][JSON payload]
    JSON contains: seqno, ts, iv (hex), ct (hex), sig (hex)
    """
    # Generate timestamp and random initialization vector
    message_timestamp = time.time()
    initialization_vector = os.urandom(16)

    # Prepare and encrypt plaintext
    message_bytes = message_text.encode("utf-8")
    padded_message = apply_pkcs7_padding(message_bytes, 16)
    encrypted_message = encrypt_with_aes_cbc(session_encryption_key, padded_message, initialization_vector)

    # Compute hash over: sequence_number || timestamp || ciphertext
    sequence_bytes = struct.pack("!Q", sequence_number)  # 8-byte unsigned integer
    timestamp_bytes = struct.pack("!d", message_timestamp)  # 8-byte double
    message_hash = sha256(sequence_bytes + timestamp_bytes + encrypted_message).digest()

    # Create digital signature over hash
    digital_signature = create_digital_signature(signing_key, message_hash)

    # Assemble JSON payload
    message_payload = {
        "seqno": sequence_number,
        "ts": message_timestamp,
        "iv": initialization_vector.hex(),
        "ct": encrypted_message.hex(),
        "sig": digital_signature.hex(),
    }
    payload_bytes = json.dumps(message_payload).encode("utf-8")
    
    # Return length-prefixed message
    return struct.pack("!I", len(payload_bytes)) + payload_bytes


def parse_chat_message(wire_data: bytes, session_encryption_key: bytes, verification_key, previous_sequence: int) -> tuple[str, int]:
    """
    Parse, verify, and decrypt a length-prefixed chat message.
    
    Returns: (decrypted_text, current_sequence_number)
    Raises: ValueError for invalid messages or replay attacks
    """
    if len(wire_data) < 4:
        raise ValueError("Message data too short to contain length prefix")

    (payload_length,) = struct.unpack("!I", wire_data[:4])
    payload_data = wire_data[4:]
    
    if len(payload_data) != payload_length:
        raise ValueError("Message payload length mismatch")

    # Parse JSON payload
    message_data = json.loads(payload_data.decode("utf-8"))
    current_sequence = int(message_data["seqno"])
    message_timestamp = float(message_data["ts"])
    initialization_vector = bytes.fromhex(message_data["iv"])
    encrypted_data = bytes.fromhex(message_data["ct"])
    digital_signature = bytes.fromhex(message_data["sig"])

    # Enforce strict sequence ordering (replay protection)
    if current_sequence <= previous_sequence:
        raise ValueError(f"Sequence number violation: {current_sequence} <= {previous_sequence}")

    # Recompute hash for signature verification
    sequence_bytes = struct.pack("!Q", current_sequence)
    timestamp_bytes = struct.pack("!d", message_timestamp)
    computed_hash = sha256(sequence_bytes + timestamp_bytes + encrypted_data).digest()

    # Verify digital signature
    validate_digital_signature(verification_key, computed_hash, digital_signature)

    # Decrypt and unpad message
    padded_plaintext = decrypt_with_aes_cbc(session_encryption_key, encrypted_data, initialization_vector)
    plaintext_bytes = remove_pkcs7_padding(padded_plaintext, 16)
    
    return plaintext_bytes.decode("utf-8"), current_sequence