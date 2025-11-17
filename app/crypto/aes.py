"""AES-128 encryption/decryption using ECB mode with PKCS#7 padding."""
from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


AES_BLOCK_SIZE = 16  # AES block size in bytes


def apply_pkcs7_padding(plaintext: bytes) -> bytes:
    """Apply PKCS#7 padding to data to make it a multiple of block size."""
    padding_length = AES_BLOCK_SIZE - (len(plaintext) % AES_BLOCK_SIZE)
    padding_byte = bytes([padding_length])
    return plaintext + (padding_byte * padding_length)


def remove_pkcs7_padding(padded_data: bytes) -> bytes:
    """Remove PKCS#7 padding from data and validate correctness."""
    if len(padded_data) == 0:
        raise ValueError("Cannot remove padding from empty data")
    
    padding_length = padded_data[-1]
    
    if padding_length < 1 or padding_length > AES_BLOCK_SIZE:
        raise ValueError(f"Invalid padding length: {padding_length}")
    
    # Verify all padding bytes are identical
    expected_padding = bytes([padding_length]) * padding_length
    if padded_data[-padding_length:] != expected_padding:
        raise ValueError("Padding bytes do not match expected pattern")
    
    return padded_data[:-padding_length]


def aes_encrypt_ecb(encryption_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext using AES-128-ECB with PKCS#7 padding."""
    if len(encryption_key) != 16:
        raise ValueError("AES-128 requires a 16-byte encryption key")
    
    cipher_engine = Cipher(algorithms.AES(encryption_key), modes.ECB())
    encryptor_instance = cipher_engine.encryptor()
    
    padded_plaintext = apply_pkcs7_padding(plaintext)
    ciphertext = encryptor_instance.update(padded_plaintext) + encryptor_instance.finalize()
    
    return ciphertext


def aes_decrypt_ecb(decryption_key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext using AES-128-ECB and remove PKCS#7 padding."""
    if len(decryption_key) != 16:
        raise ValueError("AES-128 requires a 16-byte decryption key")
    
    cipher_engine = Cipher(algorithms.AES(decryption_key), modes.ECB())
    decryptor_instance = cipher_engine.decryptor()
    
    padded_plaintext = decryptor_instance.update(ciphertext) + decryptor_instance.finalize()
    plaintext = remove_pkcs7_padding(padded_plaintext)
    
    return plaintext