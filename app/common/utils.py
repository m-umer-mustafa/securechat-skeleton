"""Utility functions for encoding, hashing, and network I/O."""
from __future__ import annotations

import base64
import time
from hashlib import sha256
import struct
import socket


def current_timestamp_ms() -> int:
    """Get current time in milliseconds since epoch."""
    return int(time.time() * 1000)


def encode_base64(data: bytes) -> str:
    """Encode bytes to base64 ASCII string."""
    return base64.b64encode(data).decode("ascii")


def decode_base64(encoded_str: str) -> bytes:
    """Decode base64 ASCII string to bytes."""
    return base64.b64decode(encoded_str.encode("ascii"))


def compute_sha256_hex(data: bytes) -> str:
    """Compute SHA256 hash and return as hex string."""
    return sha256(data).hexdigest()


def receive_exact_bytes(connection: socket.socket, byte_count: int) -> bytes:
    """Receive exact number of bytes from socket."""
    buffer = b""
    while len(buffer) < byte_count:
        chunk = connection.recv(byte_count - len(buffer))
        if not chunk:
            raise ConnectionError("Connection closed while receiving data")
        buffer += chunk
    return buffer


def recv_cert(connection: socket.socket) -> bytes:
    """Receive length-prefixed certificate (4-byte length + PEM data)."""
    length_data = receive_exact_bytes(connection, 4)
    (certificate_length,) = struct.unpack("!I", length_data)
    return receive_exact_bytes(connection, certificate_length)


def send_cert(connection: socket.socket, certificate_pem: bytes) -> None:
    """Send length-prefixed certificate."""
    connection.sendall(struct.pack("!I", len(certificate_pem)) + certificate_pem)


def recv_dh_pub(connection: socket.socket) -> bytes:
    """Receive length-prefixed DH public key (4-byte length + key data)."""
    length_data = receive_exact_bytes(connection, 4)
    (key_length,) = struct.unpack("!I", length_data)
    return receive_exact_bytes(connection, key_length)


def send_dh_pub(connection: socket.socket, dh_public_key: bytes) -> None:
    """Send length-prefixed DH public key."""
    connection.sendall(struct.pack("!I", len(dh_public_key)) + dh_public_key)