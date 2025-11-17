from __future__ import annotations
"""Protocol message models using Pydantic for validation."""

from pydantic import BaseModel


class Hello(BaseModel):
    """Client-to-server initial message with protocol version and DH public key."""
    proto: str = "SecureChat/1"
    dh_pub_b64: str  # Base64-encoded ephemeral DH public key


class ServerHello(BaseModel):
    """Server-to-client acknowledgment with protocol version and DH public key."""
    proto: str = "SecureChat/1"
    dh_pub_b64: str  # Base64-encoded ephemeral DH public key


class Register(BaseModel):
    """AES-encrypted registration data (email, username, password)."""
    ct_b64: str  # Base64-encoded encrypted JSON payload


class Login(BaseModel):
    """AES-encrypted login credentials (username, password)."""
    ct_b64: str  # Base64-encoded encrypted JSON payload