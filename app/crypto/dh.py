from __future__ import annotations
"""Diffie-Hellman key exchange utilities with AES key derivation."""

from dataclasses import dataclass
from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# Pre-defined DH group parameters (512-bit safe prime for demonstration)
# WARNING: This is NOT cryptographically secure for production use
_PRIME_MODULUS_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
)
PRIME_NUMBER = int(_PRIME_MODULUS_HEX, 16)
GENERATOR_VALUE = 2

# Initialize DH parameters from fixed constants
FIXED_DH_PARAMS = dh.DHParameterNumbers(PRIME_NUMBER, GENERATOR_VALUE).parameters()


@dataclass
class DHKeyPair:
    """Holds DH private key and serialized public key."""
    private_key: dh.DHPrivateKey
    public_bytes: bytes  # PEM-encoded public key

    @property
    def public_key(self) -> dh.DHPublicKey:
        """Get the public key component."""
        return self.private_key.public_key()


def generate_dh_parameters() -> dh.DHParameters:
    """Return the fixed DH parameters."""
    return FIXED_DH_PARAMS


def generate_dh_keypair(dh_params: dh.DHParameters | None = None) -> DHKeyPair:
    """Generate a new DH keypair using fixed or provided parameters."""
    if dh_params is None:
        dh_params = FIXED_DH_PARAMS
    
    private_key_obj = dh_params.generate_private_key()
    public_key_obj = private_key_obj.public_key()
    
    # Serialize public key to PEM format
    public_key_bytes = public_key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    
    return DHKeyPair(private_key=private_key_obj, public_bytes=public_key_bytes)


def load_peer_public_key(public_key_bytes: bytes) -> dh.DHPublicKey:
    """Deserialize peer's DH public key from PEM format."""
    return serialization.load_pem_public_key(public_key_bytes)


def derive_shared_key(my_private_key: dh.DHPrivateKey, peer_public_key: dh.DHPublicKey) -> bytes:
    """Derive 16-byte AES key from DH shared secret using SHA256 truncation."""
    # Extract DH parameters from both keys
    my_param_numbers = my_private_key.private_numbers().public_numbers.parameter_numbers
    peer_param_numbers = peer_public_key.public_numbers().parameter_numbers

    print("[DH_DEBUG] Local parameters: p =", hex(my_param_numbers.p), "g =", my_param_numbers.g)
    print("[DH_DEBUG] Peer parameters: p =", hex(peer_param_numbers.p), "g =", peer_param_numbers.g)

    # Verify parameters match
    if my_param_numbers.p != peer_param_numbers.p or my_param_numbers.g != peer_param_numbers.g:
        raise ValueError("DH parameter mismatch: peer using different group")

    # Perform DH exchange to get shared secret
    shared_secret_bytes = my_private_key.exchange(peer_public_key)
    
    # Hash and truncate to 16 bytes for AES-128
    secret_hash = sha256(shared_secret_bytes).digest()
    return secret_hash[:16]
