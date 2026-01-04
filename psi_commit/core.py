#!/usr/bin/env python3
"""
PSI-COMMIT v1.0
Cryptographic commitment scheme with HMAC-SHA256
Specification: SPECIFICATION.md
"""

import secrets
import hmac
import hashlib
import json
from typing import Tuple, Optional
try:
    import jcs
except ImportError:
    raise ImportError("Install jcs: pip install jcs")

__version__ = "1.0.0"


def seal(
    message: str,
    key: Optional[bytes] = None,
    context: str = "default"
) -> Tuple[dict, bytes]:
    """
    Create a cryptographic commitment to a message.
    
    Args:
        message: The message to commit to (will be UTF-8 encoded)
        key: 32-byte secret key (generated if None)
        context: Domain context for separation (default: "default")
    
    Returns:
        (commitment_dict, secret_key)
    
    Raises:
        ValueError: If key is provided but not exactly 32 bytes
    """
    # Validate or generate key
    if key is None:
        key = secrets.token_bytes(32)
    elif len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes")
    
    # Generate fresh nonce
    nonce = secrets.token_bytes(32)
    
    # Domain separation
    domain = f"psi-commit.v1.{context}"
    
    # Compute MAC
    mac = hmac.new(
        key,
        domain.encode("utf-8") + nonce + message.encode("utf-8"),
        hashlib.sha256
    ).digest()
    
    # Build commitment
    commitment = {
        "v": 1,
        "alg": "HMAC-SHA256",
        "domain": domain,
        "nonce": nonce.hex(),
        "mac": mac.hex()
    }
    
    return commitment, key


def verify(message: str, key: bytes, commitment: dict) -> bool:
    """
    Verify a commitment matches the message and key.
    
    Args:
        message: The claimed message
        key: The secret key
        commitment: The commitment dictionary
    
    Returns:
        True if valid, False otherwise
    
    Raises:
        ValueError: If commitment format is invalid
        KeyError: If required fields missing from commitment
    """
    # Validate commitment structure
    required_fields = {"v", "alg", "domain", "nonce", "mac"}
    if not required_fields.issubset(commitment.keys()):
        raise ValueError(f"Commitment missing required fields: {required_fields - commitment.keys()}")
    
    if commitment["v"] != 1:
        raise ValueError(f"Unsupported version: {commitment['v']}")
    
    if commitment["alg"] != "HMAC-SHA256":
        raise ValueError(f"Unsupported algorithm: {commitment['alg']}")
    
    if len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes")
    
    # Extract parameters
    domain = commitment["domain"].encode("utf-8")
    nonce = bytes.fromhex(commitment["nonce"])
    mac_expected = bytes.fromhex(commitment["mac"])
    
    # Recompute MAC
    mac_actual = hmac.new(
        key,
        domain + nonce + message.encode("utf-8"),
        hashlib.sha256
    ).digest()
    
    # Constant-time comparison
    return hmac.compare_digest(mac_actual, mac_expected)


def seal_with_passphrase(
    message: str,
    passphrase: str,
    salt: Optional[bytes] = None,
    context: str = "default"
) -> Tuple[dict, bytes, bytes]:
    """
    Create commitment using passphrase (Argon2id key derivation).
    
    Args:
        message: Message to commit to
        passphrase: User passphrase
        salt: 16-byte salt (generated if None)
        context: Domain context
    
    Returns:
        (commitment_dict, derived_key, salt)
    
    Requires: pip install argon2-cffi
    """
    try:
        from argon2 import PasswordHasher
        from argon2.low_level import hash_secret_raw, Type
    except ImportError:
        raise ImportError("Install argon2-cffi: pip install argon2-cffi")
    
    if salt is None:
        salt = secrets.token_bytes(16)
    elif len(salt) != 16:
        raise ValueError("Salt must be exactly 16 bytes")
    
    # Derive key with Argon2id
    key = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=2,
        memory_cost=64 * 1024,  # 64 MB
        parallelism=1,
        hash_len=32,
        type=Type.ID
    )
    
    commitment, _ = seal(message, key=key, context=context)
    return commitment, key, salt


# Canonical JSON serialization
def serialize_commitment(commitment: dict) -> bytes:
    """Serialize commitment using JCS (RFC 8785)"""
    return jcs.canonicalize(commitment)


def deserialize_commitment(data: bytes) -> dict:
    """Deserialize commitment from JCS bytes"""
    return json.loads(data)