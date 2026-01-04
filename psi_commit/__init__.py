"""PSI-COMMIT: Cryptographic commitment scheme for verifiable decisions."""

from .core import (
    seal,
    verify,
    seal_with_passphrase,
    serialize_commitment,
    deserialize_commitment,
    canon,
    log
)

__version__ = "1.0.0"
__all__ = [
    "seal",
    "verify",
    "seal_with_passphrase",
    "serialize_commitment",
    "deserialize_commitment",
    "canon",
    "log"
]