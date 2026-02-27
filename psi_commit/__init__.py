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

from .log import CommitmentLog

# OpenTimestamps is optional
try:
    from .timestamp import (
        create_timestamp,
        verify_timestamp,
        info_timestamp
    )
    HAS_OPENTIMESTAMPS = True
except ImportError:
    HAS_OPENTIMESTAMPS = False

__version__ = "1.0.0"
__all__ = [
    "seal",
    "verify",
    "seal_with_passphrase",
    "serialize_commitment",
    "deserialize_commitment",
    "canon",
    "log",
    "CommitmentLog"
]

if HAS_OPENTIMESTAMPS:
    __all__.extend(["create_timestamp", "verify_timestamp", "info_timestamp"])