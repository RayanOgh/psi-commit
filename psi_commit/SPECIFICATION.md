# PSI-COMMIT Specification v1.0

## Overview

PSI-COMMIT is a cryptographic commitment scheme using HMAC-SHA256 for verifiable pre-registration of decisions, predictions, and experimental hypotheses.

## Commitment Format
```json
{
  "v": 1,
  "alg": "HMAC-SHA256",
  "domain": "psi-commit.v1.{context}",
  "nonce": "<64-char-hex>",
  "mac": "<64-char-hex>"
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `v` | integer | Protocol version (currently 1) |
| `alg` | string | Algorithm identifier (must be "HMAC-SHA256") |
| `domain` | string | Domain separation tag (format: "psi-commit.v1.{context}") |
| `nonce` | string | 32-byte random nonce (hex-encoded) |
| `mac` | string | HMAC output (hex-encoded) |

## Key Requirements

- **Secret key**: Exactly 32 bytes (256 bits)
- **Generation**: `secrets.token_bytes(32)` or Argon2id-stretched passphrase
- **Nonce**: Fresh 32 bytes per commitment via `secrets.token_bytes(32)`

## HMAC Construction
```
mac = HMAC-SHA256(key, domain || nonce || message)
```

Where:
- `domain`: UTF-8 encoded domain string
- `nonce`: 32 raw bytes
- `message`: UTF-8 encoded message
- `||`: Concatenation

## Verification
```python
def verify(message, key, commitment):
    domain = commitment["domain"].encode("utf-8")
    nonce = bytes.fromhex(commitment["nonce"])
    mac_expected = bytes.fromhex(commitment["mac"])
    
    mac_actual = hmac.new(
        key,
        domain + nonce + message.encode("utf-8"),
        hashlib.sha256
    ).digest()
    
    return hmac.compare_digest(mac_actual, mac_expected)
```

**Note:** Uses `hmac.compare_digest()` for constant-time comparison to prevent timing attacks.

## Passphrase Derivation (Optional)

If using passphrase instead of raw key:
```
key = Argon2id(
    password=passphrase,
    salt=user_provided_salt,
    time_cost=2,
    memory_cost=64MB,
    parallelism=1,
    hash_length=32
)
```

## Security Properties

### Hiding
Commitment reveals nothing about the message before reveal.

### Binding
Cannot change the message after commitment without detection.

### Domain Separation
Commitments in different contexts cannot be confused or replayed.

## Version History

- **v1.0** (2025-01-04): Initial specification