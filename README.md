# PSI-COMMIT

Cryptographic commitment scheme for verifiable decisions, predictions, and experimental pre-registration.

[![Python](https://img.shields.io/badge/python-3.8+-blue)](https://www.python.org/)


## What Is This?

PSI-COMMIT lets you **prove you made a decision before seeing the outcome**.

**Use cases:**
- 🔬 Scientific pre-registration (prevent p-hacking)
- 📊 Prediction tracking (prove you called it)
- 🤝 Team accountability (record positions before decisions)
- 🎲 Fair gaming (commit moves simultaneously)
- 📝 Contract commitments (bind to terms before negotiation)

## How It Works

**1. COMMIT**
- You: "I predict the stock will go up"
- System: Creates cryptographic commitment
- Result: Commitment hash (public) + Secret key (private)

**2. WAIT**
- Events unfold...
- Your commitment is public but message is hidden

**3. REVEAL**
- You: Reveal message + key
- Anyone: Can verify you committed to it before

**Security:** Uses HMAC-SHA256 (256-bit security). Cryptographically impossible to:
- Change your message after commitment
- Create fake "backdated" commitments
- Guess the message from the commitment

## Quick Start

### Installation
```bash
pip install -e .
```

### Command Line Usage
```bash
# Create a commitment
psi-commit commit "The S&P 500 will close above 5000 on Friday" -o my-prediction.json

# Verify your commitment
psi-commit verify "The S&P 500 will close above 5000 on Friday" <key-hex> my-prediction.json
```

### Python API
```python
from psi_commit import seal, verify

# Create commitment
commitment, key = seal("My prediction here")

# Later, verify
is_valid = verify("My prediction here", key, commitment)
# Returns: True
```

## Features

### ✅ Cryptographically Secure
- HMAC-SHA256 (256-bit security)
- Constant-time comparison (prevents timing attacks)
- Cryptographically secure randomness

### ✅ Standards-Based
- JSON Canonicalization Scheme (RFC 8785)
- Domain separation (prevents cross-protocol attacks)
- Versioned format (forward compatibility)

### ✅ Production-Ready
- Comprehensive test suite (pytest + Hypothesis)
- Property-based testing
- Test vectors for cross-implementation compatibility
- Security documentation with threat model

## Documentation

- [SPECIFICATION.md](SPECIFICATION.md) - Technical specification
- [SECURITY.md](SECURITY.md) - Threat model and security analysis

## Real-World Example
```python
from psi_commit import seal, verify

# Before experiment
hypothesis = "Drug X will reduce symptoms by >20% vs placebo (p<0.05)"
commitment, key = seal(hypothesis, context="clinical-trial-2024")

# Save commitment publicly before running experiment
print(f"Commitment: {commitment}")

# ... run experiment ...

# After experiment
is_valid = verify(hypothesis, key, commitment)
# Proof you didn't change hypothesis after seeing data
```

## Security

**What this provides:**
- ✅ Cryptographic binding (can't change message)
- ✅ Cryptographic hiding (commitment reveals nothing)
- ✅ Domain separation (prevents replay attacks)

**What this does NOT provide:**
- ❌ Anonymity (doesn't hide who made commitment)
- ❌ Forward secrecy (key compromise allows forging)
- ❌ Byzantine fault tolerance (requires trust in key holder)

See [SECURITY.md](SECURITY.md) for complete threat model.

## CLI Commands
```bash
# Create commitment
psi-commit commit "message" -o output.json

# Verify commitment
psi-commit verify "message" <key-hex> commitment.json

# Show commitment info
psi-commit info commitment.json

# Generate new key
psi-commit genkey -o my-key.bin
```

## Development

### Setup
```bash
git clone https://github.com/RayanOgh/psi-commit
cd psi-commit
pip install -e ".[dev]"
```

### Run Tests
```bash
pytest tests/ -v
```

## Project Structure
```
psi-commit/
├── psi_commit/
│   ├── core.py           # Core seal/verify functions
│   ├── cli.py            # Command-line interface
│   ├── log.py            # Append-only hash-chained log
│   └── timestamp.py      # OpenTimestamps integration
├── tests/
│   └── test_properties.py
├── SPECIFICATION.md      # Technical specification
├── SECURITY.md           # Threat model
├── setup.py
└── README.md
```

## FAQ

**Q: How is this different from just hashing my message?**

A: Hashing reveals the message to anyone who can guess it. PSI-COMMIT uses a secret key, so the commitment reveals nothing until you choose to reveal it.

**Q: Can I lose my key?**

A: Yes. If you lose your key, you cannot prove what you committed to. This is by design - the key is what proves ownership.

**Q: Is this a blockchain?**

A: No. It uses cryptographic commitments but is much simpler than blockchain. You can optionally anchor commitments in Bitcoin via OpenTimestamps.

## License

MIT License - see [LICENSE](LICENSE) file.

## Links

- **GitHub:** https://github.com/RayanOgh/psi-commit
- **Issues:** https://github.com/RayanOgh/psi-commit/issues
- **Demo:** https://github.com/RayanOgh/psi-commit/issues/1

---

**Made with 🔒 for verifiable decisions**
