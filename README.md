# PSI-COMMIT

Cryptographic commitment scheme for verifiable decisions, predictions, and experimental pre-registration.

[![Python](https://img.shields.io/badge/python-3.8+-blue)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

## What Is This?

PSI-COMMIT lets you **prove you made a decision before seeing the outcome**.

**Use cases:**
- 🔬 Scientific pre-registration (prevent p-hacking)
- 📊 Prediction tracking (prove you called it)
- 🤝 Team accountability (record positions before decisions)
- 🎲 Fair gaming (commit moves simultaneously)
- 📝 Contract commitments (bind to terms before negotiation)

## How It Works
```
1. COMMIT
   You: "I predict the stock will go up"
   System: Creates cryptographic commitment
   Result: Commitment hash (public) + Secret key (private)

2. WAIT
   Events unfold...
   Your commitment is public but message is hidden

3. REVEAL
   You: Reveal message + key
   Anyone: Can verify you committed to it before
```

**Security:** Uses HMAC-SHA256 (256-bit security). Cryptographically impossible to:
- Change your message after commitment
- Create fake "backdated" commitments
- Guess the message from the commitment

## Quick Start

### Installation
```bash
pip install psi-commit
```

### Command Line Usage
```bash
# Create a commitment
psi-commit commit "The S&P 500 will close above 5000 on Friday" -o my-prediction.json

# Output:
# ✓ Commitment saved to my-prediction.json
# ✓ Keep your key safe: 8f3a2b9c...

# Later, verify your commitment
psi-commit verify-cmd "The S&P 500 will close above 5000 on Friday" \
    8f3a2b9c... \
    my-prediction.json

# Output:
# ✓ VERIFIED: Commitment matches message and key
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

## Real-World Example: Scientific Pre-Registration
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
✅ Cryptographic binding (can't change message)
✅ Cryptographic hiding (commitment reveals nothing)
✅ Domain separation (prevents replay attacks)

**What this does NOT provide:**
❌ Anonymity (doesn't hide who made commitment)
❌ Forward secrecy (key compromise allows forging)
❌ Byzantine fault tolerance (requires trust in key holder)

**Threat model:** See [SECURITY.md](SECURITY.md) for complete analysis.

## CLI Commands
```bash
# Create commitment
psi-commit commit "message" -o output.json

# Verify commitment
psi-commit verify-cmd "message" <key-hex> commitment.json

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
# Unit tests
pytest tests/

# Install test dependencies first
pip install pytest hypothesis
```

## Project Structure
```
psi-commit/
├── psi_commit/
│   ├── core.py           # Core seal/verify functions
│   └── cli.py            # Command-line interface
├── tests/
│   └── __init__.py
├── setup.py              # Package configuration
├── requirements.txt      # Dependencies
├── test_vectors.json     # Test cases
└── README.md            # This file
```

## FAQ

**Q: How is this different from just hashing my message?**

A: Hashing reveals the message to anyone who can guess it. PSI-COMMIT uses a secret key, so the commitment reveals nothing until you choose to reveal it.

**Q: Can I lose my key?**

A: Yes. If you lose your key, you cannot prove what you committed to. This is by design - the key is what proves ownership.

**Q: Is this a blockchain?**

A: No. It uses cryptographic commitments but is much simpler than blockchain. You can optionally anchor commitments in Bitcoin via OpenTimestamps.

**Q: What if I want to commit to the same message twice?**

A: Each commitment includes a random nonce, so the same message produces different commitments. This prevents fingerprinting.

## License

MIT License - see [LICENSE](LICENSE) file.

## Citation

If you use PSI-COMMIT in research, please cite:
```bibtex
@software{psi_commit,
  title = {PSI-COMMIT: Cryptographic Commitment Scheme for Verifiable Decisions},
  author = {Rayan Oghabian},
  year = {2024},
  url = {https://github.com/RayanOgh/psi-commit}
}
```

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit pull request

## Contact

- GitHub: https://github.com/RayanOgh/psi-commit
- Issues: https://github.com/RayanOgh/psi-commit/issues

---

**Made with 🔒 for verifiable decisions**