# Security Analysis: PSI-COMMIT v1.0

## Cryptographic Primitives

- **HMAC-SHA256**: Industry-standard MAC with 256-bit security
- **Random Generation**: `secrets.token_bytes()` (cryptographically secure)
- **Key Derivation**: Argon2id (optional, for passphrase-based keys)

## Security Properties

### What This Provides

✅ **Hiding**: Commitment reveals nothing about message before reveal
✅ **Binding**: Cannot change message after commitment without detection
✅ **Domain Separation**: Prevents cross-protocol attacks via domain tag
✅ **Freshness**: 32-byte nonce ensures unique commitments

### What This Does NOT Provide

❌ **Anonymity**: Commitments don't hide who made them
❌ **Forward Secrecy**: Key compromise allows forging past commitments
❌ **DoS Protection**: No rate limiting at protocol level
❌ **Time Ordering**: Timestamps are self-asserted

## Threat Model

### Assumptions

1. Attacker does NOT possess the 32-byte secret key
2. HMAC-SHA256 is collision-resistant
3. `secrets.token_bytes()` provides cryptographic randomness

### What Happens If Key Leaks

- Attacker can create valid commitments for any message
- Past commitments remain valid
- **Mitigation**: Rotate to new key, mark compromised commitments

### Timing Attacks

- **Protected**: Uses `hmac.compare_digest()` for constant-time comparison
- Prevents attackers from learning MAC bytes via timing side-channels

## Recommendations

1. **Store keys securely** (OS keychain, vault, etc.)
2. **Never commit keys to version control**
3. **Rotate keys periodically** for high-security applications
4. **Use Argon2id** for passphrase-based keys (not raw passphrases)

## Security Checklist

- [x] Uses `secrets.token_bytes()` for all randomness
- [x] Uses `hmac.compare_digest()` for constant-time comparison
- [x] 32-byte key requirement enforced
- [x] 32-byte nonce per commitment
- [x] Domain separation prevents replay attacks
- [x] Input validation on all parameters

## Reporting Vulnerabilities

Please report security issues to: [your-email@example.com]

## References

- RFC 2104: HMAC (Keyed-Hashing for Message Authentication)
- RFC 9106: Argon2 Memory-Hard Function
- NIST SP 800-90A: Recommendation for Random Number Generation