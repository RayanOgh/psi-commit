#!/usr/bin/env python3
"""
Standalone PSI-COMMIT verifier. Python 3 standard library only; makes no
network requests and does not depend on psicommit.com.

Given a .psc receipt and the original message (or the original file), it:

  1. Recomputes the MAC: HMAC-SHA256(key, domain || nonce || message), the
     same construction as psi_commit/core.py and computeHMAC in
     static/index.html.
  2. Rebuilds the stamp text (buildStampFile in static/index.html), prints its
     SHA-256, and writes it to <name>.stamp.txt. That SHA-256 is the digest
     that was submitted to OpenTimestamps and to the RFC 3161 TSA.
  3. Writes the receipt's .ots and .tsr proofs (if present) next to it so they
     can be checked independently.

Usage:
  python verify_psc.py receipt.psc --message "the original message"
  python verify_psc.py receipt.psc --message-file message.txt
  python verify_psc.py receipt.psc --file original.pdf
  python verify_psc.py receipt.psc --file-hash <sha256 hex of the original file>

For file commitments the committed message is
"FILE_HASH:<sha256>\\nDESCRIPTION:<description>"; the description is read from
the .psc (override with --description).

Exit status: 0 if the MAC matches, 1 if it does not, 2 on bad input.
"""

import argparse
import hashlib
import hmac
import json
import re
import shlex
import sys
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def compute_mac(key_hex: str, domain: str, nonce_hex: str, message: str) -> str:
    """HMAC-SHA256(key, domain || nonce || message), hex."""
    return hmac.new(
        bytes.fromhex(key_hex),
        domain.encode("utf-8") + bytes.fromhex(nonce_hex) + message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def normalize_timestamp(ts: str) -> str:
    """Servers may store +00:00; the browser stamped ...Z (see ots.normalize_timestamp)."""
    return ts[:-6] + "Z" if ts.endswith("+00:00") else ts


def build_stamp_file(psc: dict) -> str:
    """Mirror of buildStampFile in static/index.html: no trailing newline."""
    return "\n".join([
        "PSI-COMMIT STAMP",
        f"id: {psc['id']}",
        f"mac: {psc['mac']}",
        f"timestamp: {normalize_timestamp(psc['timestamp'])}",
        "site: psicommit.com",
    ])


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_message(psc: dict, args) -> str:
    file_mode = args.file or args.file_hash
    if file_mode:
        file_hash = sha256_file(Path(args.file)) if args.file else args.file_hash.strip().lower()
        if not HEX64.match(file_hash):
            die("file hash must be 64 lowercase hex characters")
        description = args.description if args.description is not None else psc.get("file_description")
        if description is None:
            die("no file description in the .psc; pass --description")
        if psc.get("file_hash") and psc["file_hash"] != file_hash:
            print(f"note: file hash {file_hash} differs from the .psc file_hash {psc['file_hash']}")
        return f"FILE_HASH:{file_hash}\nDESCRIPTION:{description.strip()}"

    if args.message_file:
        message = Path(args.message_file).read_bytes().decode("utf-8")
    else:
        message = args.message
    return message.strip()  # the web verifier trims the message before hashing


def hex_bytes(value, field: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except (TypeError, ValueError):
        die(f".psc field '{field}' is not valid hex")


def main() -> None:
    ap = argparse.ArgumentParser(description="Verify a PSI-COMMIT .psc receipt offline.")
    ap.add_argument("psc", help="path to the .psc receipt")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--message", help="the original message text")
    src.add_argument("--message-file", help="file containing the original message (UTF-8)")
    src.add_argument("--file", help="the original file (for file commitments)")
    src.add_argument("--file-hash", help="SHA-256 hex of the original file (for file commitments)")
    ap.add_argument("--description", help="file description (defaults to the one in the .psc)")
    ap.add_argument("--out-dir", help="where to write stamp/proof files (default: next to the .psc)")
    args = ap.parse_args()

    psc_path = Path(args.psc)
    try:
        psc = json.loads(psc_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        die(f"cannot read {psc_path}: {e}")

    for field in ("id", "mac", "nonce", "key", "timestamp"):
        if not psc.get(field):
            die(f".psc is missing '{field}'")
    hex_bytes(psc["key"], "key")
    hex_bytes(psc["nonce"], "nonce")

    context = psc.get("context") or "default"
    derived_domain = f"psi-commit.v1.{context}"
    domain = psc.get("domain") or derived_domain
    if domain != derived_domain:
        print(f"warning: .psc domain '{domain}' != '{derived_domain}' derived from context")

    message = resolve_message(psc, args)
    actual = compute_mac(psc["key"], domain, psc["nonce"], message)
    valid = hmac.compare_digest(actual.lower(), psc["mac"].strip().lower())

    print(f"id:            {psc['id']}")
    print(f"domain:        {domain}")
    print(f"expected MAC:  {psc['mac']}")
    print(f"computed MAC:  {actual}")
    print(f"MAC check:     {'VERIFIED' if valid else 'FAILED - message or key does not match'}")

    stamp = build_stamp_file(psc)
    stamp_bytes = stamp.encode("utf-8")
    stamp_digest = hashlib.sha256(stamp_bytes).hexdigest()

    out_dir = Path(args.out_dir) if args.out_dir else psc_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / psc_path.stem
    stamp_path = base.with_name(base.name + ".stamp.txt")
    stamp_path.write_bytes(stamp_bytes)  # bytes: no newline translation, no trailing newline

    print()
    print(f"stamp SHA-256: {stamp_digest}")
    print(f"stamp file:    {stamp_path}")

    ots_hex, tsa_hex = psc.get("ots_receipt"), psc.get("tsa_receipt")
    print()
    if ots_hex:
        ots_path = base.with_name(base.name + ".stamp.txt.ots")
        ots_path.write_bytes(hex_bytes(ots_hex, "ots_receipt"))
        block = psc.get("bitcoin_block")
        print(f"OpenTimestamps: {psc.get('ots_status') or 'unknown'}"
              + (f", Bitcoin block {block}" if block else ""))
        print(f"  Wrote {ots_path}")
        print(f"  Drop {stamp_path.name} and {ots_path.name} on https://opentimestamps.org")
        print(f"  (or: ots verify {shlex.quote(ots_path.name)}, with {shlex.quote(stamp_path.name)} alongside)")
        if not block:
            print("  Not yet anchored in Bitcoin; a pending proof will not fully verify.")
    else:
        print("OpenTimestamps: no proof in this .psc")

    print()
    if tsa_hex:
        tsr_path = base.with_name(base.name + ".tsr")
        tsr_path.write_bytes(hex_bytes(tsa_hex, "tsa_receipt"))
        print(f"RFC 3161 TSA:   {psc.get('tsa_status') or 'unknown'}")
        print(f"  Wrote {tsr_path}")
        print("  Fetch the FreeTSA chain once:")
        print("    curl -O https://freetsa.org/files/cacert.pem")
        print("    curl -O https://freetsa.org/files/tsa.crt")
        print("  Then check the token against the stamp digest:")
        print(f"    openssl ts -verify -digest {stamp_digest} \\")
        print(f"      -in {shlex.quote(tsr_path.name)} -CAfile cacert.pem -untrusted tsa.crt")
        print("  Expect: Verification: OK")
        print(f"  Token details: openssl ts -reply -in {shlex.quote(tsr_path.name)} -text")
    else:
        print("RFC 3161 TSA:   no token in this .psc")

    sys.exit(0 if valid else 1)


if __name__ == "__main__":
    main()
