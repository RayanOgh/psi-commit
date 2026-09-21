#!/usr/bin/env python3
"""
Tests for verify_psc.py.
Run with: pytest tests/test_verify_psc.py -v
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "verify_psc.py"
sys.path.insert(0, str(ROOT))

import verify_psc  # noqa: E402
from psi_commit.core import seal  # noqa: E402

# Fixed vector; expected values were computed independently with
# `openssl dgst -sha256 -mac HMAC` and `sha256sum`.
KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
NONCE = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
VECTOR_MAC = "55a866e8116cd58b25d3c73718b708942c0011acf8aefb9488189b3833bf5069"

STAMP_PSC = {
    "id": "psc_0011223344556677",
    "mac": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    "timestamp": "2026-01-02T03:04:05.678Z",
}
STAMP_TEXT = (
    "PSI-COMMIT STAMP\n"
    "id: psc_0011223344556677\n"
    "mac: 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n"
    "timestamp: 2026-01-02T03:04:05.678Z\n"
    "site: psicommit.com"
)
STAMP_SHA256 = "9b5ca564bb80cf077206ab0630c7e72c97165dd943e409ab5c76d1b5c7266ce7"


def make_psc(tmp_path, message, context="default", timestamp="2026-01-02T03:04:05.678Z", **extra):
    commitment, key = seal(message, context=context)
    psc = {
        "version": "1",
        "id": "psc_" + commitment["mac"][:16],
        "mac": commitment["mac"],
        "nonce": commitment["nonce"],
        "domain": commitment["domain"],
        "context": context,
        "timestamp": timestamp,
        "key": key.hex(),
        "ots_receipt": "00" + "ab" * 8,
        "ots_status": "submitted",
        "bitcoin_block": None,
        "tsa_receipt": "30" + "cd" * 8,
        "tsa_status": "confirmed",
        **extra,
    }
    path = tmp_path / "receipt.psc"
    path.write_text(json.dumps(psc), encoding="utf-8")
    return path, psc


def run(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *map(str, args)],
        capture_output=True, text=True, encoding="utf-8",
    )


def test_compute_mac_matches_independent_vector():
    assert verify_psc.compute_mac(KEY, "psi-commit.v1.test", NONCE, "hello world") == VECTOR_MAC


def test_compute_mac_matches_core_seal():
    commitment, key = seal("some message", context="ctx")
    mac = verify_psc.compute_mac(key.hex(), commitment["domain"], commitment["nonce"], "some message")
    assert mac == commitment["mac"]


def test_stamp_text_and_digest():
    stamp = verify_psc.build_stamp_file(STAMP_PSC)
    assert stamp == STAMP_TEXT
    assert hashlib.sha256(stamp.encode("utf-8")).hexdigest() == STAMP_SHA256


def test_timestamp_offset_normalized_to_z():
    psc = {**STAMP_PSC, "timestamp": "2026-01-02T03:04:05.678+00:00"}
    assert verify_psc.build_stamp_file(psc) == STAMP_TEXT


def test_verified_message_writes_exact_stamp(tmp_path):
    path, _ = make_psc(tmp_path, "Love 3", timestamp="2026-01-02T03:04:05.678+00:00")
    r = run(path, "--message", "Love 3")
    assert r.returncode == 0, r.stderr
    assert "MAC check:     VERIFIED" in r.stdout
    stamp = (tmp_path / "receipt.stamp.txt").read_bytes()
    assert not stamp.endswith(b"\n") and b"\r" not in stamp
    assert f"stamp SHA-256: {hashlib.sha256(stamp).hexdigest()}" in r.stdout
    assert (tmp_path / "receipt.stamp.txt.ots").read_bytes() == bytes.fromhex("00" + "ab" * 8)
    assert (tmp_path / "receipt.tsr").read_bytes() == bytes.fromhex("30" + "cd" * 8)


def test_message_is_trimmed_like_the_web_verifier(tmp_path):
    path, _ = make_psc(tmp_path, "padded")
    assert run(path, "--message", "  padded \n").returncode == 0


def test_unicode_message(tmp_path):
    path, _ = make_psc(tmp_path, "ünïcode 🎯")
    assert run(path, "--message", "ünïcode 🎯").returncode == 0


def test_message_file(tmp_path):
    path, _ = make_psc(tmp_path, "from a file")
    msg = tmp_path / "m.txt"
    msg.write_bytes(b"from a file\n")
    assert run(path, "--message-file", msg).returncode == 0


def test_wrong_message_fails(tmp_path):
    path, _ = make_psc(tmp_path, "right")
    r = run(path, "--message", "wrong")
    assert r.returncode == 1
    assert "FAILED" in r.stdout


def test_wrong_key_fails(tmp_path):
    path, psc = make_psc(tmp_path, "msg")
    psc["key"] = "11" * 32
    path.write_text(json.dumps(psc), encoding="utf-8")
    assert run(path, "--message", "msg").returncode == 1


def test_file_commitment_by_hash_and_by_file(tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(b"file contents")
    file_hash = hashlib.sha256(b"file contents").hexdigest()
    path, _ = make_psc(
        tmp_path, f"FILE_HASH:{file_hash}\nDESCRIPTION:Q3 report",
        file_hash=file_hash, file_description="Q3 report",
    )
    assert run(path, "--file-hash", file_hash).returncode == 0
    assert run(path, "--file", original).returncode == 0
    assert run(path, "--file-hash", file_hash, "--description", "other").returncode == 1


def test_wrong_file_fails(tmp_path):
    file_hash = hashlib.sha256(b"file contents").hexdigest()
    path, _ = make_psc(tmp_path, f"FILE_HASH:{file_hash}\nDESCRIPTION:d", file_description="d")
    assert run(path, "--file-hash", hashlib.sha256(b"tampered").hexdigest()).returncode == 1


def test_openssl_command_quotes_filenames_with_spaces(tmp_path):
    path, _ = make_psc(tmp_path, "msg")
    spaced = tmp_path / "PSC-abc Love 3.psc"
    path.rename(spaced)
    r = run(spaced, "--message", "msg")
    assert r.returncode == 0
    assert "-in 'PSC-abc Love 3.tsr'" in r.stdout
    assert "openssl ts -verify -digest" in r.stdout


def test_out_dir(tmp_path):
    path, _ = make_psc(tmp_path, "msg")
    out = tmp_path / "out"
    assert run(path, "--message", "msg", "--out-dir", out).returncode == 0
    assert (out / "receipt.stamp.txt").exists()


def test_receipt_without_proofs(tmp_path):
    path, psc = make_psc(tmp_path, "msg")
    psc["ots_receipt"] = psc["tsa_receipt"] = None
    path.write_text(json.dumps(psc), encoding="utf-8")
    r = run(path, "--message", "msg")
    assert r.returncode == 0
    assert "no proof" in r.stdout and "no token" in r.stdout


@pytest.mark.parametrize("missing", ["key", "nonce", "mac", "id", "timestamp"])
def test_missing_field_is_bad_input(tmp_path, missing):
    path, psc = make_psc(tmp_path, "msg")
    del psc[missing]
    path.write_text(json.dumps(psc), encoding="utf-8")
    assert run(path, "--message", "msg").returncode == 2


def test_invalid_json_and_bad_hex_are_bad_input(tmp_path):
    bad = tmp_path / "bad.psc"
    bad.write_text("not json", encoding="utf-8")
    assert run(bad, "--message", "x").returncode == 2
    path, psc = make_psc(tmp_path, "msg")
    psc["nonce"] = "zz"
    path.write_text(json.dumps(psc), encoding="utf-8")
    assert run(path, "--message", "msg").returncode == 2
