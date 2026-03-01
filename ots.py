"""
OpenTimestamps Bitcoin anchoring.
Properly constructs .ots detached timestamp files.
"""

import hashlib
import asyncio
import httpx
import struct
from typing import Optional
from database import db

OTS_CALENDARS = [
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
]

# OTS file magic: "\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OTS_MAGIC = b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94'
OTS_VERSION = b'\x01'

# OTS opcodes
OP_SHA256    = b'\x08'
OP_APPEND    = b'\xf0'
OP_PREPEND   = b'\xf1'
ATTESTATION_TAG = b'\x00\x05\x88\x96\x0d\x73\xd7\x19\x01'  # PendingAttestation


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def build_stamp_file(commitment_id: str, mac_hex: str, timestamp: str) -> str:
    """
    Build the stamp file text — identical to what the browser generates.
    This is what gets SHA256'd and submitted to OTS.
    Users drop this file on opentimestamps.org / dgi.io/ots alongside the .ots file to verify.
    Message and key are NOT included — stays private.
    """
    return "\n".join([
        "PSI-COMMIT STAMP",
        f"id: {commitment_id}",
        f"mac: {mac_hex}",
        f"timestamp: {timestamp}",
        "site: psicommit.com",
    ])


def build_ots_submit_digest(commitment_id: str, mac_hex: str, timestamp: str, psc_digest: str = None) -> bytes:
    """
    Get the 32-byte digest to submit to OTS.
    If psc_digest (stamp SHA256) is provided by browser, use it directly.
    Otherwise build the stamp file server-side and SHA256 it.
    """
    if psc_digest:
        return bytes.fromhex(psc_digest)
    stamp = build_stamp_file(commitment_id, mac_hex, timestamp)
    return sha256(stamp.encode('utf-8'))


def build_detached_ots_file(digest: bytes, calendar_receipt_body: bytes, calendar_url: str) -> bytes:
    """
    Build a proper .ots detached timestamp file from:
    - digest: the 32-byte SHA256 we submitted
    - calendar_receipt_body: the raw bytes returned by the calendar POST /digest
    - calendar_url: the calendar URL (encoded in PendingAttestation)

    Format:
      magic + version + file_hash_op(SHA256) + digest_length + digest + calendar_body
    """
    import io
    out = io.BytesIO()

    # Magic + version
    out.write(OTS_MAGIC)
    out.write(OTS_VERSION)

    # File hash operation: SHA256 (0x08)
    out.write(OP_SHA256)

    # The digest (32 bytes, length-prefixed as varint)
    out.write(_encode_varint(len(digest)))
    out.write(digest)

    # Append the calendar's response body (contains the merkle path + pending attestation)
    out.write(calendar_receipt_body)

    return out.getvalue()


def _encode_varint(n: int) -> bytes:
    """Encode integer as OTS varint."""
    result = b''
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            result += bytes([b | 0x80])
        else:
            result += bytes([b])
            break
    return result


async def anchor_commitment(commitment_id: str, mac_hex: str, timestamp: str = '', psc_digest: str = None):
    """Submit commitment stamp file digest to OTS calendar."""
    try:
        digest = build_ots_submit_digest(commitment_id, mac_hex, timestamp, psc_digest)
        print(f"[OTS] Submitting stamp digest: {digest.hex()[:16]}... for {commitment_id}")

        receipt_body = None
        used_calendar = None

        for calendar_url in OTS_CALENDARS:
            try:
                receipt_body = await submit_to_calendar(calendar_url, digest)
                if receipt_body:
                    used_calendar = calendar_url
                    break
            except Exception as e:
                print(f"[OTS] Calendar {calendar_url} failed: {e}")
                continue

        if receipt_body:
            # Build proper .ots file
            ots_file = build_detached_ots_file(digest, receipt_body, used_calendar)
            print(f"[OTS] Built .ots file: {len(ots_file)} bytes, magic check: {ots_file[:4].hex()}")

            await db.update_ots(
                commitment_id=commitment_id,
                ots_receipt=ots_file,
                ots_status="submitted"
            )
            # Also store the digest so we can check confirmation later
            await db.update_ots_digest(commitment_id, digest.hex())
            print(f"[OTS] {commitment_id} submitted via {used_calendar}")
        else:
            print(f"[OTS] Failed to submit {commitment_id} to any calendar.")

    except Exception as e:
        print(f"[OTS] Error anchoring {commitment_id}: {e}")


async def submit_to_calendar(calendar_url: str, digest: bytes) -> Optional[bytes]:
    """POST digest to OTS calendar, return raw response body."""
    url = f"{calendar_url}/digest"
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            url,
            content=digest,
            headers={"Content-Type": "application/octet-stream"}
        )
        print(f"[OTS] {calendar_url} -> {response.status_code}, {len(response.content)} bytes, starts: {response.content[:4].hex() if response.content else 'empty'}")

        if response.status_code == 200 and len(response.content) > 4:
            return response.content
        return None


async def check_ots_status(commitment_id: str, mac_hex: str, ots_receipt_hex: str, ots_digest: str = None, timestamp: str = '') -> dict:
    """Check if OTS receipt has been confirmed in a Bitcoin block."""
    try:
        digest = build_ots_submit_digest(commitment_id, mac_hex, timestamp, ots_digest)
        upgraded = await upgrade_receipt(digest)

        if upgraded:
            # Build a full .ots file first, THEN parse for block number
            ots_file = build_detached_ots_file(digest, upgraded, "confirmed")
            block_num = parse_bitcoin_block(ots_file)
            if block_num:
                await db.update_ots(
                    commitment_id=commitment_id,
                    ots_receipt=ots_file,
                    ots_status="confirmed",
                    bitcoin_block=block_num
                )
                return {"status": "confirmed", "bitcoin_block": block_num}

        return {"status": "pending", "message": "Bitcoin confirmation pending (~1-2 hours)."}

    except Exception as e:
        print(f"[OTS] check error: {e}")
        return {"status": "error", "message": str(e)}


async def upgrade_receipt(digest: bytes) -> Optional[bytes]:
    """Query calendar /timestamp/ endpoint to get confirmed receipt body."""
    commitment_hex = digest.hex()
    print(f"[OTS] Checking confirmation for: {commitment_hex[:16]}...")

    for calendar_url in OTS_CALENDARS:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{calendar_url}/timestamp/{commitment_hex}",
                    headers={"Accept": "application/octet-stream"}
                )
                if response.status_code == 200 and len(response.content) > 0:
                    print(f"[OTS] Confirmed receipt from {calendar_url} ({len(response.content)} bytes)")
                    return response.content
                elif response.status_code == 404:
                    print(f"[OTS] Not yet confirmed on {calendar_url}")
        except Exception as e:
            print(f"[OTS] Error: {calendar_url}: {e}")

    return None


def parse_bitcoin_block(receipt_bytes: bytes) -> Optional[int]:
    """Extract Bitcoin block number from confirmed OTS receipt."""
    try:
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        import io

        ctx = io.BytesIO(receipt_bytes)
        detached = DetachedTimestampFile.deserialize(ctx)

        def find_block(ts):
            for att in ts.attestations:
                if isinstance(att, BitcoinBlockHeaderAttestation):
                    return att.height
            for op, child in ts.ops.items():
                r = find_block(child)
                if r: return r
            return None

        block = find_block(detached.timestamp)
        if block:
            print(f"[OTS] Bitcoin block #{block}")
            return block
    except Exception as e:
        print(f"[OTS] Library parse failed: {e}")

    # Fallback heuristic
    try:
        for i in range(len(receipt_bytes) - 4):
            val = int.from_bytes(receipt_bytes[i:i+4], 'big')
            if 880_000 <= val <= 1_500_000:
                print(f"[OTS] Heuristic block #{val}")
                return val
    except Exception:
        pass

    return None


def get_ots_verify_url(commitment_id: str) -> str:
    return "https://opentimestamps.org"
