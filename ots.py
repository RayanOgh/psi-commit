"""
OpenTimestamps Bitcoin anchoring.
Constructs .ots detached timestamp files and handles upgrade/confirmation.
"""

import hashlib
import asyncio
import httpx
import io
from typing import Optional, List, Dict
from database import db

OTS_CALENDARS = [
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
]

# OTS file header
OTS_MAGIC = b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94'
OTS_VERSION = b'\x01'
OP_SHA256 = b'\x08'


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def build_stamp_file(commitment_id: str, mac_hex: str, timestamp: str) -> str:
    """
    Build the stamp file text — identical to what the browser generates.
    This is what gets SHA256'd and submitted to OTS.
    """
    return "\n".join([
        "PSI-COMMIT STAMP",
        f"id: {commitment_id}",
        f"mac: {mac_hex}",
        f"timestamp: {timestamp}",
        "site: psicommit.com",
    ])


def normalize_timestamp(ts: str) -> str:
    """Normalize Supabase +00:00 back to Z to match browser format."""
    if ts.endswith('+00:00'):
        ts = ts[:-6] + 'Z'
    return ts


def build_ots_submit_digest(commitment_id: str, mac_hex: str, timestamp: str, psc_digest: str = None) -> bytes:
    """Get the 32-byte digest to submit to OTS."""
    if psc_digest:
        return bytes.fromhex(psc_digest)
    stamp = build_stamp_file(commitment_id, mac_hex, normalize_timestamp(timestamp))
    return sha256(stamp.encode('utf-8'))


def build_detached_ots_file(digest: bytes, calendar_receipt_body: bytes, calendar_url: str) -> bytes:
    """
    Build a .ots detached timestamp file.
    Format: magic(31) + version(1) + hash_op(1) + digest(32, raw) + timestamp_operations
    """
    out = io.BytesIO()
    out.write(OTS_MAGIC)       # 31 bytes
    out.write(OTS_VERSION)     # 1 byte
    out.write(OP_SHA256)       # 1 byte
    assert len(digest) == 32, f"Digest must be 32 bytes, got {len(digest)}"
    out.write(digest)          # 32 bytes
    out.write(calendar_receipt_body)
    return out.getvalue()


# ── SUBMISSION ──

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
            ots_file = build_detached_ots_file(digest, receipt_body, used_calendar)
            print(f"[OTS] Built .ots file: {len(ots_file)} bytes, magic check: {ots_file[:4].hex()}")

            await db.update_ots(
                commitment_id=commitment_id,
                ots_receipt=ots_file,
                ots_status="submitted"
            )
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
        print(f"[OTS] {calendar_url} -> {response.status_code}, {len(response.content)} bytes")

        if response.status_code == 200 and len(response.content) > 4:
            return response.content
        return None


# ── UPGRADE / CONFIRMATION ──

def find_pending_attestations(ots_file_bytes: bytes) -> List[Dict]:
    """
    Parse a .ots file and find PendingAttestations with their commitment hashes.

    KEY INSIGHT: The calendar transforms our original digest via merkle ops.
    The PendingAttestation node's .msg is the TRANSFORMED hash — that's what
    we need to query /timestamp/{hash} with, NOT the original digest.
    """
    try:
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.notary import PendingAttestation

        ctx = io.BytesIO(ots_file_bytes)
        detached = DetachedTimestampFile.deserialize(ctx)

        results = []

        def walk(timestamp):
            for attestation in timestamp.attestations:
                if isinstance(attestation, PendingAttestation):
                    results.append({
                        "uri": attestation.uri,
                        "commitment_hex": timestamp.msg.hex(),
                    })
            for op, child in timestamp.ops.items():
                walk(child)

        walk(detached.timestamp)
        return results

    except Exception as e:
        print(f"[OTS] Failed to parse pending attestations: {e}")
        return []


async def upgrade_ots_file(ots_file_bytes: bytes) -> tuple:
    """
    Attempt to upgrade a .ots file by querying calendars for confirmed proofs.
    Uses the opentimestamps library to parse, upgrade, and re-serialize.

    Returns (upgraded_bytes, block_number) or (None, None).
    """
    try:
        from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
        from opentimestamps.core.notary import PendingAttestation, BitcoinBlockHeaderAttestation
        from opentimestamps.core.serialize import BytesDeserializationContext

        ctx = io.BytesIO(ots_file_bytes)
        detached = DetachedTimestampFile.deserialize(ctx)

        upgraded = False

        async def try_upgrade(timestamp):
            nonlocal upgraded

            pending_to_remove = []
            for attestation in list(timestamp.attestations):
                if isinstance(attestation, PendingAttestation):
                    calendar_url = attestation.uri
                    commitment_hex = timestamp.msg.hex()
                    print(f"[OTS] Querying {calendar_url}/timestamp/{commitment_hex[:16]}...")

                    try:
                        async with httpx.AsyncClient(timeout=30) as client:
                            response = await client.get(
                                f"{calendar_url}/timestamp/{commitment_hex}",
                                headers={
                                    "Accept": "application/octet-stream",
                                    "User-Agent": "psi-commit/1.0",
                                },
                            )
                            if response.status_code == 200 and response.content:
                                print(f"[OTS] Got upgrade from {calendar_url}: {len(response.content)} bytes")

                                # Deserialize the calendar's response as a Timestamp
                                upgrade_ctx = BytesDeserializationContext(response.content)
                                new_timestamp = Timestamp.deserialize(upgrade_ctx, timestamp.msg)

                                # Merge the upgraded timestamp into our tree
                                timestamp.merge(new_timestamp)
                                pending_to_remove.append(attestation)
                                upgraded = True
                            elif response.status_code == 200:
                                print(f"[OTS] {calendar_url} returned empty 200")
                            else:
                                print(f"[OTS] {calendar_url} -> {response.status_code}")
                    except Exception as e:
                        print(f"[OTS] Upgrade error for {calendar_url}: {e}")

            for att in pending_to_remove:
                timestamp.attestations.discard(att)

            for op, child in timestamp.ops.items():
                await try_upgrade(child)

        await try_upgrade(detached.timestamp)

        if upgraded:
            # Re-serialize
            out = io.BytesIO()
            detached.serialize(out)
            upgraded_bytes = out.getvalue()

            block_num = _find_block_in_timestamp(detached.timestamp)
            print(f"[OTS] Upgrade done! Block: {block_num}, file: {len(upgraded_bytes)} bytes")
            return upgraded_bytes, block_num

    except ImportError as e:
        print(f"[OTS] opentimestamps library not installed: {e}")
    except Exception as e:
        print(f"[OTS] Upgrade failed: {e}")
        import traceback
        traceback.print_exc()

    return None, None


def _find_block_in_timestamp(timestamp) -> Optional[int]:
    """Walk timestamp tree to find BitcoinBlockHeaderAttestation."""
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation

    for att in timestamp.attestations:
        if isinstance(att, BitcoinBlockHeaderAttestation):
            return att.height
    for op, child in timestamp.ops.items():
        result = _find_block_in_timestamp(child)
        if result is not None:
            return result
    return None


async def check_ots_status(commitment_id: str, mac_hex: str, ots_receipt_hex: str, ots_digest: str = None, timestamp: str = '') -> dict:
    """
    Check if an OTS receipt has been confirmed in Bitcoin.
    Properly parses the .ots file and queries the right calendar endpoint.
    """
    try:
        ots_bytes = bytes.fromhex(ots_receipt_hex) if isinstance(ots_receipt_hex, str) else ots_receipt_hex

        # First check if already confirmed
        block_num = parse_bitcoin_block(ots_bytes)
        if block_num:
            return {"status": "confirmed", "bitcoin_block": block_num}

        # Try to upgrade
        upgraded_bytes, block_num = await upgrade_ots_file(ots_bytes)

        if upgraded_bytes and block_num:
            await db.update_ots(
                commitment_id=commitment_id,
                ots_receipt=upgraded_bytes,
                ots_status="confirmed",
                bitcoin_block=block_num
            )
            return {"status": "confirmed", "bitcoin_block": block_num}

        if upgraded_bytes:
            # Intermediate upgrade (no block yet)
            await db.update_ots(
                commitment_id=commitment_id,
                ots_receipt=upgraded_bytes,
                ots_status="submitted"
            )

        return {"status": "pending", "message": "Bitcoin confirmation pending (~1-2 hours)."}

    except Exception as e:
        print(f"[OTS] check error: {e}")
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}


def parse_bitcoin_block(ots_file_bytes: bytes) -> Optional[int]:
    """Extract Bitcoin block number from a complete .ots file."""
    try:
        from opentimestamps.core.timestamp import DetachedTimestampFile

        ctx = io.BytesIO(ots_file_bytes)
        detached = DetachedTimestampFile.deserialize(ctx)

        block = _find_block_in_timestamp(detached.timestamp)
        if block:
            print(f"[OTS] Bitcoin block #{block}")
        else:
            print(f"[OTS] Parsed OK but no Bitcoin attestation yet")
        return block

    except ImportError:
        print(f"[OTS] opentimestamps library not installed")
        return None
    except Exception as e:
        print(f"[OTS] Parse failed: {e}")
        return None


def get_ots_verify_url(commitment_id: str) -> str:
    return "https://opentimestamps.org"
