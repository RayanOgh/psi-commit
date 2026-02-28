"""
OpenTimestamps Bitcoin anchoring.
Anchors commitment MACs to the Bitcoin blockchain via OTS calendar servers.
Free — uses public calendar servers, no Bitcoin wallet needed.
"""

import hashlib
import asyncio
import httpx
from typing import Optional
from database import db


# OTS Calendar servers (public, free, run by Peter Todd and volunteers)
OTS_CALENDARS = [
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
]


def hash_mac(mac_hex: str) -> bytes:
    """Hash the MAC to get a 32-byte digest for OTS submission."""
    return bytes.fromhex(mac_hex)


async def anchor_commitment(commitment_id: str, mac_hex: str):
    """
    Submit a commitment MAC to OTS calendar servers.
    Runs in background — does not block the API response.
    Saves receipt to database when done.
    """
    try:
        digest = hash_mac(mac_hex)

        receipt_data = None
        for calendar_url in OTS_CALENDARS:
            try:
                receipt_data = await submit_to_calendar(calendar_url, digest)
                if receipt_data:
                    break
            except Exception:
                continue

        if receipt_data:
            await db.update_ots(
                commitment_id=commitment_id,
                ots_receipt=receipt_data,
                ots_status="submitted"
            )
            print(f"[OTS] Commitment {commitment_id} submitted to Bitcoin calendar.")
        else:
            print(f"[OTS] Failed to submit {commitment_id} to any calendar server.")

    except Exception as e:
        print(f"[OTS] Error anchoring {commitment_id}: {e}")


async def submit_to_calendar(calendar_url: str, digest: bytes) -> Optional[bytes]:
    """
    POST a 32-byte digest to an OTS calendar server.
    Returns the raw .ots receipt bytes.
    """
    url = f"{calendar_url}/digest"
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            url,
            content=digest,
            headers={"Content-Type": "application/octet-stream"}
        )
        if response.status_code == 200:
            return response.content
        return None


async def check_ots_status(
    commitment_id: str,
    mac_hex: str,
    ots_receipt_hex: str
) -> dict:
    """
    Check if an OTS receipt has been confirmed in a Bitcoin block.
    Updates the database if confirmed.
    """
    try:
        receipt_bytes = bytes.fromhex(ots_receipt_hex)

        # Use the original MAC as the digest — this is what we submitted to the calendar
        digest = bytes.fromhex(mac_hex)

        upgraded = await upgrade_receipt(receipt_bytes, digest=digest)

        if upgraded:
            block_num = parse_bitcoin_block(upgraded)
            if block_num:
                await db.update_ots(
                    commitment_id=commitment_id,
                    ots_receipt=upgraded,
                    ots_status="confirmed",
                    bitcoin_block=block_num
                )
                return {
                    "status": "confirmed",
                    "bitcoin_block": block_num,
                    "message": f"Anchored in Bitcoin block #{block_num}. Verify at opentimestamps.org"
                }

        return {
            "status": "pending",
            "message": "Bitcoin confirmation pending. Usually takes 1-2 hours after submission."
        }

    except Exception as e:
        return {
            "status": "error",
            "message": f"Could not check OTS status: {str(e)}"
        }


async def upgrade_receipt(receipt_bytes: bytes, digest: bytes = None) -> Optional[bytes]:
    """
    Try to upgrade a pending OTS receipt by fetching confirmation from calendar servers.

    The digest is the original 32-byte hash we submitted to the calendar.
    We query the calendar with this digest to get the upgraded receipt
    containing the Bitcoin block proof if confirmed.
    """
    if digest:
        commitment_hex = digest.hex()
    else:
        # Fall back to extracting from receipt — skip 2-byte magic header
        if len(receipt_bytes) < 34:
            return None
        commitment_hex = receipt_bytes[2:34].hex()

    print(f"[OTS] Checking calendar for digest: {commitment_hex[:16]}...")

    for calendar_url in OTS_CALENDARS:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{calendar_url}/timestamp/{commitment_hex}",
                    headers={"Accept": "application/octet-stream"}
                )
                if response.status_code == 200 and len(response.content) > 0:
                    print(f"[OTS] Got upgraded receipt from {calendar_url} ({len(response.content)} bytes)")
                    return response.content
                elif response.status_code == 404:
                    print(f"[OTS] Not yet confirmed on {calendar_url}")
                else:
                    print(f"[OTS] {calendar_url} returned {response.status_code}")
        except Exception as e:
            print(f"[OTS] Error contacting {calendar_url}: {e}")
            continue
    return None


def parse_bitcoin_block(receipt_bytes: bytes) -> Optional[int]:
    """
    Extract Bitcoin block number from a confirmed OTS receipt.
    Uses the opentimestamps library for proper parsing.
    Falls back to heuristic scanning if library unavailable.
    """
    try:
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        import io

        ctx = io.BytesIO(receipt_bytes)
        detached = DetachedTimestampFile.deserialize(ctx)

        def find_bitcoin_block(timestamp):
            for attestation in timestamp.attestations:
                if isinstance(attestation, BitcoinBlockHeaderAttestation):
                    return attestation.height
            for op, ts in timestamp.ops.items():
                result = find_bitcoin_block(ts)
                if result:
                    return result
            return None

        block = find_bitcoin_block(detached.timestamp)
        if block:
            return block

    except Exception:
        pass

    # Fallback: scan for 4-byte big-endian integers in Bitcoin block range
    try:
        for i in range(len(receipt_bytes) - 4):
            val = int.from_bytes(receipt_bytes[i:i+4], 'big')
            if 800_000 <= val <= 1_500_000:
                return val
    except Exception:
        pass

    return None


def get_ots_verify_url(commitment_id: str) -> str:
    """
    Return the URL where users can independently verify their commitment
    on opentimestamps.org.
    """
    return f"https://opentimestamps.org"
