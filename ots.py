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

        # Try each calendar server until one succeeds
        receipt_data = None
        for calendar_url in OTS_CALENDARS:
            try:
                receipt_data = await submit_to_calendar(calendar_url, digest)
                if receipt_data:
                    break
            except Exception:
                continue

        if receipt_data:
            # Save the raw receipt — Bitcoin not yet confirmed (~2hrs)
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

        # Try to upgrade the receipt (checks if Bitcoin block is mined)
        upgraded = await upgrade_receipt(receipt_bytes)

        if upgraded and b"bitcoin" in upgraded.lower() if isinstance(upgraded, bytes) else False:
            # Parse block number from upgraded receipt
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


async def upgrade_receipt(receipt_bytes: bytes) -> Optional[bytes]:
    """
    Try to upgrade a pending OTS receipt by fetching confirmation
    from calendar servers.
    """
    for calendar_url in OTS_CALENDARS:
        try:
            # Send the pending receipt to get an upgraded (confirmed) version
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{calendar_url}/timestamp/",
                    content=receipt_bytes,
                    headers={"Content-Type": "application/octet-stream"}
                )
                if response.status_code == 200:
                    return response.content
        except Exception:
            continue
    return None


def parse_bitcoin_block(receipt_bytes: bytes) -> Optional[int]:
    """
    Extract Bitcoin block number from a confirmed OTS receipt.
    OTS receipts are binary — look for block height bytes.
    For production, use the opentimestamps Python library for proper parsing.
    """
    # Simple heuristic: block numbers are typically 6 digits in recent years
    # For production use: pip install opentimestamps
    # from opentimestamps.core.timestamp import Timestamp
    # This is a simplified version — the opentimestamps library handles full parsing
    try:
        # Look for 4-byte big-endian integers that look like block numbers (700000-1000000)
        for i in range(len(receipt_bytes) - 4):
            val = int.from_bytes(receipt_bytes[i:i+4], 'big')
            if 700_000 <= val <= 1_500_000:
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
