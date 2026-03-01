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


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def build_ots_submit_digest(mac_hex: str) -> bytes:
    """
    SHA256 the MAC bytes to get a proper 32-byte digest for OTS submission.
    The OTS calendar expects a raw 32-byte SHA256 digest.
    """
    mac_bytes = bytes.fromhex(mac_hex)
    return sha256(mac_bytes)


async def anchor_commitment(commitment_id: str, mac_hex: str):
    """
    Submit a commitment MAC to OTS calendar servers.
    Runs in background — does not block the API response.
    """
    try:
        digest = build_ots_submit_digest(mac_hex)
        print(f"[OTS] Submitting digest: {digest.hex()[:16]}... for {commitment_id}")

        receipt_data = None
        used_calendar = None

        for calendar_url in OTS_CALENDARS:
            try:
                receipt_data = await submit_to_calendar(calendar_url, digest)
                if receipt_data:
                    used_calendar = calendar_url
                    break
            except Exception as e:
                print(f"[OTS] Calendar {calendar_url} failed: {e}")
                continue

        if receipt_data:
            await db.update_ots(
                commitment_id=commitment_id,
                ots_receipt=receipt_data,
                ots_status="submitted"
            )
            print(f"[OTS] {commitment_id} submitted via {used_calendar} ({len(receipt_data)} bytes, starts: {receipt_data[:4].hex()})")
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

        print(f"[OTS] {calendar_url} responded {response.status_code}, {len(response.content)} bytes, starts: {response.content[:4].hex() if response.content else 'empty'}")

        if response.status_code == 200 and len(response.content) > 10:
            return response.content

        return None


async def check_ots_status(
    commitment_id: str,
    mac_hex: str,
    ots_receipt_hex: str
) -> dict:
    """
    Check if an OTS receipt has been confirmed in a Bitcoin block.
    """
    try:
        receipt_bytes = bytes.fromhex(ots_receipt_hex)
        digest = build_ots_submit_digest(mac_hex)

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
                    "message": f"Anchored in Bitcoin block #{block_num}."
                }

        return {
            "status": "pending",
            "message": "Bitcoin confirmation pending. Usually takes 1-2 hours after submission."
        }

    except Exception as e:
        print(f"[OTS] check_ots_status error: {e}")
        return {
            "status": "error",
            "message": f"Could not check OTS status: {str(e)}"
        }


async def upgrade_receipt(receipt_bytes: bytes, digest: bytes = None) -> Optional[bytes]:
    """
    Try to upgrade a pending OTS receipt by querying the calendar's /timestamp/ endpoint.
    """
    if digest is None:
        return None

    commitment_hex = digest.hex()
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
            print(f"[OTS] Parsed Bitcoin block #{block}")
            return block

    except Exception as e:
        print(f"[OTS] opentimestamps library parse failed: {e}")

    # Fallback: scan for 4-byte big-endian integers in Bitcoin block range
    try:
        for i in range(len(receipt_bytes) - 4):
            val = int.from_bytes(receipt_bytes[i:i+4], 'big')
            if 880_000 <= val <= 1_500_000:
                print(f"[OTS] Heuristic found block #{val}")
                return val
    except Exception:
        pass

    return None


def get_ots_verify_url(commitment_id: str) -> str:
    return "https://opentimestamps.org"
