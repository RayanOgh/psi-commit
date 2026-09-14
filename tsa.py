"""
RFC 3161 timestamping via FreeTSA.
Provides an independent Time-Stamping Authority (TSA) attestation alongside
the OpenTimestamps Bitcoin anchor — issued immediately, not after a Bitcoin
confirmation delay.
"""

import httpx
from typing import Optional

from database import db
from ots import build_ots_submit_digest

try:
    import rfc3161ng
    RFC3161_AVAILABLE = True
except ImportError:
    RFC3161_AVAILABLE = False
    print("[TSA] rfc3161ng library not installed — RFC 3161 timestamping disabled.")

FREETSA_URL = "https://freetsa.org/tsr"
HASHNAME = "sha256"


def build_tsq(digest: bytes) -> bytes:
    """Build a DER-encoded RFC 3161 TimeStampReq (TSQ) for a 32-byte SHA-256 digest."""
    if not RFC3161_AVAILABLE:
        raise RuntimeError("rfc3161ng library is not installed")
    request = rfc3161ng.make_timestamp_request(digest=digest, hashname=HASHNAME)
    return rfc3161ng.encode_timestamp_request(request)


def parse_and_check_tsr(tsr_bytes: bytes, digest: bytes) -> None:
    """
    Decode a raw .tsr response and sanity-check it against the submitted digest.
    Raises on a rejected request or a message-imprint mismatch.
    """
    tsr = rfc3161ng.decode_timestamp_response(tsr_bytes)

    status = int(tsr.status['status'])
    if status not in (0, 1):  # 0 = granted, 1 = grantedWithMods
        raise rfc3161ng.TimestampingError(f"FreeTSA rejected the timestamp request (status={status})")

    tst = tsr.time_stamp_token
    imprint = tst.tst_info.message_imprint
    if bytes(imprint.hashed_message) != digest:
        raise ValueError("TSA response message imprint does not match the submitted digest")


async def request_tsa_timestamp(digest: bytes) -> Optional[bytes]:
    """
    Send a digest to FreeTSA and return the raw RFC 3161 .tsr response bytes.
    Returns None on failure.
    """
    if not RFC3161_AVAILABLE:
        return None

    assert len(digest) == 32, "RFC 3161 timestamping expects a 32-byte SHA-256 digest"

    tsq_bytes = build_tsq(digest)

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            FREETSA_URL,
            content=tsq_bytes,
            headers={"Content-Type": "application/timestamp-query"},
        )

    if response.status_code != 200 or not response.content:
        print(f"[TSA] FreeTSA -> {response.status_code}, {len(response.content)} bytes")
        return None

    tsr_bytes = response.content
    parse_and_check_tsr(tsr_bytes, digest)
    return tsr_bytes


async def anchor_commitment_tsa(commitment_id: str, mac_hex: str, timestamp: str = '', psc_digest: str = None):
    """Get an RFC 3161 timestamp token from FreeTSA and store it alongside the OTS proof."""
    try:
        digest = build_ots_submit_digest(commitment_id, mac_hex, timestamp, psc_digest)
        print(f"[TSA] Requesting FreeTSA timestamp for digest: {digest.hex()[:16]}... for {commitment_id}")

        tsr_bytes = await request_tsa_timestamp(digest)

        if tsr_bytes:
            await db.update_tsa(commitment_id=commitment_id, tsa_receipt=tsr_bytes, tsa_status="confirmed")
            print(f"[TSA] {commitment_id} timestamped via FreeTSA ({len(tsr_bytes)} bytes)")
        else:
            await db.update_tsa(commitment_id=commitment_id, tsa_receipt=None, tsa_status="failed")
            print(f"[TSA] Failed to timestamp {commitment_id}")

    except Exception as e:
        print(f"[TSA] Error timestamping {commitment_id}: {e}")
        try:
            await db.update_tsa(commitment_id=commitment_id, tsa_receipt=None, tsa_status="failed")
        except Exception:
            pass


def get_tsa_verify_url(commitment_id: str) -> str:
    return "https://freetsa.org/index_en.php"
