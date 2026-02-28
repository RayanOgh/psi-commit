"""
Database layer — Supabase client.
All commitment data lives here.
"""

import os
from supabase import create_client, Client
from typing import Optional, List, Dict

# ── SUPABASE CLIENT ──
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]  # Use service key (not anon) for server

_client: Optional[Client] = None

def get_client() -> Client:
    global _client
    if _client is None:
        _client = create_client(SUPABASE_URL, SUPABASE_KEY)
    return _client


# ── DATABASE OPERATIONS ──
class Database:

    async def insert_commitment(self, commitment: dict) -> dict:
        """Save a new commitment to the database."""
        client = get_client()
        result = client.table("commitments").insert(commitment).execute()
        return result.data[0] if result.data else {}

    async def get_commitment(self, commitment_id: str) -> Optional[dict]:
        """Fetch a single commitment by ID."""
        client = get_client()
        result = (
            client.table("commitments")
            .select("*")
            .eq("id", commitment_id)
            .limit(1)
            .execute()
        )
        return result.data[0] if result.data else None

    async def get_wall(self, limit: int = 50, offset: int = 0) -> List[dict]:
        """
        Fetch public wall commitments, newest first.
        Never returns secret keys or unrevealed messages.
        """
        client = get_client()
        result = (
            client.table("commitments")
            .select(
                "id, mac, nonce, context, domain, committed_at, "
                "revealed, revealed_message, ots_status, bitcoin_block, ots_confirmed_at"
                # Note: deliberately NOT selecting any secret key fields
            )
            .order("committed_at", desc=True)
            .range(offset, offset + limit - 1)
            .execute()
        )
        return result.data or []

    async def update_ots(
        self,
        commitment_id: str,
        ots_receipt: bytes,
        ots_status: str,
        bitcoin_block: Optional[int] = None
    ):
        """Update OTS anchoring status after Bitcoin confirmation."""
        client = get_client()
        update = {
            "ots_receipt": ots_receipt.hex() if isinstance(ots_receipt, bytes) else ots_receipt,
            "ots_status": ots_status,
        }
        if bitcoin_block:
            update["bitcoin_block"] = bitcoin_block

        client.table("commitments").update(update).eq("id", commitment_id).execute()

    async def reveal_commitment(self, commitment_id: str, message: str):
        """Store the revealed message after verification."""
        client = get_client()
        client.table("commitments").update({
            "revealed": True,
            "revealed_message": message,
            "revealed_at": "now()"
        }).eq("id", commitment_id).execute()


    async def get_pending_ots(self) -> List[dict]:
        """Fetch all commitments that are submitted but not yet confirmed in Bitcoin."""
        client = get_client()
        result = (
            client.table("commitments")
            .select("id, mac, ots_receipt, ots_status")
            .eq("ots_status", "submitted")
            .execute()
        )
        return result.data or []


# Singleton instance
db = Database()
