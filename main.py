"""
PSI-COMMIT API
FastAPI backend for the psi-commit web app.
Handles: wall persistence, OTS Bitcoin anchoring, verification.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
from pydantic import BaseModel
from typing import Optional
import os
import asyncio
from datetime import datetime

from database import db
from ots import anchor_commitment, check_ots_status


# ── BACKGROUND OTS POLLER ──
async def poll_ots_confirmations():
    """
    Runs every 30 minutes in the background.
    Checks all submitted-but-unconfirmed commitments against Bitcoin.
    Updates the database when a block is confirmed.
    """
    while True:
        await asyncio.sleep(30 * 60)  # wait 30 minutes
        try:
            print("[OTS] Polling for Bitcoin confirmations...")
            pending = await db.get_pending_ots()
            for commitment in pending:
                if commitment.get("ots_receipt"):
                    status = await check_ots_status(
                        commitment["id"],
                        commitment["mac"],
                        commitment["ots_receipt"]
                    )
                    if status.get("status") == "confirmed":
                        print(f"[OTS] confirmed {commitment['id']} in Bitcoin block #{status.get('bitcoin_block')}")
                    else:
                        print(f"[OTS] Still pending: {commitment['id']}")
        except Exception as e:
            print(f"[OTS] Polling error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(poll_ots_confirmations())
    print("[OTS] Background Bitcoin confirmation poller started.")
    yield
    task.cancel()


# ── APP SETUP ──
app = FastAPI(title="PSI-COMMIT API", version="1.0.0", lifespan=lifespan)

# Allow your website to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Lock this down to your domain in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the frontend (index.html) from the same server
app.mount("/static", StaticFiles(directory="static"), name="static")


# ── MODELS ──
class CommitmentPost(BaseModel):
    id: str              # psc_xxxx
    mac: str             # 64-char hex
    nonce: str           # 64-char hex
    context: str         # e.g. "default"
    domain: str          # e.g. "psi-commit.v1.default"
    timestamp: str       # ISO timestamp


class RevealPost(BaseModel):
    id: str
    message: str
    key_hex: str


# ── ROUTES ──

@app.get("/")
async def serve_frontend():
    """Serve the main website."""
    return FileResponse("static/index.html")


@app.post("/api/commit")
async def post_commitment(data: CommitmentPost):
    """
    Save a commitment to the wall and trigger OTS anchoring.
    Server never receives the secret key or message — only the public MAC.
    """
    # Check if already exists
    existing = await db.get_commitment(data.id)
    if existing:
        return {"success": True, "id": data.id, "already_exists": True}

    # Save to database
    commitment = {
        "id": data.id,
        "mac": data.mac,
        "nonce": data.nonce,
        "context": data.context,
        "domain": data.domain,
        "committed_at": data.timestamp,
        "revealed": False,
        "revealed_message": None,
        "ots_status": "pending",
        "ots_receipt": None,
        "bitcoin_block": None,
    }

    await db.insert_commitment(commitment)

    # Trigger OTS anchoring in background (don't make user wait)
    asyncio.create_task(anchor_commitment(data.id, data.mac))

    return {
        "success": True,
        "id": data.id,
        "message": "Commitment saved and Bitcoin anchoring started."
    }


@app.get("/api/wall")
async def get_wall(limit: int = 50, offset: int = 0):
    """Return all public wall commitments, newest first."""
    commitments = await db.get_wall(limit=limit, offset=offset)
    return {"commitments": commitments, "total": len(commitments)}


@app.get("/api/commitment/{commitment_id}")
async def get_commitment(commitment_id: str):
    """Get a single commitment by ID."""
    commitment = await db.get_commitment(commitment_id)
    if not commitment:
        raise HTTPException(status_code=404, detail="Commitment not found")
    return commitment


@app.get("/api/ots/{commitment_id}")
async def get_ots_status(commitment_id: str):
    """
    Check OTS anchoring status for a commitment.
    Returns Bitcoin block number if confirmed.
    """
    commitment = await db.get_commitment(commitment_id)
    if not commitment:
        raise HTTPException(status_code=404, detail="Commitment not found")

    # If already confirmed, return cached result
    if commitment.get("ots_status") == "confirmed":
        return {
            "status": "confirmed",
            "bitcoin_block": commitment.get("bitcoin_block"),
            "message": f"Anchored in Bitcoin block #{commitment.get('bitcoin_block')}"
        }

    # If pending, check live status
    if commitment.get("ots_receipt"):
        status = await check_ots_status(
            commitment_id,
            commitment["mac"],
            commitment["ots_receipt"]
        )
        return status

    return {
        "status": "pending",
        "message": "OTS anchoring in progress. Bitcoin confirmation takes ~2 hours."
    }


@app.post("/api/reveal/{commitment_id}")
async def reveal_commitment(commitment_id: str, data: RevealPost):
    """
    Reveal a commitment. Verifies the key matches before storing message.
    This is where the server first learns the original message.
    """
    import hmac as hmac_lib
    import hashlib

    commitment = await db.get_commitment(commitment_id)
    if not commitment:
        raise HTTPException(status_code=404, detail="Commitment not found")

    if commitment.get("revealed"):
        raise HTTPException(status_code=400, detail="Already revealed")

    # Server-side verification before storing
    try:
        key_bytes = bytes.fromhex(data.key_hex)
        nonce_bytes = bytes.fromhex(commitment["nonce"])
        domain = commitment["domain"].encode("utf-8")
        message = data.message.encode("utf-8")

        mac_actual = hmac_lib.new(
            key_bytes,
            domain + nonce_bytes + message,
            hashlib.sha256
        ).hexdigest()

        if not hmac_lib.compare_digest(mac_actual, commitment["mac"]):
            raise HTTPException(status_code=400, detail="Key or message does not match commitment")

    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid key format")

    # Store the revealed message
    await db.reveal_commitment(commitment_id, data.message)

    return {
        "success": True,
        "id": commitment_id,
        "message": "Commitment revealed and verified."
    }


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
