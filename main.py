"""
PSI-COMMIT API
FastAPI backend for the psi-commit web app.
Handles: wall persistence, OTS Bitcoin anchoring, verification.
"""

from fastapi import FastAPI, HTTPException, Request
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
    while True:
        await asyncio.sleep(30 * 60)
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")


# ── MODELS ──
class CommitmentPost(BaseModel):
    id: str
    mac: str
    nonce: str
    context: str
    domain: str
    timestamp: str
    user_id: Optional[str] = None
    visibility: Optional[str] = "public"


class RevealPost(BaseModel):
    id: str
    message: str
    key_hex: str


# ── ROUTES ──

@app.get("/")
async def serve_frontend():
    return FileResponse("static/index.html")


@app.post("/api/commit")
async def post_commitment(data: CommitmentPost):
    existing = await db.get_commitment(data.id)
    if existing:
        return {"success": True, "id": data.id, "already_exists": True}

    commitment = {
        "id": data.id,
        "mac": data.mac,
        "nonce": data.nonce,
        "context": data.context,
        "domain": data.domain,
        "committed_at": data.timestamp,
        "user_id": data.user_id,
        "visibility": data.visibility or "public",
        "revealed": False,
        "revealed_message": None,
        "ots_status": "pending",
        "ots_receipt": None,
        "bitcoin_block": None,
    }

    await db.insert_commitment(commitment)
    asyncio.create_task(anchor_commitment(data.id, data.mac))

    return {
        "success": True,
        "id": data.id,
        "message": "Commitment saved and Bitcoin anchoring started."
    }


@app.get("/api/wall")
async def get_wall(limit: int = 50, offset: int = 0):
    """Return public wall commitments only."""
    commitments = await db.get_wall(limit=limit, offset=offset)
    return {"commitments": commitments, "total": len(commitments)}


@app.get("/api/commitment/{commitment_id}")
async def get_commitment(commitment_id: str):
    commitment = await db.get_commitment(commitment_id)
    if not commitment:
        raise HTTPException(status_code=404, detail="Commitment not found")
    return commitment


@app.get("/api/user/{user_id}/commitments")
async def get_user_commitments(user_id: str, visibility: Optional[str] = None):
    """Get commitments for a user. visibility=public|private|all"""
    commitments = await db.get_user_commitments(user_id, visibility)
    return {"commitments": commitments}


@app.get("/api/ots/{commitment_id}")
async def get_ots_status(commitment_id: str):
    commitment = await db.get_commitment(commitment_id)
    if not commitment:
        raise HTTPException(status_code=404, detail="Commitment not found")

    if commitment.get("ots_status") == "confirmed":
        return {
            "status": "confirmed",
            "bitcoin_block": commitment.get("bitcoin_block"),
            "message": f"Anchored in Bitcoin block #{commitment.get('bitcoin_block')}"
        }

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
    import hmac as hmac_lib
    import hashlib

    commitment = await db.get_commitment(commitment_id)
    if not commitment:
        raise HTTPException(status_code=404, detail="Commitment not found")

    if commitment.get("revealed"):
        raise HTTPException(status_code=400, detail="Already revealed")

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

    await db.reveal_commitment(commitment_id, data.message)

    return {
        "success": True,
        "id": commitment_id,
        "message": "Commitment revealed and verified."
    }




@app.delete("/api/commitment/{commitment_id}")
async def delete_commitment(commitment_id: str, request: Request):
    user_id = request.headers.get('x-user-id')
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    commitment = await db.get_commitment(commitment_id)
    if not commitment:
        raise HTTPException(status_code=404, detail="Not found")
    if commitment.get('user_id') != user_id:
        raise HTTPException(status_code=403, detail="Not your commitment")
    await db.delete_commitment(commitment_id)
    return {"success": True}

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
