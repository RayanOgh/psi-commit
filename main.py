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

from database import db, get_client
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
                        commitment["ots_receipt"],
                        ots_digest=commitment.get("ots_digest"),
                        timestamp=commitment.get("committed_at", "")
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
    psc_digest: Optional[str] = None  # SHA256 of canonical PSC JSON


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
    # Use PSC digest for OTS if provided, otherwise fall back to MAC
    ots_digest = data.psc_digest or None
    asyncio.create_task(anchor_commitment(data.id, data.mac, timestamp=data.timestamp, psc_digest=ots_digest))

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


@app.get("/api/ots/diagnostics")
async def ots_diagnostics():
    """
    Run diagnostics on the OTS Bitcoin anchoring system.
    Checks: calendar connectivity, pending/confirmed counts, sample verification.
    """
    from ots import OTS_CALENDARS, submit_to_calendar, upgrade_receipt, build_ots_submit_digest, parse_bitcoin_block, build_detached_ots_file
    import hashlib

    results = {
        "calendars": [],
        "commitments": {"total": 0, "pending": 0, "submitted": 0, "confirmed": 0, "no_receipt": 0},
        "sample_checks": [],
    }

    # 1. Check calendar connectivity
    test_digest = hashlib.sha256(b"psi-commit-diagnostic-test").digest()
    for cal_url in OTS_CALENDARS:
        try:
            body = await submit_to_calendar(cal_url, test_digest)
            results["calendars"].append({
                "url": cal_url,
                "status": "ok" if body else "no_response",
                "response_bytes": len(body) if body else 0,
            })
        except Exception as e:
            results["calendars"].append({
                "url": cal_url,
                "status": "error",
                "error": str(e),
            })

    # 2. Count commitments by OTS status
    client = get_client()

    for status_val in ["pending", "submitted", "confirmed"]:
        r = client.table("commitments").select("id", count="exact").eq("ots_status", status_val).execute()
        results["commitments"][status_val] = r.count if hasattr(r, 'count') and r.count else len(r.data or [])
    results["commitments"]["total"] = sum(results["commitments"][k] for k in ["pending", "submitted", "confirmed"])

    # Count ones with no OTS receipt
    r = client.table("commitments").select("id").is_("ots_receipt", "null").execute()
    results["commitments"]["no_receipt"] = len(r.data or [])

    # 3. Try to upgrade a few submitted (pending confirmation) commitments
    submitted = client.table("commitments").select(
        "id, mac, ots_receipt, ots_status, ots_digest, committed_at"
    ).eq("ots_status", "submitted").limit(3).execute()

    for c in (submitted.data or []):
        try:
            digest = build_ots_submit_digest(c["id"], c["mac"], c.get("committed_at", ""), c.get("ots_digest"))
            upgraded = await upgrade_receipt(digest)
            if upgraded:
                ots_file = build_detached_ots_file(digest, upgraded, "confirmed")
                block_num = parse_bitcoin_block(ots_file)
                if block_num:
                    await db.update_ots(c["id"], ots_file, "confirmed", block_num)
                    results["sample_checks"].append({
                        "id": c["id"],
                        "result": "confirmed",
                        "bitcoin_block": block_num,
                    })
                else:
                    results["sample_checks"].append({
                        "id": c["id"],
                        "result": "upgraded_but_no_block",
                        "upgraded_bytes": len(upgraded),
                    })
            else:
                results["sample_checks"].append({
                    "id": c["id"],
                    "result": "still_pending",
                    "committed_at": c.get("committed_at"),
                    "digest_prefix": digest.hex()[:16],
                })
        except Exception as e:
            results["sample_checks"].append({
                "id": c["id"],
                "result": "error",
                "error": str(e),
            })

    # 4. Check a confirmed one to make sure the .ots file is valid
    confirmed = client.table("commitments").select(
        "id, ots_receipt, bitcoin_block"
    ).eq("ots_status", "confirmed").limit(1).execute()

    if confirmed.data:
        c = confirmed.data[0]
        try:
            ots_bytes = bytes.fromhex(c["ots_receipt"])
            has_magic = ots_bytes[:15] == b'\x00OpenTimestamps'
            results["confirmed_sample"] = {
                "id": c["id"],
                "bitcoin_block": c.get("bitcoin_block"),
                "ots_file_size": len(ots_bytes),
                "has_valid_magic": has_magic,
            }
        except Exception as e:
            results["confirmed_sample"] = {"error": str(e)}

    return results


@app.post("/api/ots/repair")
async def ots_repair():
    """
    Repair OTS issues:
    1. Resubmit commitments stuck at 'pending' (never submitted to calendar)
    2. Fix malformed .ots files on 'submitted' commitments (had digest embedded incorrectly)
    """
    client = get_client()
    results = {"resubmitted": [], "fixed_ots": [], "errors": []}

    # 1. Resubmit stuck 'pending' commitments
    stuck = client.table("commitments").select(
        "id, mac, committed_at, ots_digest"
    ).eq("ots_status", "pending").execute()

    for c in (stuck.data or []):
        try:
            asyncio.create_task(anchor_commitment(
                c["id"], c["mac"],
                timestamp=c.get("committed_at", ""),
                psc_digest=c.get("ots_digest")
            ))
            results["resubmitted"].append(c["id"])
        except Exception as e:
            results["errors"].append({"id": c["id"], "step": "resubmit", "error": str(e)})

    # 2. Fix malformed .ots files (old format had digest embedded at bytes 33-65)
    submitted = client.table("commitments").select(
        "id, ots_receipt"
    ).eq("ots_status", "submitted").not_.is_("ots_receipt", "null").execute()

    OTS_HEADER_LEN = 33  # magic(31) + version(1) + hash_op(1)

    for c in (submitted.data or []):
        try:
            ots_bytes = bytes.fromhex(c["ots_receipt"])
            # Check if file has the old malformed format (digest embedded after header)
            # Old format: header(33) + varint(1) + digest(32) + calendar_body
            # New format: header(33) + calendar_body
            if len(ots_bytes) > OTS_HEADER_LEN + 33:
                # Check if byte 33 is 0x20 (varint for 32) — sign of old format
                if ots_bytes[OTS_HEADER_LEN] == 0x20:
                    # Strip the varint(1 byte) + digest(32 bytes)
                    fixed = ots_bytes[:OTS_HEADER_LEN] + ots_bytes[OTS_HEADER_LEN + 33:]
                    client.table("commitments").update({
                        "ots_receipt": fixed.hex()
                    }).eq("id", c["id"]).execute()
                    results["fixed_ots"].append(c["id"])
                else:
                    results["fixed_ots"].append({"id": c["id"], "status": "already_correct"})
        except Exception as e:
            results["errors"].append({"id": c["id"], "step": "fix_ots", "error": str(e)})

    return results


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
            commitment["ots_receipt"],
            ots_digest=commitment.get("ots_digest"),
            timestamp=commitment.get("committed_at", "")
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




@app.post("/api/ots/verify")
async def verify_ots(request: Request):
    """
    Verify an OTS file against a stamp digest.
    Client sends: ots_hex (the .ots file bytes as hex), stamp_digest (SHA256 of .stamp.txt)
    We check if the OTS proof confirms the stamp digest in Bitcoin.
    """
    body = await request.json()
    ots_hex = body.get("ots_hex")
    stamp_digest = body.get("stamp_digest")

    if not ots_hex or not stamp_digest:
        raise HTTPException(status_code=400, detail="Missing ots_hex or stamp_digest")

    try:
        from ots import upgrade_receipt, parse_bitcoin_block, build_ots_submit_digest
        import hashlib

        ots_bytes = bytes.fromhex(ots_hex)
        digest = bytes.fromhex(stamp_digest)

        # Try to upgrade/confirm the receipt from calendars
        upgraded = await upgrade_receipt(digest)

        if upgraded:
            block_num = parse_bitcoin_block(upgraded)
            if block_num:
                return {"status": "confirmed", "bitcoin_block": block_num}

        # Check if the existing ots_bytes are already confirmed
        block_num = parse_bitcoin_block(ots_bytes)
        if block_num:
            return {"status": "confirmed", "bitcoin_block": block_num}

        return {"status": "pending", "message": "Bitcoin confirmation in progress. Try again in 1-2 hours."}

    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/api/ots/{commitment_id}/download")
async def download_ots(commitment_id: str):
    """Download the raw .ots binary file for a commitment."""
    commitment = await db.get_commitment(commitment_id)
    if not commitment:
        raise HTTPException(status_code=404, detail="Commitment not found")
    ots_hex = commitment.get("ots_receipt")
    if not ots_hex:
        raise HTTPException(status_code=404, detail="OTS receipt not yet available. Bitcoin anchoring in progress.")
    ots_bytes = bytes.fromhex(ots_hex)
    from fastapi.responses import Response
    return Response(
        content=ots_bytes,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={commitment_id}.ots"}
    )


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
