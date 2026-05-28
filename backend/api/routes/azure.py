from __future__ import annotations
import asyncio
import logging

from fastapi import APIRouter, BackgroundTasks, HTTPException

from ...azure import auth as azure_auth
from ...azure import engine as azure_engine

logger = logging.getLogger("autopwn.azure.routes")
router = APIRouter(prefix="/api/azure", tags=["azure"])


@router.post("/auth/start")
async def start_auth(background_tasks: BackgroundTasks):
    """Initiate Azure device code OAuth flow."""
    session_id = azure_auth.create_session_id()
    try:
        flow_info = azure_auth.start_device_flow(session_id)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Start background polling in the event loop
    asyncio.create_task(azure_auth.run_device_flow_background(session_id))

    return {
        "session_id": session_id,
        "user_code": flow_info["user_code"],
        "verification_uri": flow_info["verification_uri"],
        "expires_in": flow_info["expires_in"],
        "message": flow_info["message"],
    }


@router.get("/auth/status/{session_id}")
async def auth_status(session_id: str):
    """Poll auth status. Returns pending / success / error."""
    session = azure_auth.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "status": session["status"],
        "tenant_id": session.get("tenant_id"),
        "user_name": session.get("user_name"),
        "arm_available": session.get("arm_token") is not None,
        "error": session.get("error"),
    }


@router.post("/assess/start/{session_id}")
async def start_assessment(session_id: str):
    """Begin the security assessment for an authenticated session."""
    session = azure_auth.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session["status"] != "success":
        raise HTTPException(status_code=400, detail=f"Session is not authenticated (status: {session['status']})")

    job_id = azure_engine.start_assessment(
        graph_token=session["graph_token"],
        arm_token=session.get("arm_token"),
        tenant_id=session.get("tenant_id", "unknown"),
        user_name=session.get("user_name", "Unknown"),
    )
    return {"job_id": job_id}


@router.get("/assess/{job_id}/status")
async def assessment_status(job_id: str):
    """Poll assessment job progress."""
    job = azure_engine.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "status": job["status"],
        "progress": job["progress"],
        "phase": job["phase"],
        "error": job.get("error"),
    }


@router.get("/assess/{job_id}/results")
async def assessment_results(job_id: str):
    """Retrieve completed assessment results."""
    job = azure_engine.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] != "complete":
        raise HTTPException(status_code=400, detail=f"Assessment not complete (status: {job['status']})")
    return job["result"]
