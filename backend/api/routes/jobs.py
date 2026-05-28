from __future__ import annotations
import ipaddress
import json
import uuid
import logging
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field, field_validator
from typing import Optional
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from ...database.session import get_session
from ...database import crud
from ...core.job_queue import enqueue, cancel_job
from ...core.auth import require_token
from ...core.rate_limit import limiter
from ...core.event_bus import bus, make_job_status

logger = logging.getLogger("autopwn.api.jobs")

router = APIRouter(prefix="/api/v1/jobs", tags=["jobs"],
                   dependencies=[Depends(require_token)])

VALID_PROFILES = {"quick", "standard", "aggressive", "web_focus", "ad_windows", "custom"}


class JobCreate(BaseModel):
    target_ip: str
    target_name: Optional[str] = None
    profile: str = "standard"
    options: Optional[dict] = Field(default_factory=dict)

    @field_validator("target_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target_ip cannot be empty")
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address (IPv4 or IPv6)")
        return v

    @field_validator("profile")
    @classmethod
    def validate_profile(cls, v: str) -> str:
        if v not in VALID_PROFILES:
            raise ValueError(f"Unknown profile '{v}'. Valid options: {', '.join(sorted(VALID_PROFILES))}")
        return v

    @field_validator("target_name")
    @classmethod
    def sanitize_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        # Reject names that could be used for path traversal or injection
        if any(c in v for c in ("/", "\\", "..", "<", ">", "|", "\x00")):
            raise ValueError("target_name contains invalid characters")
        return v[:64] if v else None


class JobResponse(BaseModel):
    id: str
    target_ip: str
    target_name: Optional[str]
    profile: str
    status: str
    current_phase: Optional[str]
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    error_msg: Optional[str]
    queue_position: Optional[int] = None


def _job_to_response(job) -> dict:
    return {
        "id": job.id,
        "target_ip": job.target_ip,
        "target_name": job.target_name,
        "profile": job.profile,
        "status": job.status,
        "current_phase": job.current_phase,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "error_msg": job.error_msg,
    }


@router.post("", status_code=201)
@limiter.limit("10/minute")
async def create_job(request: Request, body: JobCreate,
                     session: AsyncSession = Depends(get_session)):
    job_id = str(uuid.uuid4())
    try:
        job = await crud.create_job(
            session,
            job_id=job_id,
            target_ip=body.target_ip,
            target_name=body.target_name,
            profile=body.profile,
            options=body.options,
        )
    except SQLAlchemyError as e:
        logger.error(f"DB error creating job: {e}")
        raise HTTPException(status_code=500, detail="Database error — could not create job")
    queue_position = await enqueue(job_id)
    resp = _job_to_response(job)
    resp["queue_position"] = queue_position
    return resp


@router.get("")
async def list_jobs(limit: int = 50, offset: int = 0,
                    session: AsyncSession = Depends(get_session)):
    if limit > 200:
        raise HTTPException(status_code=400, detail="limit cannot exceed 200")
    try:
        jobs = await crud.list_jobs(session, limit=limit, offset=offset)
        return [_job_to_response(j) for j in jobs]
    except SQLAlchemyError as e:
        logger.error(f"DB error listing jobs: {e}")
        raise HTTPException(status_code=500, detail="Database error")


@router.get("/{job_id}")
async def get_job(job_id: str, session: AsyncSession = Depends(get_session)):
    try:
        job = await crud.get_job(session, job_id)
    except SQLAlchemyError as e:
        logger.error(f"DB error fetching job {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Database error")
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _job_to_response(job)


@router.delete("/{job_id}", status_code=204)
async def cancel_job_route(job_id: str, session: AsyncSession = Depends(get_session)):
    try:
        job = await crud.get_job(session, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status in ("completed", "failed", "cancelled"):
            raise HTTPException(status_code=409, detail=f"Job is already '{job.status}' and cannot be cancelled")
        await crud.update_job_status(session, job_id, "cancelled")
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"DB error cancelling job {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Database error")
    # Kill running subprocess + cancel asyncio task (best-effort, no error on failure)
    await cancel_job(job_id)
    # Notify any connected WebSocket clients immediately
    await bus.publish(make_job_status(job_id, "cancelled"))
