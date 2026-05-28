from __future__ import annotations
import json
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ...database.session import get_session
from ...database import crud
from ...core.auth import require_token

router = APIRouter(prefix="/api/v1/results", tags=["results"],
                   dependencies=[Depends(require_token)])


def _finding_dict(f) -> dict:
    return {
        "id": f.id, "job_id": f.job_id, "phase": f.phase, "tool": f.tool,
        "finding_type": f.finding_type, "severity": f.severity,
        "value": f.value, "metadata": json.loads(f.metadata_ or "{}"),
        "timestamp": f.timestamp,
    }


def _cred_dict(c) -> dict:
    return {
        "id": c.id, "job_id": c.job_id, "service": c.service,
        "username": c.username, "password": c.password,
        "port": c.port, "valid": bool(c.valid),
        "found_by": c.found_by, "timestamp": c.timestamp,
    }


def _flag_dict(f) -> dict:
    return {
        "id": f.id, "job_id": f.job_id, "flag_type": f.flag_type,
        "value": f.value, "path": f.path, "submitted": bool(f.submitted),
        "timestamp": f.timestamp,
    }


def _log_dict(l) -> dict:
    return {
        "id": l.id, "job_id": l.job_id, "phase": l.phase, "tool": l.tool,
        "level": l.level, "message": l.message, "timestamp": l.timestamp,
    }


@router.get("/{job_id}")
async def get_all_results(job_id: str, session: AsyncSession = Depends(get_session)):
    findings = await crud.get_findings(session, job_id)
    credentials = await crud.get_credentials(session, job_id)
    flags = await crud.get_flags(session, job_id)
    return {
        "job_id": job_id,
        "findings": [_finding_dict(f) for f in findings],
        "credentials": [_cred_dict(c) for c in credentials],
        "flags": [_flag_dict(f) for f in flags],
    }


@router.get("/{job_id}/findings")
async def get_findings(job_id: str, session: AsyncSession = Depends(get_session)):
    findings = await crud.get_findings(session, job_id)
    return [_finding_dict(f) for f in findings]


@router.get("/{job_id}/credentials")
async def get_credentials(job_id: str, session: AsyncSession = Depends(get_session)):
    creds = await crud.get_credentials(session, job_id)
    return [_cred_dict(c) for c in creds]


@router.get("/{job_id}/flags")
async def get_flags(job_id: str, session: AsyncSession = Depends(get_session)):
    flags = await crud.get_flags(session, job_id)
    return [_flag_dict(f) for f in flags]


@router.get("/{job_id}/logs")
async def get_logs(job_id: str, limit: int = 500, offset: int = 0,
                   session: AsyncSession = Depends(get_session)):
    logs = await crud.get_logs(session, job_id, limit=limit, offset=offset)
    return [_log_dict(l) for l in logs]
