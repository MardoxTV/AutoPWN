import json
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from .models import Job, Phase, Finding, Credential, Flag, Log


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- Jobs ---

async def create_job(session: AsyncSession, job_id: str, target_ip: str,
                     target_name: Optional[str], profile: str,
                     options: Optional[dict]) -> Job:
    job = Job(
        id=job_id,
        target_ip=target_ip,
        target_name=target_name,
        profile=profile,
        status="created",
        created_at=_now(),
        options=json.dumps(options or {}),
    )
    session.add(job)
    await session.commit()
    await session.refresh(job)
    return job


async def get_job(session: AsyncSession, job_id: str) -> Optional[Job]:
    result = await session.execute(select(Job).where(Job.id == job_id))
    return result.scalar_one_or_none()


async def list_jobs(session: AsyncSession, limit: int = 50, offset: int = 0):
    result = await session.execute(
        select(Job).order_by(Job.created_at.desc()).limit(limit).offset(offset)
    )
    return result.scalars().all()


async def update_job_status(session: AsyncSession, job_id: str, status: str,
                             current_phase: Optional[str] = None,
                             error_msg: Optional[str] = None):
    values = {"status": status}
    if status == "running" and current_phase is None:
        values["started_at"] = _now()
    if status in ("completed", "failed", "cancelled"):
        values["completed_at"] = _now()
    if current_phase is not None:
        values["current_phase"] = current_phase
    if error_msg is not None:
        values["error_msg"] = error_msg
    await session.execute(update(Job).where(Job.id == job_id).values(**values))
    await session.commit()


# --- Phases ---

async def upsert_phase(session: AsyncSession, job_id: str, phase_name: str,
                        status: str, error_msg: Optional[str] = None):
    result = await session.execute(
        select(Phase).where(Phase.job_id == job_id, Phase.phase == phase_name)
    )
    phase = result.scalar_one_or_none()
    now = _now()
    if phase is None:
        phase = Phase(job_id=job_id, phase=phase_name, status=status,
                      started_at=now if status == "running" else None)
        session.add(phase)
    else:
        phase.status = status
        if status == "running":
            phase.started_at = now
        if status in ("completed", "failed", "skipped"):
            phase.completed_at = now
        if error_msg:
            phase.error_msg = error_msg
    await session.commit()


# --- Findings ---

async def add_finding(session: AsyncSession, job_id: str, phase: str, tool: str,
                       finding_type: str, value: str, severity: Optional[str] = None,
                       metadata: Optional[dict] = None) -> Finding:
    f = Finding(
        job_id=job_id, phase=phase, tool=tool, finding_type=finding_type,
        value=value, severity=severity,
        metadata_=json.dumps(metadata or {}),
        timestamp=_now(),
    )
    session.add(f)
    await session.commit()
    return f


async def get_findings(session: AsyncSession, job_id: str):
    result = await session.execute(select(Finding).where(Finding.job_id == job_id))
    return result.scalars().all()


# --- Credentials ---

async def add_credential(session: AsyncSession, job_id: str, service: str,
                          username: str, password: str, port: Optional[int] = None,
                          found_by: Optional[str] = None) -> Credential:
    c = Credential(
        job_id=job_id, service=service, username=username, password=password,
        port=port, found_by=found_by, timestamp=_now(),
    )
    session.add(c)
    await session.commit()
    return c


async def get_credentials(session: AsyncSession, job_id: str):
    result = await session.execute(select(Credential).where(Credential.job_id == job_id))
    return result.scalars().all()


# --- Flags ---

async def add_flag(session: AsyncSession, job_id: str, flag_type: str,
                   value: str, path: Optional[str] = None) -> Flag:
    f = Flag(job_id=job_id, flag_type=flag_type, value=value, path=path, timestamp=_now())
    session.add(f)
    await session.commit()
    return f


async def get_flags(session: AsyncSession, job_id: str):
    result = await session.execute(select(Flag).where(Flag.job_id == job_id))
    return result.scalars().all()


# --- Logs ---

async def add_log(session: AsyncSession, job_id: str, message: str,
                  level: str = "info", phase: Optional[str] = None,
                  tool: Optional[str] = None):
    log = Log(job_id=job_id, phase=phase, tool=tool, level=level,
              message=message, timestamp=_now())
    session.add(log)
    await session.commit()


async def get_logs(session: AsyncSession, job_id: str, limit: int = 500, offset: int = 0):
    result = await session.execute(
        select(Log).where(Log.job_id == job_id)
        .order_by(Log.timestamp.asc())
        .limit(limit).offset(offset)
    )
    return result.scalars().all()
