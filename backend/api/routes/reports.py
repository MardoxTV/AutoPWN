from __future__ import annotations
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import HTMLResponse, FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path

from ...database.session import get_session
from ...database import crud
from ...reports.generator import generate_html, generate_pdf
from ...core.auth import require_token

router = APIRouter(prefix="/api/v1/reports", tags=["reports"],
                   dependencies=[Depends(require_token)])


@router.get("/{job_id}/html", response_class=HTMLResponse)
async def get_html_report(job_id: str, session: AsyncSession = Depends(get_session)):
    job = await crud.get_job(session, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    findings = await crud.get_findings(session, job_id)
    credentials = await crud.get_credentials(session, job_id)
    flags = await crud.get_flags(session, job_id)
    html = await generate_html(job, findings, credentials, flags)
    return HTMLResponse(content=html)


@router.get("/{job_id}/pdf")
async def get_pdf_report(job_id: str, session: AsyncSession = Depends(get_session)):
    job = await crud.get_job(session, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    findings = await crud.get_findings(session, job_id)
    credentials = await crud.get_credentials(session, job_id)
    flags = await crud.get_flags(session, job_id)
    pdf_path = await generate_pdf(job, findings, credentials, flags)
    return FileResponse(pdf_path, media_type="application/pdf",
                        filename=f"autopwn-report-{job_id[:8]}.pdf")
