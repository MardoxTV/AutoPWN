from __future__ import annotations
import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from .client import GraphClient, ARMClient
from .models import Finding, FindingStatus, Severity, AssessmentResult, AssessmentSummary
from .checks import identity, risky, network, storage, defender

logger = logging.getLogger("autopwn.azure.engine")

_jobs: dict[str, dict] = {}


def create_job_id() -> str:
    return str(uuid.uuid4())


def get_job(job_id: str) -> Optional[dict]:
    return _jobs.get(job_id)


async def run_assessment(
    job_id: str,
    graph_token: str,
    arm_token: Optional[str],
    tenant_id: str,
    user_name: str,
) -> None:
    job = _jobs[job_id]
    job["status"] = "running"

    graph = GraphClient(graph_token)
    arm = ARMClient(arm_token) if arm_token else None

    all_findings: list[Finding] = []
    subscriptions: list[dict] = []

    try:
        # --- Phase 1: Identity checks ---
        job["phase"] = "Identity & Access"
        job["progress"] = 10
        logger.info("[%s] Running identity checks", job_id)
        id_findings = await identity.run_all(graph)
        all_findings.extend(id_findings)

        # --- Phase 2: Risk & Threat detection ---
        job["phase"] = "Risk & Threat Detection"
        job["progress"] = 30
        logger.info("[%s] Running risky user / threat checks", job_id)
        risk_findings = await risky.run_all(graph)
        all_findings.extend(risk_findings)

        # --- Phase 3: ARM checks (Network, Storage, Defender) ---
        if arm:
            job["phase"] = "Enumerating Subscriptions"
            job["progress"] = 50
            sub_data = await arm.get_list("/subscriptions", "2022-12-01")
            subscriptions = sub_data

            sub_tasks = []
            for sub in subscriptions:
                sid = sub.get("subscriptionId", "")
                sub_tasks.append(network.run_all(arm, sid))
                sub_tasks.append(storage.run_all(arm, sid))
                sub_tasks.append(defender.run_all(arm, sid))

            job["phase"] = "Network, Storage & Defender"
            job["progress"] = 65
            logger.info("[%s] Running ARM checks on %d subscriptions", job_id, len(subscriptions))
            arm_results = await asyncio.gather(*sub_tasks, return_exceptions=True)
            for r in arm_results:
                if isinstance(r, Exception):
                    logger.error("[%s] ARM check raised: %s", job_id, r)
                elif isinstance(r, list):
                    all_findings.extend(r)
        else:
            logger.info("[%s] ARM token unavailable — skipping network/storage/defender checks", job_id)

        job["progress"] = 95
        job["phase"] = "Building Report"

        # Get tenant name
        tenant_name = user_name
        try:
            org_data = await graph.get("/organization?$select=displayName")
            orgs = org_data.get("value", [])
            if orgs:
                tenant_name = orgs[0].get("displayName", user_name)
        except Exception:
            pass

        # Try to pull secure score for summary
        secure_score: Optional[float] = None
        for f in all_findings:
            if "Secure Score" in f.title and f.status == FindingStatus.PASS:
                try:
                    pct_str = f.title.split(":")[1].strip().split("%")[0]
                    secure_score = float(pct_str)
                except Exception:
                    pass
                break
            elif "Low Secure Score" in f.title:
                try:
                    pct_str = f.title.split(":")[1].strip().split("%")[0]
                    secure_score = float(pct_str)
                except Exception:
                    pass
                break

        # Build summary
        real_findings = [f for f in all_findings if f.status != FindingStatus.SKIP]
        summary = AssessmentSummary(
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            assessed_at=datetime.now(timezone.utc).isoformat(),
            total_checks=len(all_findings),
            passed=sum(1 for f in all_findings if f.status == FindingStatus.PASS),
            failed=sum(1 for f in all_findings if f.status == FindingStatus.FAIL),
            warnings=sum(1 for f in all_findings if f.status == FindingStatus.WARN),
            skipped=sum(1 for f in all_findings if f.status == FindingStatus.SKIP),
            critical_count=sum(1 for f in real_findings if f.severity == Severity.CRITICAL and f.status != FindingStatus.PASS),
            high_count=sum(1 for f in real_findings if f.severity == Severity.HIGH and f.status != FindingStatus.PASS),
            medium_count=sum(1 for f in real_findings if f.severity == Severity.MEDIUM and f.status != FindingStatus.PASS),
            low_count=sum(1 for f in real_findings if f.severity == Severity.LOW and f.status != FindingStatus.PASS),
            subscriptions_assessed=len(subscriptions),
            arm_available=arm is not None,
            secure_score=secure_score,
        )

        result = AssessmentResult(job_id=job_id, summary=summary, findings=all_findings)
        job["result"] = result.model_dump()
        job["status"] = "complete"
        job["progress"] = 100
        job["phase"] = "Complete"
        logger.info("[%s] Assessment complete — %d findings", job_id, len(all_findings))

    except Exception as e:
        logger.exception("[%s] Assessment failed: %s", job_id, e)
        job["status"] = "error"
        job["error"] = str(e)
    finally:
        await graph.close()
        if arm:
            await arm.close()


def start_assessment(
    graph_token: str,
    arm_token: Optional[str],
    tenant_id: str,
    user_name: str,
) -> str:
    job_id = create_job_id()
    _jobs[job_id] = {
        "status": "queued",
        "progress": 0,
        "phase": "Queued",
        "result": None,
        "error": None,
    }
    asyncio.create_task(
        run_assessment(job_id, graph_token, arm_token, tenant_id, user_name)
    )
    return job_id
