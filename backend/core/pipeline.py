from __future__ import annotations
import asyncio
import json
import logging
import yaml
from pathlib import Path

from .event_bus import bus, make_log, make_phase_change, make_job_status
from ..database import crud
from ..database.session import AsyncSessionLocal
from ..phases.recon import run_recon
from ..phases.enumeration import run_enumeration
from ..phases.exploitation import run_exploitation
from ..phases.post_exploitation import run_post_exploitation

logger = logging.getLogger("autopwn.pipeline")

PROFILES_PATH = Path(__file__).parent.parent.parent / "config" / "profiles.yaml"

# Recon is the only blocking phase — no ports = nothing to do.
# Enum/Exploit/PostEx failures are logged and skipped so the job can continue.
_RECON_IS_FATAL = True


def _load_profile(profile_name: str) -> dict:
    try:
        with open(PROFILES_PATH) as f:
            profiles = yaml.safe_load(f)
        return profiles.get("profiles", {}).get(profile_name, {})
    except Exception as e:
        logger.error(f"Failed to load profile '{profile_name}': {e}")
        return {}


async def run_pipeline(job_id: str):
    logger.info(f"[{job_id}] run_pipeline ENTERED")
    try:
        async with AsyncSessionLocal() as session:
            logger.info(f"[{job_id}] DB session opened")
            job = await crud.get_job(session, job_id)
            logger.info(f"[{job_id}] DB get_job returned {'job' if job else 'None'}")
            if not job:
                logger.error(f"Job {job_id} not found in database")
                return
            target_ip = job.target_ip
            profile_name = job.profile
            options = json.loads(job.options or "{}")
            logger.info(f"[{job_id}] Loaded: ip={target_ip} profile={profile_name}")
    except Exception as e:
        logger.exception(f"[{job_id}] Cannot load job from DB: {e}")
        # At least mark the job failed so the UI doesn't hang forever
        try:
            await _set_status(job_id, "failed", error_msg=f"DB load failed: {e}")
        except Exception:
            pass
        return

    profile = _load_profile(profile_name)
    phases_cfg = profile.get("phases", {})
    wordlists = profile.get("wordlists", {})
    logger.info(f"[{job_id}] Profile loaded: phases={list(phases_cfg.keys())}")

    if options.get("wordlist"):
        wordlists["directories"] = options["wordlist"]

    logger.info(f"[{job_id}] About to call _set_status('running')")
    try:
        await _set_status(job_id, "running")
        logger.info(f"[{job_id}] _set_status('running') OK")
    except Exception as e:
        logger.exception(f"[{job_id}] _set_status('running') FAILED: {e}")
        return

    _current_phase: list[str] = [""]  # mutable container so CancelledError handler can read it

    try:
        await _run_phases(job_id, target_ip, phases_cfg, wordlists, _current_phase)
    except asyncio.CancelledError:
        phase = _current_phase[0]
        logger.info(f"[{job_id}] Pipeline cancelled during phase '{phase}'")
        if phase:
            await _end_phase(job_id, phase, "cancelled")
        await _set_status(job_id, "cancelled")
        raise  # propagate so the worker task knows it was cancelled
    except Exception as e:
        logger.exception(f"[{job_id}] _run_phases raised: {e}")
        await _set_status(job_id, "failed", error_msg=str(e))


async def _run_phases(job_id: str, target_ip: str, phases_cfg: dict,
                      wordlists: dict, _current_phase: list[str]):

    # ── Phase 1 — Recon ──────────────────────────────────────────────────────
    nmap_result = None
    recon_cfg = phases_cfg.get("recon", {})
    if recon_cfg.get("enabled", True):
        _current_phase[0] = "recon"
        await _begin_phase(job_id, "recon")
        try:
            nmap_result = await run_recon(
                job_id=job_id,
                target_ip=target_ip,
                nmap_args=recon_cfg.get("nmap_args", "-sV -sC -p- -T4"),
                udp=recon_cfg.get("udp", False),
                udp_args=recon_cfg.get("udp_args", "-sU --top-ports 200"),
            )
            await _end_phase(job_id, "recon", "completed")
        except Exception as e:
            logger.exception(f"[{job_id}] Recon phase failed: {e}")
            await _end_phase(job_id, "recon", "failed", error_msg=str(e))
            await bus.publish(make_log(job_id, f"[Recon] FAILED: {e}", level="error", phase="recon"))
            # Recon failure is fatal — no port data means nothing downstream can run
            await _set_status(job_id, "failed", error_msg=f"Recon failed: {e}")
            return
    else:
        await _end_phase(job_id, "recon", "skipped")

    if not nmap_result or not nmap_result.ports:
        await bus.publish(make_log(job_id, "[Pipeline] No open ports found — stopping.", level="warning"))
        await _set_status(job_id, "completed")
        return

    # ── Phase 2 — Enumeration ────────────────────────────────────────────────
    enum_cfg = phases_cfg.get("enumeration", {})
    if enum_cfg.get("enabled", True):
        _current_phase[0] = "enumeration"
        await _begin_phase(job_id, "enumeration")
        try:
            await run_enumeration(
                job_id=job_id,
                target_ip=target_ip,
                nmap_result=nmap_result,
                profile_config=enum_cfg,
                wordlist=wordlists.get("directories", ""),
            )
            await _end_phase(job_id, "enumeration", "completed")
        except Exception as e:
            logger.exception(f"[{job_id}] Enumeration phase failed: {e}")
            await _end_phase(job_id, "enumeration", "failed", error_msg=str(e))
            await bus.publish(make_log(job_id, f"[Enum] FAILED: {e} — continuing to exploitation", level="error", phase="enumeration"))
    else:
        await _end_phase(job_id, "enumeration", "skipped")

    # ── Phase 3 — Exploitation ───────────────────────────────────────────────
    exploit_cfg = phases_cfg.get("exploitation", {})
    if exploit_cfg.get("enabled", True):
        _current_phase[0] = "exploitation"
        await _begin_phase(job_id, "exploitation")
        try:
            async with AsyncSessionLocal() as session:
                raw_findings = await crud.get_findings(session, job_id)
                findings = [
                    {"finding_type": f.finding_type, "value": f.value,
                     "metadata": json.loads(f.metadata_ or "{}")}
                    for f in raw_findings
                ]
            await run_exploitation(
                job_id=job_id,
                target_ip=target_ip,
                nmap_result=nmap_result,
                profile_config=exploit_cfg,
                findings=findings,
                wordlists=wordlists,
            )
            await _end_phase(job_id, "exploitation", "completed")
        except Exception as e:
            logger.exception(f"[{job_id}] Exploitation phase failed: {e}")
            await _end_phase(job_id, "exploitation", "failed", error_msg=str(e))
            await bus.publish(make_log(job_id, f"[Exploit] FAILED: {e} — continuing to post-exploitation", level="error", phase="exploitation"))
    else:
        await _end_phase(job_id, "exploitation", "skipped")

    # ── Phase 4 — Post-Exploitation ──────────────────────────────────────────
    postex_cfg = phases_cfg.get("post_exploitation", {})
    if postex_cfg.get("enabled", True):
        _current_phase[0] = "post_exploitation"
        await _begin_phase(job_id, "post_exploitation")
        try:
            await run_post_exploitation(
                job_id=job_id,
                target_ip=target_ip,
                profile_config=postex_cfg,
            )
            await _end_phase(job_id, "post_exploitation", "completed")
        except Exception as e:
            logger.exception(f"[{job_id}] Post-exploitation phase failed: {e}")
            await _end_phase(job_id, "post_exploitation", "failed", error_msg=str(e))
            await bus.publish(make_log(job_id, f"[PostEx] FAILED: {e}", level="error", phase="post_exploitation"))
    else:
        await _end_phase(job_id, "post_exploitation", "skipped")

    await _set_status(job_id, "completed")
    await bus.publish(make_log(job_id, "[Pipeline] Job completed.", level="info"))


async def _begin_phase(job_id: str, phase: str):
    async with AsyncSessionLocal() as session:
        await crud.update_job_status(session, job_id, "running", current_phase=phase)
        await crud.upsert_phase(session, job_id, phase, "running")
    await bus.publish(make_phase_change(job_id, phase, "started"))
    await bus.publish(make_log(job_id, f"[Pipeline] Phase started: {phase}", phase=phase))


async def _end_phase(job_id: str, phase: str, status: str, error_msg: str = None):
    async with AsyncSessionLocal() as session:
        await crud.upsert_phase(session, job_id, phase, status, error_msg=error_msg)
    await bus.publish(make_phase_change(job_id, phase, status))


async def _set_status(job_id: str, status: str, error_msg: str = None):
    async with AsyncSessionLocal() as session:
        await crud.update_job_status(session, job_id, status, error_msg=error_msg)
    await bus.publish(make_job_status(job_id, status))
