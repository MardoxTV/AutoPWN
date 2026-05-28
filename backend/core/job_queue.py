from __future__ import annotations
import asyncio
import logging
from typing import Optional

logger = logging.getLogger("autopwn.queue")

_queue: asyncio.Queue = asyncio.Queue()
_worker_task: Optional[asyncio.Task] = None
# Maps job_id → the asyncio.Task running run_pipeline() for that job.
# Populated while the job is actively executing (not while it waits in queue).
_active_tasks: dict[str, asyncio.Task] = {}


async def enqueue(job_id: str) -> int:
    """Add job to queue. Returns 0-based queue position (0 = next to run)."""
    await _queue.put(job_id)
    position = _queue.qsize() - 1
    logger.info(f"Job {job_id} enqueued (position {position})")
    return position


async def cancel_job(job_id: str) -> bool:
    """Kill any running subprocess for the job and cancel its asyncio Task."""
    from ..wrappers.base import kill_job_procs
    await kill_job_procs(job_id)
    task = _active_tasks.get(job_id)
    if task and not task.done():
        task.cancel()
        logger.info(f"Cancelled asyncio task for job {job_id}")
        return True
    return False


async def _worker():
    from .pipeline import run_pipeline
    logger.info("Job worker started")
    while True:
        job_id = await _queue.get()
        logger.info(f"Worker picked up job {job_id}")
        task = asyncio.current_task()
        # Wrap pipeline in a sub-task so cancel_job() can target it specifically
        pipeline_task = asyncio.create_task(run_pipeline(job_id))
        _active_tasks[job_id] = pipeline_task
        try:
            await pipeline_task
        except asyncio.CancelledError:
            logger.info(f"Pipeline task for job {job_id} was cancelled")
        except Exception as e:
            logger.exception(f"Pipeline error for job {job_id}: {e}")
        finally:
            _active_tasks.pop(job_id, None)
            _queue.task_done()


def start_worker():
    global _worker_task
    if _worker_task is None or _worker_task.done():
        _worker_task = asyncio.create_task(_worker())
        logger.info("Job queue worker task created")


def stop_worker():
    global _worker_task
    if _worker_task and not _worker_task.done():
        _worker_task.cancel()
        _worker_task = None


def is_running(job_id: str) -> bool:
    return job_id in _active_tasks


def queue_size() -> int:
    return _queue.qsize()
