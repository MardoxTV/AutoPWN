from __future__ import annotations
import asyncio
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class LogEvent:
    type: str
    job_id: str
    timestamp: str = ""
    phase: Optional[str] = None
    tool: Optional[str] = None
    level: str = "info"
    message: Optional[str] = None
    data: Optional[str] = None        # raw ANSI output
    finding_type: Optional[str] = None
    severity: Optional[str] = None
    value: Optional[str] = None
    metadata: Optional[dict] = None
    status: Optional[str] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = _now()

    def to_json(self) -> str:
        d = {k: v for k, v in asdict(self).items() if v is not None}
        return json.dumps(d)


class EventBus:
    def __init__(self):
        # job_id -> list of subscriber queues
        self._subscribers: dict[str, list[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()

    async def subscribe(self, job_id: str, maxsize: int = 1000) -> asyncio.Queue:
        async with self._lock:
            q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
            self._subscribers.setdefault(job_id, []).append(q)
            return q

    async def unsubscribe(self, job_id: str, queue: asyncio.Queue):
        async with self._lock:
            subs = self._subscribers.get(job_id, [])
            if queue in subs:
                subs.remove(queue)
            if not subs:
                self._subscribers.pop(job_id, None)

    async def publish(self, event: LogEvent):
        async with self._lock:
            queues = list(self._subscribers.get(event.job_id, []))

        for q in queues:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Drop oldest, insert newest to avoid blocking the pipeline
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except Exception:
                    pass

    def publish_sync(self, event: LogEvent):
        """Fire-and-forget from sync context — schedules on the running loop."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.publish(event))
        except RuntimeError:
            pass


# Singleton
bus = EventBus()


def make_log(job_id: str, message: str, phase: str = None, tool: str = None,
             level: str = "info") -> LogEvent:
    return LogEvent(type="log", job_id=job_id, phase=phase, tool=tool,
                    level=level, message=message)


def make_tool_output(job_id: str, tool: str, data: str,
                     phase: str = None) -> LogEvent:
    return LogEvent(type="tool_output", job_id=job_id, tool=tool,
                    data=data, phase=phase)


def make_phase_change(job_id: str, phase: str, status: str) -> LogEvent:
    return LogEvent(type="phase_change", job_id=job_id, phase=phase, status=status)


def make_finding(job_id: str, phase: str, finding_type: str, value: str,
                 severity: str = "info", metadata: dict = None) -> LogEvent:
    return LogEvent(type="finding", job_id=job_id, phase=phase,
                    finding_type=finding_type, value=value,
                    severity=severity, metadata=metadata)


def make_job_status(job_id: str, status: str) -> LogEvent:
    return LogEvent(type="job_status", job_id=job_id, status=status)
