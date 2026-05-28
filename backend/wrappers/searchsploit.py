from __future__ import annotations
import asyncio
import json
from typing import Optional

from .base import BaseWrapper
from ..core.event_bus import LogEvent, make_finding, bus, make_log


class SearchsploitWrapper(BaseWrapper):
    tool_name = "searchsploit"

    def build_command(self, query: str, **kwargs) -> list[str]:
        return ["searchsploit", "--json", query]

    async def search(self, query: str) -> list[dict]:
        cmd = ["searchsploit", "--json", query]
        await bus.publish(make_log(
            self.job_id, f"[searchsploit] Searching: {query}",
            phase=self.phase, tool="searchsploit",
        ))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        try:
            data = json.loads(stdout)
            exploits = data.get("RESULTS_EXPLOIT", [])
            for e in exploits:
                await bus.publish(make_finding(
                    job_id=self.job_id, phase=self.phase,
                    finding_type="exploit",
                    value=e.get("Title", "Unknown exploit"),
                    severity="high",
                    metadata={
                        "path": e.get("Path", ""),
                        "edb_id": e.get("EDB-ID", ""),
                        "type": e.get("Type", ""),
                    },
                ))
            return exploits
        except (json.JSONDecodeError, KeyError):
            return []
