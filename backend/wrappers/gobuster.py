from __future__ import annotations
import re
from typing import Optional

from .base import BaseWrapper
from ..core.event_bus import LogEvent, make_finding

_FOUND_RE = re.compile(r"^/(\S+)\s+\(Status:\s*(\d+)\)")


class GobusterWrapper(BaseWrapper):
    tool_name = "gobuster"

    def build_command(self, url: str, wordlist: str,
                      threads: int = 20, extensions: str = "",
                      mode: str = "dir", **kwargs) -> list[str]:
        cmd = [
            "gobuster", mode,
            "-u", url,
            "-w", wordlist,
            "-t", str(threads),
            "--no-error",
            "-q",
        ]
        if extensions:
            cmd += ["-x", extensions]
        return cmd

    async def parse_output(self, line: str) -> Optional[LogEvent]:
        m = _FOUND_RE.search(line)
        if m:
            path, status = m.group(1), m.group(2)
            severity = "medium" if status.startswith("2") else "info"
            return make_finding(
                job_id=self.job_id, phase=self.phase,
                finding_type="http_path",
                value=f"/{path}",
                severity=severity,
                metadata={"status_code": int(status)},
            )
        return None
