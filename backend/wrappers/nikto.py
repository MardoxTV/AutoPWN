from __future__ import annotations
import re
from typing import Optional

from .base import BaseWrapper
from ..core.event_bus import LogEvent, make_finding

_VULN_RE = re.compile(r"^\+\s+(.+)")


class NiktoWrapper(BaseWrapper):
    tool_name = "nikto"

    def build_command(self, host: str, port: int = 80,
                      ssl: bool = False, **kwargs) -> list[str]:
        scheme = "https" if ssl else "http"
        return [
            "nikto",
            "-h", f"{scheme}://{host}:{port}",
            "-nointeractive",
            "-Format", "txt",
        ]

    async def parse_output(self, line: str) -> Optional[LogEvent]:
        m = _VULN_RE.match(line)
        if m and "OSVDB" in line or "CVE" in line or "vulnerable" in line.lower():
            return make_finding(
                job_id=self.job_id, phase=self.phase,
                finding_type="vuln",
                value=m.group(1).strip(),
                severity="medium",
            )
        return None
