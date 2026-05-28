from __future__ import annotations
import re
from typing import Optional

from .base import BaseWrapper
from ..core.event_bus import LogEvent, make_finding

_FOUND_RE = re.compile(
    r"\[(\d+)\]\[(\w+)\] host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)"
)


class HydraWrapper(BaseWrapper):
    tool_name = "hydra"
    tool_timeout_s = 7200  # 2 hours for brute-force runs

    def build_command(self, target: str, port: int, service: str,
                      userlist: str, passlist: str,
                      threads: int = 16, **kwargs) -> list[str]:
        return [
            "hydra",
            "-L", userlist,
            "-P", passlist,
            "-s", str(port),
            "-t", str(threads),
            "-f",        # stop after first valid pair
            "-q",
            f"{service}://{target}",
        ]

    async def parse_output(self, line: str) -> Optional[LogEvent]:
        m = _FOUND_RE.search(line)
        if m:
            port, service, host, login, password = m.groups()
            return make_finding(
                job_id=self.job_id, phase=self.phase,
                finding_type="credential",
                value=f"{login}:{password}",
                severity="critical",
                metadata={
                    "service": service,
                    "host": host,
                    "port": int(port),
                    "username": login,
                    "password": password,
                },
            )
        return None
