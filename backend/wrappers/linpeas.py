from __future__ import annotations
import re
import asyncio
import logging
from typing import Optional

from .base import BaseWrapper
from ..core.event_bus import LogEvent, make_finding, bus, make_log

logger = logging.getLogger("autopwn.linpeas")

_FLAG_PATTERNS = [
    re.compile(r"[a-f0-9]{32}"),
    re.compile(r"HTB\{[^}]+\}"),
]

_PRIVESC_RE = re.compile(
    r"(SUID|SGID|sudo|writable|cron|password|credential|token|secret|root)",
    re.IGNORECASE,
)


class LinpeasWrapper(BaseWrapper):
    tool_name = "linpeas"

    def build_command(self, **kwargs) -> list[str]:
        return []  # Not used directly — linpeas runs on target, not locally

    async def parse_output(self, line: str) -> Optional[LogEvent]:
        for pattern in _FLAG_PATTERNS:
            m = pattern.search(line)
            if m:
                flag = m.group(0)
                flag_type = "root" if "root" in line.lower() else "user"
                return make_finding(
                    job_id=self.job_id, phase=self.phase,
                    finding_type="flag",
                    value=flag,
                    severity="critical",
                    metadata={"flag_type": flag_type, "context": line.strip()},
                )

        if _PRIVESC_RE.search(line) and ("!" in line or "99%" in line or "[+]" in line):
            return make_finding(
                job_id=self.job_id, phase=self.phase,
                finding_type="privesc_hint",
                value=line.strip(),
                severity="high",
            )
        return None

    async def run_on_target(self, shell_session, linpeas_path: str = "/opt/autopwn/loot/linpeas.sh"):
        """Upload and run linpeas on a remote shell session (future: paramiko/netcat)."""
        await bus.publish(make_log(
            self.job_id, "[linpeas] Uploading and running linpeas on target...",
            phase=self.phase, tool="linpeas",
        ))
        # Placeholder: actual shell session upload/run logic handled by post_exploitation phase
        pass
