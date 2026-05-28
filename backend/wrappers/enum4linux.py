from __future__ import annotations
import shutil
from typing import Optional

from .base import BaseWrapper
from ..core.event_bus import LogEvent, make_finding


class Enum4linuxWrapper(BaseWrapper):
    tool_name = "enum4linux"

    def build_command(self, target: str, **kwargs) -> list[str]:
        binary = "enum4linux-ng" if shutil.which("enum4linux-ng") else "enum4linux"
        self.tool_name = binary
        if binary == "enum4linux-ng":
            return [binary, "-A", target, "-oJ", "/dev/null"]
        return [binary, "-a", target]

    async def parse_output(self, line: str) -> Optional[LogEvent]:
        line_lower = line.lower()
        if "share" in line_lower and "ok" in line_lower:
            return make_finding(
                job_id=self.job_id, phase=self.phase,
                finding_type="smb_share", value=line.strip(), severity="info",
            )
        if "user:" in line_lower or "username:" in line_lower:
            return make_finding(
                job_id=self.job_id, phase=self.phase,
                finding_type="smb_user", value=line.strip(), severity="info",
            )
        return None
