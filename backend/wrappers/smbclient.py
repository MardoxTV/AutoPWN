from __future__ import annotations
import re
from typing import Optional

from .base import BaseWrapper
from ..core.event_bus import LogEvent, make_finding

_SHARE_RE = re.compile(r"^\s+(\S+)\s+Disk", re.IGNORECASE)


class SmbclientWrapper(BaseWrapper):
    tool_name = "smbclient"

    def build_command(self, target: str, **kwargs) -> list[str]:
        return ["smbclient", "-L", f"//{target}", "-N", "--no-pass"]

    async def parse_output(self, line: str) -> Optional[LogEvent]:
        m = _SHARE_RE.match(line)
        if m:
            return make_finding(
                job_id=self.job_id, phase=self.phase,
                finding_type="smb_share",
                value=m.group(1),
                severity="info",
                metadata={"share": m.group(1)},
            )
        return None
