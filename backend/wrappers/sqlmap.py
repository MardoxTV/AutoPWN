from __future__ import annotations
import re
from typing import Optional

from .base import BaseWrapper
from ..core.event_bus import LogEvent, make_finding

_INJECTABLE_RE = re.compile(r"Parameter:\s+(.+?)\s+\(", re.IGNORECASE)
_DB_DUMPED_RE = re.compile(r"fetched data logged to text files", re.IGNORECASE)


class SqlmapWrapper(BaseWrapper):
    tool_name = "sqlmap"
    tool_timeout_s = 3600  # 1 hour

    def build_command(self, url: str, data: str = None,
                      level: int = 3, risk: int = 2,
                      dbs: bool = True, dump: bool = False,
                      extra_args: str = "", **kwargs) -> list[str]:
        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",           # never ask interactive questions
            "--level", str(level),
            "--risk", str(risk),
            "--timeout", "10",
            "--retries", "2",
        ]
        if data:
            cmd += ["--data", data]
        if dbs:
            cmd += ["--dbs"]
        if dump:
            cmd += ["--dump"]
        if extra_args:
            cmd += extra_args.split()
        return cmd

    async def parse_output(self, line: str) -> Optional[LogEvent]:
        if _INJECTABLE_RE.search(line):
            m = _INJECTABLE_RE.search(line)
            return make_finding(
                job_id=self.job_id, phase=self.phase,
                finding_type="sqli",
                value=f"Injectable parameter: {m.group(1)}",
                severity="critical",
                metadata={"raw": line.strip()},
            )
        if _DB_DUMPED_RE.search(line):
            return make_finding(
                job_id=self.job_id, phase=self.phase,
                finding_type="sqli_dump",
                value="sqlmap dumped database data",
                severity="critical",
            )
        return None
