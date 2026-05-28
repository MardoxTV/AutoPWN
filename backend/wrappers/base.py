from __future__ import annotations
import asyncio
import os
import signal
import logging
from abc import ABC, abstractmethod
from typing import Optional, AsyncIterator

from ..core.event_bus import bus, make_tool_output, make_log, LogEvent

logger = logging.getLogger("autopwn.wrapper")

# Hard cap: no single tool run can exceed this. Brute-force tools get a longer
# cap via tool_timeout_s on the subclass. Default covers deep nmap/nikto runs.
DEFAULT_TOOL_TIMEOUT_S = 1800  # 30 min

# Registry of active subprocesses per job — used by cancel_job() to SIGTERM
# running tools without waiting for the asyncio Task to reach a yield point.
_job_procs: dict[str, list] = {}


def _register_proc(job_id: str, proc) -> None:
    _job_procs.setdefault(job_id, []).append(proc)


def _unregister_proc(job_id: str, proc) -> None:
    procs = _job_procs.get(job_id, [])
    if proc in procs:
        procs.remove(proc)
    if not procs:
        _job_procs.pop(job_id, None)


async def kill_job_procs(job_id: str) -> None:
    """Kill all subprocesses registered under job_id (called on cancel)."""
    procs = _job_procs.pop(job_id, [])
    for proc in procs:
        try:
            if proc.returncode is None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except (ProcessLookupError, OSError):
                    proc.terminate()
        except Exception:
            pass


class BaseWrapper(ABC):
    tool_name: str = "unknown"
    tool_timeout_s: int = DEFAULT_TOOL_TIMEOUT_S

    def __init__(self, job_id: str, phase: str):
        self.job_id = job_id
        self.phase = phase

    @abstractmethod
    def build_command(self, **kwargs) -> list[str]:
        """Return the command + args list to execute."""

    async def parse_output(self, line: str) -> Optional[LogEvent]:
        """Override to emit findings from tool output lines."""
        return None

    async def run(self, **kwargs) -> int:
        """Run the tool with a hard timeout, stream output, return exit code."""
        cmd = self.build_command(**kwargs)
        await bus.publish(make_log(
            self.job_id,
            f"[{self.tool_name}] Running: {' '.join(str(c) for c in cmd)}",
            phase=self.phase,
            tool=self.tool_name,
        ))

        try:
            exit_code = await asyncio.wait_for(
                self._run_with_pty(cmd),
                timeout=self.tool_timeout_s,
            )
            return exit_code
        except asyncio.TimeoutError:
            msg = f"[{self.tool_name}] Timed out after {self.tool_timeout_s}s — killed"
            logger.warning(f"[{self.job_id}] {msg}")
            await bus.publish(make_log(self.job_id, msg, phase=self.phase, tool=self.tool_name, level="warning"))
            return -1
        except Exception as e:
            msg = f"[{self.tool_name}] Unexpected error: {e}"
            logger.exception(f"[{self.job_id}] {msg}")
            await bus.publish(make_log(self.job_id, msg, phase=self.phase, tool=self.tool_name, level="error"))
            return -2

    async def _run_with_pty(self, cmd: list[str]) -> int:
        """Run command via pty to force line-buffered output from tools."""
        try:
            import pty
            master_fd, slave_fd = pty.openpty()
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=slave_fd,
                stderr=slave_fd,
                stdin=asyncio.subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
            os.close(slave_fd)
            _register_proc(self.job_id, proc)

            loop = asyncio.get_running_loop()
            reader = asyncio.StreamReader()
            transport, _ = await loop.connect_read_pipe(
                lambda: asyncio.StreamReaderProtocol(reader),
                os.fdopen(master_fd, "rb", 0),
            )

            try:
                async for line in self._iter_lines(reader):
                    await self._emit_line(line)
            finally:
                transport.close()
                _unregister_proc(self.job_id, proc)
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except (ProcessLookupError, OSError):
                    pass

            await proc.wait()
            return proc.returncode or 0

        except (ImportError, OSError):
            return await self._run_plain(cmd)

    async def _run_plain(self, cmd: list[str]) -> int:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except FileNotFoundError:
            msg = f"[{self.tool_name}] Binary not found — is it installed?"
            await bus.publish(make_log(self.job_id, msg, phase=self.phase, tool=self.tool_name, level="error"))
            return -3

        _register_proc(self.job_id, proc)
        try:
            async for line in proc.stdout:
                decoded = line.decode(errors="replace").rstrip()
                await self._emit_line(decoded)
        finally:
            _unregister_proc(self.job_id, proc)
            try:
                proc.terminate()
            except ProcessLookupError:
                pass

        await proc.wait()
        return proc.returncode or 0

    async def _iter_lines(self, reader: asyncio.StreamReader) -> AsyncIterator[str]:
        buf = b""
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=0.1)
                if not chunk:
                    if buf:
                        yield buf.decode(errors="replace").rstrip()
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    yield line.decode(errors="replace").rstrip()
            except asyncio.TimeoutError:
                if buf:
                    yield buf.decode(errors="replace").rstrip()
                    buf = b""
            except Exception:
                break

    async def _emit_line(self, line: str):
        if not line:
            return
        await bus.publish(make_tool_output(self.job_id, self.tool_name, line, self.phase))
        try:
            finding = await self.parse_output(line)
            if finding:
                await bus.publish(finding)
        except Exception as e:
            logger.debug(f"[{self.tool_name}] parse_output error on line: {e}")
