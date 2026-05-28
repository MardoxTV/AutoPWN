from __future__ import annotations
import asyncio
import logging
import tempfile
import os
from typing import Optional
from dataclasses import dataclass, field

from .base import BaseWrapper
from ..core.event_bus import make_finding, bus

logger = logging.getLogger("autopwn.nmap")


@dataclass
class NmapPort:
    port: int
    protocol: str
    state: str
    service: str = ""
    version: str = ""
    product: str = ""


@dataclass
class NmapResult:
    target: str
    ports: list[NmapPort] = field(default_factory=list)
    os_guess: Optional[str] = None
    hostnames: list[str] = field(default_factory=list)


class NmapWrapper(BaseWrapper):
    tool_name = "nmap"

    def build_command(self, target: str, extra_args: str = "-sV -sC -p- -T4",
                      output_file: str = None, **kwargs) -> list[str]:
        cmd = ["nmap", target] + extra_args.split()
        if output_file:
            cmd += ["-oX", output_file]
        return cmd

    async def run_scan(self, target: str, extra_args: str = "-sV -sC -p- -T4") -> NmapResult:
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            xml_path = f.name

        try:
            cmd = self.build_command(target=target, extra_args=extra_args, output_file=xml_path)
            await self._run_nmap(cmd)
            return self._parse_xml(xml_path, target)
        finally:
            try:
                os.unlink(xml_path)
            except OSError:
                pass

    async def _run_nmap(self, cmd: list[str]):
        from ..core.event_bus import make_log
        await bus.publish(make_log(
            self.job_id, f"[nmap] Running: {' '.join(cmd)}",
            phase=self.phase, tool="nmap",
        ))
        try:
            await asyncio.wait_for(self._run_plain(cmd), timeout=self.tool_timeout_s)
        except asyncio.TimeoutError:
            msg = f"[nmap] Scan timed out after {self.tool_timeout_s}s — killed"
            logger.warning(f"[{self.job_id}] {msg}")
            await bus.publish(make_log(self.job_id, msg,
                                       phase=self.phase, tool="nmap", level="warning"))

    def _parse_xml(self, xml_path: str, target: str) -> NmapResult:
        try:
            from libnmap.parser import NmapParser
            report = NmapParser.parse_fromfile(xml_path)
            result = NmapResult(target=target)
            for host in report.hosts:
                result.hostnames = list(host.hostnames)
                if host.os_match_probabilities():
                    result.os_guess = host.os_match_probabilities()[0].name
                for svc in host.services:
                    result.ports.append(NmapPort(
                        port=svc.port,
                        protocol=svc.protocol,
                        state=svc.state,
                        service=svc.service,
                        version=svc.version,
                        product=svc.product,
                    ))
            return result
        except Exception as e:
            logger.warning(f"[nmap] Failed to parse XML results for {target}: {e}")
            return NmapResult(target=target)

    async def emit_findings(self, result: NmapResult):
        for p in result.ports:
            if p.state == "open":
                await bus.publish(make_finding(
                    job_id=self.job_id,
                    phase=self.phase,
                    finding_type="open_port",
                    value=f"{p.port}/{p.protocol}",
                    severity="info",
                    metadata={
                        "port": p.port,
                        "protocol": p.protocol,
                        "service": p.service,
                        "version": p.version,
                        "product": p.product,
                    },
                ))
