"""
metasploit.py — AutoPwn Metasploit integration via pymetasploit3.

Auto-exploits discovered CVEs by searching MSF and running matching exploits.
Requires: msfconsole running with RPC enabled on localhost:55553
"""
from __future__ import annotations

import logging
from typing import Optional

from .base import BaseWrapper
from ..core.event_bus import bus, make_log

logger = logging.getLogger("autopwn.msf")

# Graceful fallback if pymetasploit3 not installed
try:
    from pymetasploit3.msfrpc import MsfRpcClient
    MSF_AVAILABLE = True
except ImportError:
    MSF_AVAILABLE = False
    logger.warning("pymetasploit3 not available — Metasploit module disabled")


class MetasploitWrapper(BaseWrapper):
    """RPC wrapper around msfconsole for automated exploitation."""
    
    tool_name = "metasploit"
    tool_timeout_s = 300
    
    RPC_HOST = "127.0.0.1"
    RPC_PORT = 55553
    RPC_PASS = "msf"

    def build_command(self, **kwargs) -> list[str]:
        return ["msfconsole"]

    async def run(self, **kwargs) -> int:
        """Auto-exploit via Metasploit RPC."""
        if not MSF_AVAILABLE:
            await bus.publish(make_log(
                self.job_id,
                "[MSF] pymetasploit3 not installed",
                phase=self.phase, level="warning",
            ))
            return -1

        try:
            client = MsfRpcClient(
                password=self.RPC_PASS,
                host=self.RPC_HOST,
                port=self.RPC_PORT,
            )
        except Exception as e:
            await bus.publish(make_log(
                self.job_id,
                f"[MSF] RPC connect failed: {e}. Start msfconsole with RPC enabled.",
                phase=self.phase, level="error",
            ))
            return -1

        try:
            exploit = kwargs.get("exploit")
            target = kwargs.get("target")
            port = kwargs.get("port", 80)

            if not exploit or not target:
                return 0

            await bus.publish(make_log(
                self.job_id,
                f"[MSF] Running {exploit} on {target}:{port}",
                phase=self.phase,
            ))

            # Load and configure exploit
            mod = client.modules.use("exploit", exploit)
            mod["RHOSTS"] = target
            mod["RPORT"] = str(port)
            
            for key in ("USERNAME", "PASSWORD", "PAYLOAD", "LHOST", "LPORT"):
                if key.lower() in kwargs:
                    mod[key] = kwargs[key.lower()]

            # Execute
            result = client.modules.execute(mod)
            if result.get("job_id"):
                await bus.publish(make_log(
                    self.job_id,
                    f"[MSF] Exploit launched (job {result['job_id']})",
                    phase=self.phase,
                ))
                return 0
            else:
                return 1

        except Exception as e:
            logger.exception(f"[{self.job_id}] MSF error: {e}")
            return -2
