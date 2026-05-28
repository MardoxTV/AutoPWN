from __future__ import annotations
import logging
from typing import Optional
import httpx

logger = logging.getLogger("autopwn.go_client")

SCANNER_BASE = "http://127.0.0.1:8001"


async def scan(target: str, ports: str = "1-65535", protocol: str = "tcp",
               rate: int = 1000, timeout_ms: int = 2000) -> Optional[dict]:
    payload = {
        "target": target,
        "ports": ports,
        "protocol": protocol,
        "rate": rate,
        "timeout_ms": timeout_ms,
    }
    try:
        async with httpx.AsyncClient(timeout=300) as client:
            r = await client.post(f"{SCANNER_BASE}/scan", json=payload)
            r.raise_for_status()
            return r.json()
    except Exception as e:
        logger.warning(f"Go scanner unavailable: {e}")
        return None


async def brute(target: str, port: int, service: str,
                userlist: list[str], passlist: list[str],
                threads: int = 16, timeout_ms: int = 5000) -> Optional[dict]:
    payload = {
        "target": target,
        "port": port,
        "service": service,
        "userlist": userlist,
        "passlist": passlist,
        "threads": threads,
        "timeout_ms": timeout_ms,
    }
    try:
        async with httpx.AsyncClient(timeout=600) as client:
            r = await client.post(f"{SCANNER_BASE}/brute", json=payload)
            r.raise_for_status()
            return r.json()
    except Exception as e:
        logger.warning(f"Go brute-forcer unavailable: {e}")
        return None


async def health() -> bool:
    try:
        async with httpx.AsyncClient(timeout=2) as client:
            r = await client.get(f"{SCANNER_BASE}/health")
            return r.status_code == 200
    except Exception:
        return False
