from __future__ import annotations
import asyncio
import urllib.parse
import logging

from ..core.event_bus import bus, make_log, make_finding

logger = logging.getLogger("autopwn.xss")

_XSS_PAYLOAD = "<autopwn_xss_test>"
_SSTI_PAYLOADS = {
    "{{7*7}}": "49",     # Jinja2 / Twig
    "${7*7}": "49",      # FreeMarker / EL / Velocity
    "<%= 7*7 %>": "49", # ERB / EJS
    "#{7*7}": "49",      # Thymeleaf / Ruby
}

_XSS_PARAMS = ["q", "search", "query", "s", "id", "name", "input", "text",
               "value", "msg", "message", "keyword", "term", "data"]
_SSTI_PARAMS = ["name", "template", "msg", "message", "text", "input",
                "greeting", "subject", "body", "content"]


async def probe_xss(job_id: str, base_url: str) -> None:
    """Test common GET parameters for reflected XSS."""
    await bus.publish(make_log(
        job_id, f"[XSS] Probing reflected XSS on {base_url}", phase="exploitation"
    ))
    found = False
    for param in _XSS_PARAMS:
        if found:
            break
        url = f"{base_url}?{param}={urllib.parse.quote(_XSS_PAYLOAD)}"
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sk", "--max-time", "8", url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            body = stdout.decode(errors="replace")
            if _XSS_PAYLOAD in body:
                found = True
                await bus.publish(make_finding(
                    job_id=job_id, phase="exploitation",
                    finding_type="xss",
                    value=f"Reflected XSS in parameter '{param}': {url}",
                    severity="high",
                    metadata={"url": url, "param": param, "payload": _XSS_PAYLOAD},
                ))
        except Exception as e:
            logger.debug(f"[xss] curl error on {url}: {e}")


async def probe_ssti(job_id: str, base_url: str) -> None:
    """Test common GET parameters for Server-Side Template Injection."""
    await bus.publish(make_log(
        job_id, f"[SSTI] Probing template injection on {base_url}", phase="exploitation"
    ))
    for param in _SSTI_PARAMS:
        for payload, expected in _SSTI_PAYLOADS.items():
            url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            try:
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sk", "--max-time", "8", url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await proc.communicate()
                body = stdout.decode(errors="replace")
                if expected in body:
                    await bus.publish(make_finding(
                        job_id=job_id, phase="exploitation",
                        finding_type="ssti",
                        value=f"SSTI via '{param}' (payload: {payload!r}): {url}",
                        severity="critical",
                        metadata={"url": url, "param": param,
                                  "payload": payload, "expected": expected},
                    ))
                    return  # stop on first confirmed hit
            except Exception as e:
                logger.debug(f"[ssti] curl error on {url}: {e}")
