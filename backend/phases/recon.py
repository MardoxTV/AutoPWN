from __future__ import annotations
import logging
from ..wrappers.nmap import NmapWrapper, NmapResult
from ..core.event_bus import bus, make_log
from ..core.hosts import add_hosts, is_root
from ..database import crud
from ..database.session import AsyncSessionLocal

logger = logging.getLogger("autopwn.recon")


async def _add_to_hosts(job_id: str, target_ip: str, hostnames: list[str]) -> list[str]:
    """Add discovered hostnames to /etc/hosts and report to the live job log."""
    if not hostnames:
        return []
    if not is_root():
        await bus.publish(make_log(
            job_id,
            f"[Recon] Discovered hostnames {hostnames} but not running as root — skipping /etc/hosts update",
            phase="recon", level="warning",
        ))
        return []

    added = add_hosts(target_ip=target_ip, hostnames=hostnames, job_id=job_id)
    if added:
        await bus.publish(make_log(
            job_id,
            f"[Recon] Added {len(added)} hostname(s) to /etc/hosts: {', '.join(added)}",
            phase="recon",
        ))
    return added


async def run_recon(job_id: str, target_ip: str, nmap_args: str = "-sV -sC -p- -T4",
                    udp: bool = False, udp_args: str = "-sU --top-ports 200") -> NmapResult:
    await bus.publish(make_log(job_id, f"[Recon] Starting TCP scan of {target_ip}", phase="recon"))

    wrapper = NmapWrapper(job_id=job_id, phase="recon")
    result = await wrapper.run_scan(target=target_ip, extra_args=nmap_args)
    await wrapper.emit_findings(result)

    open_ports = [p for p in result.ports if p.state == "open"]
    await bus.publish(make_log(
        job_id,
        f"[Recon] TCP scan complete — {len(open_ports)} open port(s): "
        + ", ".join(f"{p.port}/{p.protocol}" for p in open_ports),
        phase="recon",
    ))

    # Auto-register hostnames discovered in HTTP redirects, SSL certs, etc.
    # so downstream phases (gobuster vhost, web fuzzing) can reach them by name.
    if result.discovered_hostnames:
        await bus.publish(make_log(
            job_id,
            f"[Recon] Discovered hostnames in service output: {', '.join(result.discovered_hostnames)}",
            phase="recon",
        ))
        added = await _add_to_hosts(job_id, target_ip, result.discovered_hostnames)
        # Persist as findings + extend hostnames list so downstream phases see them
        for h in result.discovered_hostnames:
            if h not in result.hostnames:
                result.hostnames.append(h)
        async with AsyncSessionLocal() as session:
            for h in added:
                await crud.add_finding(
                    session, job_id=job_id, phase="recon", tool="nmap",
                    finding_type="hostname",
                    value=h,
                    severity="info",
                    metadata={"source": "script_output", "added_to_hosts": True},
                )

    async with AsyncSessionLocal() as session:
        for p in open_ports:
            await crud.add_finding(
                session, job_id=job_id, phase="recon", tool="nmap",
                finding_type="open_port",
                value=f"{p.port}/{p.protocol}",
                severity="info",
                metadata={"port": p.port, "protocol": p.protocol,
                          "service": p.service, "version": p.version,
                          "product": p.product},
            )

    if udp:
        await bus.publish(make_log(job_id, f"[Recon] Starting UDP scan of {target_ip}", phase="recon"))
        udp_result = await wrapper.run_scan(target=target_ip, extra_args=udp_args)
        await wrapper.emit_findings(udp_result)
        # Merge UDP open ports into result
        result.ports += [p for p in udp_result.ports if p.state == "open"]

    return result
