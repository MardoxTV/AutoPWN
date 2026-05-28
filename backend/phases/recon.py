from __future__ import annotations
import logging
from ..wrappers.nmap import NmapWrapper, NmapResult
from ..core.event_bus import bus, make_log
from ..database import crud
from ..database.session import AsyncSessionLocal

logger = logging.getLogger("autopwn.recon")


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
