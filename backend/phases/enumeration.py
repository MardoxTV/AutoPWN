from __future__ import annotations
import asyncio
import logging

from ..wrappers.nmap import NmapResult, NmapPort
from ..wrappers.gobuster import GobusterWrapper
from ..wrappers.nikto import NiktoWrapper
from ..wrappers.enum4linux import Enum4linuxWrapper
from ..wrappers.smbclient import SmbclientWrapper
from ..core.event_bus import bus, make_log
from ..database import crud
from ..database.session import AsyncSessionLocal

logger = logging.getLogger("autopwn.enum")

DEFAULT_WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"


async def run_enumeration(job_id: str, target_ip: str, nmap_result: NmapResult,
                           profile_config: dict, wordlist: str = DEFAULT_WORDLIST):
    open_ports = [p for p in nmap_result.ports if p.state == "open"]

    await bus.publish(make_log(
        job_id, f"[Enum] Dispatching enumeration for {len(open_ports)} open port(s)",
        phase="enumeration",
    ))

    tasks = []
    for port in open_ports:
        svc = port.service.lower()

        # Independent ifs — a port can trigger multiple enumerators (e.g. HTTPS + vhost)
        if profile_config.get("http") and svc in ("http", "https", "http-alt", "ssl/http"):
            ssl = "https" in svc or port.port == 443
            tasks.append(_enum_http(job_id, target_ip, port, ssl, wordlist))

        if profile_config.get("smb") and (svc in ("microsoft-ds", "smb", "netbios-ssn") or port.port in (139, 445)):
            tasks.append(_enum_smb(job_id, target_ip, port))

        if profile_config.get("ftp") and svc == "ftp":
            tasks.append(_enum_ftp(job_id, target_ip, port))

        if profile_config.get("ssh") and svc == "ssh":
            tasks.append(_enum_ssh(job_id, target_ip, port))

        if profile_config.get("snmp") and (svc == "snmp" or port.port == 161):
            tasks.append(_enum_snmp(job_id, target_ip, port))

    await asyncio.gather(*tasks, return_exceptions=True)
    await bus.publish(make_log(job_id, "[Enum] Enumeration complete", phase="enumeration"))


async def _enum_http(job_id: str, target: str, port: NmapPort, ssl: bool, wordlist: str):
    scheme = "https" if ssl else "http"
    url = f"{scheme}://{target}:{port.port}"
    await bus.publish(make_log(job_id, f"[Enum/HTTP] Probing {url}", phase="enumeration"))

    # Gobuster directory brute
    gobuster = GobusterWrapper(job_id=job_id, phase="enumeration")
    await gobuster.run(url=url, wordlist=wordlist, threads=20,
                       extensions="php,html,txt,js,bak")

    # Nikto
    nikto = NiktoWrapper(job_id=job_id, phase="enumeration")
    await nikto.run(host=target, port=port.port, ssl=ssl)

    # Gobuster vhost fuzzing
    vhost_wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    import os
    if os.path.exists(vhost_wordlist):
        gobuster_vhost = GobusterWrapper(job_id=job_id, phase="enumeration")
        await gobuster_vhost.run(
            url=url, wordlist=vhost_wordlist,
            mode="vhost", threads=20,
        )


async def _enum_smb(job_id: str, target: str, port: NmapPort):
    await bus.publish(make_log(
        job_id, f"[Enum/SMB] Enumerating SMB on {target}:{port.port}", phase="enumeration"
    ))
    smbclient = SmbclientWrapper(job_id=job_id, phase="enumeration")
    await smbclient.run(target=target)

    enum4linux = Enum4linuxWrapper(job_id=job_id, phase="enumeration")
    await enum4linux.run(target=target)


async def _enum_ftp(job_id: str, target: str, port: NmapPort):
    await bus.publish(make_log(
        job_id, f"[Enum/FTP] Checking anonymous FTP on {target}:{port.port}", phase="enumeration"
    ))
    # Use nmap script for anon check
    from ..wrappers.nmap import NmapWrapper
    wrapper = NmapWrapper(job_id=job_id, phase="enumeration")
    await wrapper.run(
        target=target,
        extra_args=f"-p {port.port} --script=ftp-anon,ftp-bounce -T4",
    )


async def _enum_ssh(job_id: str, target: str, port: NmapPort):
    await bus.publish(make_log(
        job_id, f"[Enum/SSH] Banner grab SSH on {target}:{port.port}", phase="enumeration"
    ))
    from ..wrappers.nmap import NmapWrapper
    wrapper = NmapWrapper(job_id=job_id, phase="enumeration")
    await wrapper.run(
        target=target,
        extra_args=f"-p {port.port} --script=ssh2-enum-algos,ssh-auth-methods -T4",
    )


async def _enum_snmp(job_id: str, target: str, port: NmapPort):
    await bus.publish(make_log(
        job_id, f"[Enum/SNMP] Walking SNMP on {target}:{port.port}", phase="enumeration"
    ))
    from ..wrappers.nmap import NmapWrapper
    wrapper = NmapWrapper(job_id=job_id, phase="enumeration")
    await wrapper.run(
        target=target,
        extra_args=f"-sU -p {port.port} --script=snmp-walk,snmp-info -T4",
    )
