from __future__ import annotations
import asyncio
import logging

from ..client import ARMClient, PermissionError
from ..models import Finding, FindingStatus, Severity

logger = logging.getLogger("autopwn.azure.checks.network")

DANGEROUS_PORTS = {
    22: "SSH", 3389: "RDP", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    23: "Telnet", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
    27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 445: "SMB",
}


def _skip(check_id: str, title: str, reason: str) -> Finding:
    return Finding(
        id=check_id,
        category="Network",
        title=title,
        severity=Severity.INFO,
        status=FindingStatus.SKIP,
        description=f"Check skipped: {reason}",
        remediation="Ensure the authenticated account has Reader role on the subscription.",
    )


def _is_open_to_internet(rule: dict) -> bool:
    props = rule.get("properties", {})
    if props.get("direction") != "Inbound":
        return False
    if props.get("access") != "Allow":
        return False
    src = props.get("sourceAddressPrefix", "")
    return src in ("*", "0.0.0.0/0", "Internet", "Any")


def _get_port_range(rule: dict) -> set[int]:
    props = rule.get("properties", {})
    ranges: list[str] = []
    if props.get("destinationPortRange"):
        ranges.append(props["destinationPortRange"])
    ranges.extend(props.get("destinationPortRanges", []))

    ports: set[int] = set()
    for r in ranges:
        if r == "*":
            return set(DANGEROUS_PORTS.keys())
        if "-" in r:
            try:
                lo, hi = r.split("-")
                ports.update(range(int(lo), int(hi) + 1))
            except ValueError:
                pass
        else:
            try:
                ports.add(int(r))
            except ValueError:
                pass
    return ports


async def check_nsg_open_ports(client: ARMClient, subscription_id: str) -> Finding:
    try:
        nsgs = await client.get_list(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Network/networkSecurityGroups",
            "2023-09-01",
        )
        open_rules: list[dict] = []
        for nsg in nsgs:
            name = nsg.get("name", "")
            rg = nsg.get("id", "").split("/")[4] if nsg.get("id") else ""
            rules = (nsg.get("properties") or {}).get("securityRules", [])
            for rule in rules:
                if _is_open_to_internet(rule):
                    exposed = _get_port_range(rule) & set(DANGEROUS_PORTS.keys())
                    if exposed:
                        for port in exposed:
                            open_rules.append({
                                "nsg": name,
                                "resourceGroup": rg,
                                "rule": rule.get("name", ""),
                                "port": port,
                                "service": DANGEROUS_PORTS[port],
                            })

        if not open_rules:
            return Finding(
                id=f"AZURE-NET-001-{subscription_id[:8]}",
                category="Network",
                title="NSG: No Dangerous Ports Open to Internet",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description="No NSG rules expose dangerous management ports to the public internet.",
                remediation="No action required.",
            )

        rdp_ssh = [r for r in open_rules if r["port"] in (22, 3389)]
        severity = Severity.CRITICAL if rdp_ssh else Severity.HIGH
        return Finding(
            id=f"AZURE-NET-001-{subscription_id[:8]}",
            category="Network",
            title=f"NSG: {len(open_rules)} Dangerous Ports Exposed ({len(rdp_ssh)} RDP/SSH)",
            severity=severity,
            status=FindingStatus.FAIL,
            description=(
                f"{len(open_rules)} NSG rules expose dangerous management ports to the internet "
                f"across {len({r['nsg'] for r in open_rules})} NSGs. "
                f"{'RDP and/or SSH are directly accessible from the internet.' if rdp_ssh else ''}"
            ),
            remediation=(
                "Remove inbound Allow rules from internet (0.0.0.0/0) for management ports. "
                "Use Azure Bastion for RDP/SSH access. Enable Just-In-Time VM access in "
                "Defender for Cloud. Restrict management ports to known corporate IP ranges."
            ),
            affected_count=len(open_rules),
            affected_resources=open_rules[:50],
        )
    except PermissionError:
        return _skip(f"AZURE-NET-001-{subscription_id[:8]}", "NSG Open Ports", "Requires Reader on subscription")
    except Exception as e:
        return _skip(f"AZURE-NET-001-{subscription_id[:8]}", "NSG Open Ports", str(e))


async def check_vms_public_ip(client: ARMClient, subscription_id: str) -> Finding:
    try:
        nics = await client.get_list(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Network/networkInterfaces",
            "2023-09-01",
        )
        exposed_vms: list[dict] = []
        for nic in nics:
            props = nic.get("properties") or {}
            vm_id = props.get("virtualMachine", {}).get("id", "")
            for ip_config in props.get("ipConfigurations", []):
                ip_props = ip_config.get("properties") or {}
                if ip_props.get("publicIPAddress"):
                    exposed_vms.append({
                        "nic": nic.get("name", ""),
                        "vm": vm_id.split("/")[-1] if vm_id else "unattached",
                        "resourceGroup": nic.get("id", "").split("/")[4] if nic.get("id") else "",
                        "publicIpId": (ip_props["publicIPAddress"].get("id", "")),
                    })

        if not exposed_vms:
            return Finding(
                id=f"AZURE-NET-002-{subscription_id[:8]}",
                category="Network",
                title="No VMs with Direct Public IP",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description="No VM NICs are directly associated with a public IP address.",
                remediation="No action required.",
            )

        return Finding(
            id=f"AZURE-NET-002-{subscription_id[:8]}",
            category="Network",
            title=f"VMs with Public IP: {len(exposed_vms)} NICs Directly Exposed",
            severity=Severity.HIGH,
            status=FindingStatus.WARN,
            description=(
                f"{len(exposed_vms)} VM network interfaces have a directly attached public IP. "
                "Direct public IPs on VMs increase the attack surface — inbound management traffic "
                "should route through Azure Bastion or a load balancer with NSG controls."
            ),
            remediation=(
                "Replace direct public IPs with Azure Bastion for management access. "
                "If public access is required, ensure strict NSG rules limit inbound traffic. "
                "Use Azure Load Balancer with health probes instead of direct VM public IPs."
            ),
            affected_count=len(exposed_vms),
            affected_resources=exposed_vms[:50],
        )
    except PermissionError:
        return _skip(f"AZURE-NET-002-{subscription_id[:8]}", "VMs with Public IP", "Requires Reader on subscription")
    except Exception as e:
        return _skip(f"AZURE-NET-002-{subscription_id[:8]}", "VMs with Public IP", str(e))


async def run_all(client: ARMClient, subscription_id: str) -> list[Finding]:
    results = await asyncio.gather(
        check_nsg_open_ports(client, subscription_id),
        check_vms_public_ip(client, subscription_id),
        return_exceptions=True,
    )
    findings = []
    for r in results:
        if isinstance(r, Exception):
            logger.error("Network check raised: %s", r)
        else:
            findings.append(r)
    return findings
