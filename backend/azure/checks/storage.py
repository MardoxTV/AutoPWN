from __future__ import annotations
import asyncio
import logging

from ..client import ARMClient, PermissionError
from ..models import Finding, FindingStatus, Severity

logger = logging.getLogger("autopwn.azure.checks.storage")


def _skip(check_id: str, title: str, reason: str) -> Finding:
    return Finding(
        id=check_id,
        category="Storage & Secrets",
        title=title,
        severity=Severity.INFO,
        status=FindingStatus.SKIP,
        description=f"Check skipped: {reason}",
        remediation="Ensure the authenticated account has Reader on the subscription.",
    )


async def check_storage_accounts(client: ARMClient, subscription_id: str) -> list[Finding]:
    try:
        accounts = await client.get_list(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Storage/storageAccounts",
            "2023-05-01",
        )
        if not accounts:
            return [Finding(
                id=f"AZURE-STG-001-{subscription_id[:8]}",
                category="Storage & Secrets",
                title="No Storage Accounts Found",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description="No storage accounts in this subscription.",
                remediation="No action required.",
            )]

        public_blob: list[dict] = []
        no_https: list[dict] = []
        old_tls: list[dict] = []
        shared_key_allowed: list[dict] = []

        for sa in accounts:
            name = sa.get("name", "")
            rg = sa.get("id", "").split("/")[4] if sa.get("id") else ""
            props = sa.get("properties") or {}

            entry = {"name": name, "resourceGroup": rg}

            # Public blob access
            if props.get("allowBlobPublicAccess", True):
                public_blob.append(entry)

            # HTTPS enforcement
            if not props.get("supportsHttpsTrafficOnly", True):
                no_https.append(entry)

            # TLS version
            min_tls = props.get("minimumTlsVersion", "TLS1_0")
            if min_tls in ("TLS1_0", "TLS1_1"):
                old_tls.append({**entry, "minTLS": min_tls})

            # Shared key auth enabled (default true — should be disabled)
            if props.get("allowSharedKeyAccess", True):
                shared_key_allowed.append(entry)

        findings: list[Finding] = []

        if public_blob:
            findings.append(Finding(
                id=f"AZURE-STG-001-{subscription_id[:8]}",
                category="Storage & Secrets",
                title=f"Storage: {len(public_blob)} Accounts Allow Public Blob Access",
                severity=Severity.HIGH,
                status=FindingStatus.FAIL,
                description=(
                    f"{len(public_blob)} storage accounts have public blob access enabled. "
                    "Any container in these accounts can be made publicly readable, risking data exposure."
                ),
                remediation=(
                    "Set 'Allow Blob public access' to Disabled on each storage account. "
                    "Audit existing containers for public access and restrict them."
                ),
                affected_count=len(public_blob),
                affected_resources=public_blob[:30],
            ))

        if no_https:
            findings.append(Finding(
                id=f"AZURE-STG-002-{subscription_id[:8]}",
                category="Storage & Secrets",
                title=f"Storage: {len(no_https)} Accounts Allow HTTP (Non-HTTPS)",
                severity=Severity.HIGH,
                status=FindingStatus.FAIL,
                description=(
                    f"{len(no_https)} storage accounts do not enforce HTTPS-only traffic. "
                    "Data in transit can be intercepted over unencrypted HTTP connections."
                ),
                remediation="Enable 'Secure transfer required' (HTTPS only) on all storage accounts.",
                affected_count=len(no_https),
                affected_resources=no_https[:30],
            ))

        if old_tls:
            findings.append(Finding(
                id=f"AZURE-STG-003-{subscription_id[:8]}",
                category="Storage & Secrets",
                title=f"Storage: {len(old_tls)} Accounts Accept Old TLS Versions",
                severity=Severity.MEDIUM,
                status=FindingStatus.FAIL,
                description=(
                    f"{len(old_tls)} storage accounts allow TLS 1.0 or 1.1, which have known "
                    "cryptographic weaknesses and are deprecated."
                ),
                remediation="Set 'Minimum TLS version' to TLS 1.2 on all storage accounts.",
                affected_count=len(old_tls),
                affected_resources=old_tls[:30],
            ))

        if shared_key_allowed:
            findings.append(Finding(
                id=f"AZURE-STG-004-{subscription_id[:8]}",
                category="Storage & Secrets",
                title=f"Storage: {len(shared_key_allowed)} Accounts Allow Shared Key Auth",
                severity=Severity.MEDIUM,
                status=FindingStatus.WARN,
                description=(
                    f"{len(shared_key_allowed)} storage accounts allow Shared Key (account key) "
                    "authentication. Account keys grant full access with no RBAC or audit trail."
                ),
                remediation=(
                    "Disable shared key access where possible ('allowSharedKeyAccess: false'). "
                    "Use Azure AD (RBAC) or SAS tokens with IP restrictions and expiry instead."
                ),
                affected_count=len(shared_key_allowed),
                affected_resources=shared_key_allowed[:30],
            ))

        if not findings:
            findings.append(Finding(
                id=f"AZURE-STG-001-{subscription_id[:8]}",
                category="Storage & Secrets",
                title=f"Storage Accounts: {len(accounts)} Accounts — No Issues Found",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description="All storage accounts have secure configuration (HTTPS, TLS 1.2+, no public blob).",
                remediation="No action required.",
            ))

        return findings

    except PermissionError:
        return [_skip(f"AZURE-STG-001-{subscription_id[:8]}", "Storage Accounts", "Requires Reader on subscription")]
    except Exception as e:
        return [_skip(f"AZURE-STG-001-{subscription_id[:8]}", "Storage Accounts", str(e))]


async def check_key_vaults(client: ARMClient, subscription_id: str) -> list[Finding]:
    try:
        vaults = await client.get_list(
            f"/subscriptions/{subscription_id}/providers/Microsoft.KeyVault/vaults",
            "2023-07-01",
        )
        if not vaults:
            return []

        no_soft_delete: list[dict] = []
        no_purge_protect: list[dict] = []
        public_access: list[dict] = []

        for v in vaults:
            name = v.get("name", "")
            rg = v.get("id", "").split("/")[4] if v.get("id") else ""
            props = v.get("properties") or {}
            entry = {"name": name, "resourceGroup": rg}

            if not props.get("enableSoftDelete", False):
                no_soft_delete.append(entry)
            if not props.get("enablePurgeProtection", False):
                no_purge_protect.append(entry)

            net_rules = props.get("networkAcls") or {}
            if net_rules.get("defaultAction", "Allow") == "Allow":
                public_access.append(entry)

        findings: list[Finding] = []

        if no_soft_delete:
            findings.append(Finding(
                id=f"AZURE-STG-005-{subscription_id[:8]}",
                category="Storage & Secrets",
                title=f"Key Vault: {len(no_soft_delete)} Vaults Without Soft Delete",
                severity=Severity.HIGH,
                status=FindingStatus.FAIL,
                description=(
                    f"{len(no_soft_delete)} Key Vaults do not have soft delete enabled. "
                    "Deleted secrets, keys, and certificates cannot be recovered."
                ),
                remediation="Enable soft delete on all Key Vaults (retention period ≥ 7 days).",
                affected_count=len(no_soft_delete),
                affected_resources=no_soft_delete[:30],
            ))

        if no_purge_protect:
            findings.append(Finding(
                id=f"AZURE-STG-006-{subscription_id[:8]}",
                category="Storage & Secrets",
                title=f"Key Vault: {len(no_purge_protect)} Vaults Without Purge Protection",
                severity=Severity.HIGH,
                status=FindingStatus.FAIL,
                description=(
                    f"{len(no_purge_protect)} Key Vaults lack purge protection. "
                    "A malicious insider or attacker could permanently destroy all secrets."
                ),
                remediation="Enable purge protection on all Key Vaults.",
                affected_count=len(no_purge_protect),
                affected_resources=no_purge_protect[:30],
            ))

        if public_access:
            findings.append(Finding(
                id=f"AZURE-STG-007-{subscription_id[:8]}",
                category="Storage & Secrets",
                title=f"Key Vault: {len(public_access)} Vaults Accessible from Public Network",
                severity=Severity.MEDIUM,
                status=FindingStatus.WARN,
                description=(
                    f"{len(public_access)} Key Vaults allow access from all networks. "
                    "Restricting network access limits exposure if credentials are compromised."
                ),
                remediation=(
                    "Configure Key Vault network firewall to restrict access to specific VNets "
                    "and trusted service IPs. Set 'defaultAction' to Deny."
                ),
                affected_count=len(public_access),
                affected_resources=public_access[:30],
            ))

        return findings

    except PermissionError:
        return [_skip(f"AZURE-STG-005-{subscription_id[:8]}", "Key Vaults", "Requires Reader on subscription")]
    except Exception as e:
        return [_skip(f"AZURE-STG-005-{subscription_id[:8]}", "Key Vaults", str(e))]


async def run_all(client: ARMClient, subscription_id: str) -> list[Finding]:
    result_groups = await asyncio.gather(
        check_storage_accounts(client, subscription_id),
        check_key_vaults(client, subscription_id),
        return_exceptions=True,
    )
    findings = []
    for rg in result_groups:
        if isinstance(rg, Exception):
            logger.error("Storage check raised: %s", rg)
        elif isinstance(rg, list):
            findings.extend(rg)
    return findings
