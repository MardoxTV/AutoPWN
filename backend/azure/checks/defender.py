from __future__ import annotations
import asyncio
import logging

from ..client import ARMClient, PermissionError
from ..models import Finding, FindingStatus, Severity

logger = logging.getLogger("autopwn.azure.checks.defender")


def _skip(check_id: str, title: str, reason: str) -> Finding:
    return Finding(
        id=check_id,
        category="Defender & Compliance",
        title=title,
        severity=Severity.INFO,
        status=FindingStatus.SKIP,
        description=f"Check skipped: {reason}",
        remediation="Ensure the authenticated account has Security Reader on the subscription.",
    )


async def check_secure_score(client: ARMClient, subscription_id: str) -> Finding:
    try:
        data = await client.get(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Security/secureScores/ascScore",
            "2020-01-01",
        )
        props = data.get("properties") or {}
        score = props.get("score", {})
        current = score.get("current", 0)
        max_score = score.get("max", 100)
        pct = (current / max_score * 100) if max_score else 0

        if pct >= 70:
            return Finding(
                id=f"AZURE-DEF-001-{subscription_id[:8]}",
                category="Defender & Compliance",
                title=f"Secure Score: {pct:.0f}% ({current:.0f}/{max_score:.0f})",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description=f"Defender for Cloud secure score is {pct:.0f}%. Above the 70% good-standing threshold.",
                remediation="Continue implementing Defender recommendations to raise the score further.",
            )

        severity = Severity.CRITICAL if pct < 30 else Severity.HIGH if pct < 50 else Severity.MEDIUM
        return Finding(
            id=f"AZURE-DEF-001-{subscription_id[:8]}",
            category="Defender & Compliance",
            title=f"Low Secure Score: {pct:.0f}% ({current:.0f}/{max_score:.0f})",
            severity=severity,
            status=FindingStatus.FAIL,
            description=(
                f"Defender for Cloud secure score is {pct:.0f}%, indicating significant security "
                "gaps. Scores below 50% suggest many high-impact recommendations are unaddressed."
            ),
            remediation=(
                "Review Defender for Cloud > Recommendations sorted by Score Impact. "
                "Prioritise 'Quick fixes' and high-impact recommendations."
            ),
        )
    except PermissionError:
        return _skip(f"AZURE-DEF-001-{subscription_id[:8]}", "Secure Score", "Requires Security Reader")
    except Exception as e:
        return _skip(f"AZURE-DEF-001-{subscription_id[:8]}", "Secure Score", str(e))


async def check_defender_recommendations(client: ARMClient, subscription_id: str) -> Finding:
    try:
        assessments = await client.get_list(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Security/assessments",
            "2021-06-01",
        )
        unhealthy = [
            a for a in assessments
            if (a.get("properties") or {}).get("status", {}).get("code") == "Unhealthy"
        ]
        if not unhealthy:
            return Finding(
                id=f"AZURE-DEF-002-{subscription_id[:8]}",
                category="Defender & Compliance",
                title="Defender Recommendations: All Healthy",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description="No unhealthy Defender for Cloud assessments found.",
                remediation="No action required.",
            )

        high_sev = [
            a for a in unhealthy
            if (a.get("properties") or {}).get("metadata", {}).get("severity") in ("High", "Critical")
        ]

        affected = [
            {
                "name": (a.get("properties") or {}).get("displayName", a.get("name", "")),
                "severity": (a.get("properties") or {}).get("metadata", {}).get("severity", ""),
                "description": (a.get("properties") or {}).get("metadata", {}).get("description", "")[:100],
            }
            for a in high_sev[:30]
        ]

        return Finding(
            id=f"AZURE-DEF-002-{subscription_id[:8]}",
            category="Defender & Compliance",
            title=f"Defender Recommendations: {len(unhealthy)} Open ({len(high_sev)} High/Critical)",
            severity=Severity.HIGH if high_sev else Severity.MEDIUM,
            status=FindingStatus.FAIL if high_sev else FindingStatus.WARN,
            description=(
                f"{len(unhealthy)} open Defender for Cloud recommendations, "
                f"of which {len(high_sev)} are High or Critical severity."
            ),
            remediation=(
                "Navigate to Defender for Cloud > Recommendations. "
                "Sort by severity and address High/Critical items first. "
                "Use Quick Fix where available for rapid remediation."
            ),
            affected_count=len(unhealthy),
            affected_resources=affected,
        )
    except PermissionError:
        return _skip(f"AZURE-DEF-002-{subscription_id[:8]}", "Defender Recommendations", "Requires Security Reader")
    except Exception as e:
        return _skip(f"AZURE-DEF-002-{subscription_id[:8]}", "Defender Recommendations", str(e))


async def check_defender_plans(client: ARMClient, subscription_id: str) -> Finding:
    """Check whether Defender for Cloud plans are enabled."""
    try:
        data = await client.get(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Security/pricings",
            "2024-01-01",
        )
        pricings = data.get("value", [])
        off_plans = [
            p.get("name", "") for p in pricings
            if (p.get("properties") or {}).get("pricingTier", "Free") == "Free"
        ]

        if not off_plans:
            return Finding(
                id=f"AZURE-DEF-003-{subscription_id[:8]}",
                category="Defender & Compliance",
                title="Defender for Cloud: All Plans Enabled",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description="All Defender for Cloud plans are on the Standard (paid) tier.",
                remediation="No action required.",
            )

        key_plans = {"VirtualMachines", "StorageAccounts", "SqlServers", "AppServices", "KeyVaults"}
        missing_key = [p for p in off_plans if p in key_plans]
        severity = Severity.HIGH if missing_key else Severity.MEDIUM

        return Finding(
            id=f"AZURE-DEF-003-{subscription_id[:8]}",
            category="Defender & Compliance",
            title=f"Defender Plans Disabled: {len(off_plans)} on Free Tier",
            severity=severity,
            status=FindingStatus.WARN,
            description=(
                f"{len(off_plans)} Defender for Cloud plans are on the free tier and lack advanced "
                f"threat protection. Key plans disabled: {missing_key or off_plans[:5]}"
            ),
            remediation=(
                "Enable Defender for Cloud Standard tier for critical workload types: "
                "VMs, Storage, SQL Servers, App Services, Key Vaults, and Containers."
            ),
            affected_count=len(off_plans),
            affected_resources=[{"plan": p} for p in off_plans],
        )
    except PermissionError:
        return _skip(f"AZURE-DEF-003-{subscription_id[:8]}", "Defender Plans", "Requires Security Reader")
    except Exception as e:
        return _skip(f"AZURE-DEF-003-{subscription_id[:8]}", "Defender Plans", str(e))


async def run_all(client: ARMClient, subscription_id: str) -> list[Finding]:
    results = await asyncio.gather(
        check_secure_score(client, subscription_id),
        check_defender_recommendations(client, subscription_id),
        check_defender_plans(client, subscription_id),
        return_exceptions=True,
    )
    findings = []
    for r in results:
        if isinstance(r, Exception):
            logger.error("Defender check raised: %s", r)
        else:
            findings.append(r)
    return findings
