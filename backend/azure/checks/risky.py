from __future__ import annotations
import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from ..client import GraphClient, PermissionError
from ..models import Finding, FindingStatus, Severity

logger = logging.getLogger("autopwn.azure.checks.risky")

LEGACY_AUTH_CLIENTS = {
    "exchangeActiveSync", "other",
    "pop", "imap", "smtp", "mapi",
}


def _skip(check_id: str, title: str, reason: str) -> Finding:
    return Finding(
        id=check_id,
        category="Risk & Threats",
        title=title,
        severity=Severity.INFO,
        status=FindingStatus.SKIP,
        description=f"Check skipped: {reason}",
        remediation="Requires Entra ID P2 license and/or AuditLog.Read.All permission.",
    )


async def check_risky_users(client: GraphClient) -> Finding:
    """Requires Entra P2 + IdentityRiskyUser.Read.All."""
    try:
        beta = client.beta_view()
        data = await beta.get_all_pages(
            "/identityProtection/riskyUsers?$filter=riskState eq 'atRisk' or riskState eq 'confirmedCompromised'",
            max_items=500,
        )
        if not data:
            return Finding(
                id="AZURE-RISK-001",
                category="Risk & Threats",
                title="No Active Risky Users",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description="Identity Protection reports no users currently flagged as at-risk or compromised.",
                remediation="No action required. Continue monitoring Identity Protection alerts.",
            )

        compromised = [u for u in data if u.get("riskState") == "confirmedCompromised"]
        at_risk = [u for u in data if u.get("riskState") == "atRisk"]

        severity = Severity.CRITICAL if compromised else Severity.HIGH
        affected = [
            {
                "displayName": u.get("userDisplayName", ""),
                "upn": u.get("userPrincipalName", ""),
                "riskState": u.get("riskState", ""),
                "riskLevel": u.get("riskLevel", ""),
                "riskDetail": u.get("riskDetail", ""),
            }
            for u in data[:50]
        ]
        return Finding(
            id="AZURE-RISK-001",
            category="Risk & Threats",
            title=f"Risky Users: {len(compromised)} Compromised, {len(at_risk)} At Risk",
            severity=severity,
            status=FindingStatus.FAIL,
            description=(
                f"Identity Protection has flagged {len(data)} users: "
                f"{len(compromised)} confirmed compromised, {len(at_risk)} at risk. "
                "These accounts may have had credentials stolen or are exhibiting suspicious behaviour."
            ),
            remediation=(
                "For confirmed compromised: reset credentials immediately, revoke sessions, "
                "investigate activity. For at-risk: force MFA re-registration and review sign-in logs. "
                "Use Identity Protection's Remediate workflow."
            ),
            affected_count=len(data),
            affected_resources=affected,
        )
    except PermissionError:
        return _skip("AZURE-RISK-001", "Risky Users", "Requires Entra P2 + IdentityRiskyUser.Read.All")
    except Exception as e:
        return _skip("AZURE-RISK-001", "Risky Users", str(e))


async def check_risk_detections(client: GraphClient) -> Finding:
    """Recent risk detections (Entra P2)."""
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        data = await client.get_all_pages(
            f"/identityProtection/riskDetections?$filter=detectedDateTime ge {since}&$orderby=detectedDateTime desc",
            max_items=200,
        )
        if not data:
            return Finding(
                id="AZURE-RISK-002",
                category="Risk & Threats",
                title="No Risk Detections (Last 7 Days)",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description="No Identity Protection risk detections in the last 7 days.",
                remediation="No action required.",
            )

        high_risk = [d for d in data if d.get("riskLevel") in ("high", "medium")]
        by_type: dict[str, int] = defaultdict(int)
        for d in data:
            by_type[d.get("riskEventType", "unknown")] += 1

        top_types = sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:5]
        summary = ", ".join(f"{t} ({c})" for t, c in top_types)

        return Finding(
            id="AZURE-RISK-002",
            category="Risk & Threats",
            title=f"Risk Detections (7d): {len(data)} Events ({len(high_risk)} High/Medium)",
            severity=Severity.HIGH if high_risk else Severity.MEDIUM,
            status=FindingStatus.FAIL if high_risk else FindingStatus.WARN,
            description=(
                f"{len(data)} risk detections in the last 7 days. "
                f"High/medium severity: {len(high_risk)}. "
                f"Top event types: {summary}."
            ),
            remediation=(
                "Investigate high-severity detections in Identity Protection > Risk Detections. "
                "Dismiss false positives and remediate genuine threats."
            ),
            affected_count=len(data),
            affected_resources=[
                {
                    "user": d.get("userDisplayName", ""),
                    "type": d.get("riskEventType", ""),
                    "level": d.get("riskLevel", ""),
                    "detectedAt": d.get("detectedDateTime", ""),
                    "ip": d.get("ipAddress", ""),
                }
                for d in high_risk[:30]
            ],
        )
    except PermissionError:
        return _skip("AZURE-RISK-002", "Risk Detections", "Requires Entra P2 + IdentityRiskEvent.Read.All")
    except Exception as e:
        return _skip("AZURE-RISK-002", "Risk Detections", str(e))


async def check_password_spray(client: GraphClient) -> Finding:
    """Detect password spray patterns in sign-in logs."""
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # errorCode != 0 means failure
        failures = await client.get_all_pages(
            "/auditLogs/signIns"
            f"?$filter=createdDateTime ge {since} and status/errorCode ne 0"
            "&$select=ipAddress,userPrincipalName,createdDateTime,status,clientAppUsed",
            max_items=2000,
        )
        if not failures:
            return Finding(
                id="AZURE-RISK-003",
                category="Risk & Threats",
                title="No Failed Sign-ins (Last 7 Days)",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description="No failed authentication attempts found in the last 7 days.",
                remediation="No action required.",
            )

        # Group failures by IP → set of UPNs
        ip_to_upns: dict[str, set[str]] = defaultdict(set)
        ip_to_count: dict[str, int] = defaultdict(int)
        for f in failures:
            ip = f.get("ipAddress", "unknown")
            upn = f.get("userPrincipalName", "unknown")
            if ip and ip != "unknown":
                ip_to_upns[ip].add(upn)
                ip_to_count[ip] += 1

        # Password spray: 1 IP targeting 5+ distinct accounts
        spray_ips = {
            ip: {"unique_targets": len(upns), "attempts": ip_to_count[ip], "sample_targets": list(upns)[:5]}
            for ip, upns in ip_to_upns.items()
            if len(upns) >= 5
        }

        # Brute force: 1 IP with 20+ failures against the same account
        brute_candidates: list[dict] = []
        upn_ip: dict[tuple[str, str], int] = defaultdict(int)
        for f in failures:
            upn_ip[(f.get("userPrincipalName", ""), f.get("ipAddress", ""))] += 1
        for (upn, ip), cnt in upn_ip.items():
            if cnt >= 20:
                brute_candidates.append({"upn": upn, "ip": ip, "attempts": cnt})

        total_failures = len(failures)
        if not spray_ips and not brute_candidates:
            return Finding(
                id="AZURE-RISK-003",
                category="Risk & Threats",
                title=f"No Attack Patterns Detected ({total_failures} Failures in 7d)",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description=(
                    f"{total_failures} failed sign-ins in the last 7 days. "
                    "No password spray or brute force patterns detected."
                ),
                remediation="No action required. Continue monitoring sign-in logs.",
            )

        resources: list[dict] = [
            {"type": "spray", "ip": ip, **info}
            for ip, info in list(spray_ips.items())[:20]
        ] + [
            {"type": "brute_force", **b}
            for b in brute_candidates[:10]
        ]

        return Finding(
            id="AZURE-RISK-003",
            category="Risk & Threats",
            title=(
                f"Attack Patterns Detected: {len(spray_ips)} Spray IPs, "
                f"{len(brute_candidates)} Brute-Force Targets"
            ),
            severity=Severity.CRITICAL if spray_ips else Severity.HIGH,
            status=FindingStatus.FAIL,
            description=(
                f"Sign-in log analysis ({total_failures} failures over 7 days): "
                f"{len(spray_ips)} IP addresses show password spray patterns (targeting 5+ accounts). "
                f"{len(brute_candidates)} accounts targeted by brute force (20+ failures from 1 IP)."
            ),
            remediation=(
                "Block offending IPs in Conditional Access Named Locations or Azure Firewall. "
                "Force password resets for targeted accounts. Enable Smart Lockout "
                "(Azure AD > Authentication Methods > Password Protection)."
            ),
            affected_count=len(spray_ips) + len(brute_candidates),
            affected_resources=resources,
        )
    except PermissionError:
        return _skip("AZURE-RISK-003", "Password Spray Detection", "Requires AuditLog.Read.All")
    except Exception as e:
        return _skip("AZURE-RISK-003", "Password Spray Detection", str(e))


async def check_legacy_auth_signins(client: GraphClient) -> Finding:
    """Detect active use of legacy authentication protocols."""
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        sign_ins = await client.get_all_pages(
            "/auditLogs/signIns"
            f"?$filter=createdDateTime ge {since} and clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients'"
            "&$select=userPrincipalName,clientAppUsed,ipAddress,createdDateTime,status",
            max_items=1000,
        )

        legacy = [
            s for s in sign_ins
            if s.get("clientAppUsed", "").lower() in {
                "exchange activesync", "other clients", "other clients; imap",
                "other clients; smtp", "other clients; pop3", "other clients; mapi",
                "authenticated smtp", "imap4", "pop3", "mapi over http",
            }
        ]

        successful_legacy = [s for s in legacy if (s.get("status") or {}).get("errorCode", 1) == 0]

        if not legacy:
            return Finding(
                id="AZURE-RISK-004",
                category="Risk & Threats",
                title="No Legacy Authentication Sign-ins",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description="No legacy authentication protocol usage detected in the last 7 days.",
                remediation="No action required. Ensure legacy auth is blocked via Conditional Access.",
            )

        by_client: dict[str, int] = defaultdict(int)
        for s in legacy:
            by_client[s.get("clientAppUsed", "unknown")] += 1

        return Finding(
            id="AZURE-RISK-004",
            category="Risk & Threats",
            title=f"Legacy Auth Sign-ins: {len(legacy)} ({len(successful_legacy)} Successful)",
            severity=Severity.HIGH if successful_legacy else Severity.MEDIUM,
            status=FindingStatus.FAIL,
            description=(
                f"{len(legacy)} legacy auth sign-ins in the last 7 days "
                f"({len(successful_legacy)} succeeded). Legacy protocols like IMAP/POP3/SMTP "
                "cannot enforce MFA and are a primary vector for credential spray attacks. "
                f"Client breakdown: {dict(list(by_client.items())[:5])}"
            ),
            remediation=(
                "Block legacy authentication via Conditional Access: create a policy targeting "
                "'Exchange ActiveSync clients' and 'Other clients', apply to all users, and set "
                "Grant to Block. Verify no critical line-of-business apps depend on legacy auth first."
            ),
            affected_count=len(legacy),
            affected_resources=[
                {
                    "upn": s.get("userPrincipalName", ""),
                    "client": s.get("clientAppUsed", ""),
                    "ip": s.get("ipAddress", ""),
                    "success": (s.get("status") or {}).get("errorCode", 1) == 0,
                }
                for s in successful_legacy[:30] or legacy[:30]
            ],
        )
    except PermissionError:
        return _skip("AZURE-RISK-004", "Legacy Auth Sign-ins", "Requires AuditLog.Read.All")
    except Exception as e:
        return _skip("AZURE-RISK-004", "Legacy Auth Sign-ins", str(e))


async def check_admin_signins(client: GraphClient) -> Finding:
    """Check for admin accounts signing in from unusual or anonymous IPs."""
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Get current global admin UPNs to filter sign-in logs
        admins_data = await client.get_all_pages(
            "/roleManagement/directory/roleAssignments"
            "?$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'"
            "&$expand=principal",
            max_items=100,
        )
        admin_upns = {
            (a.get("principal") or {}).get("userPrincipalName", "")
            for a in admins_data
            if (a.get("principal") or {}).get("userPrincipalName")
        }

        if not admin_upns:
            return _skip("AZURE-RISK-005", "Admin Sign-in Analysis", "Could not enumerate Global Admin accounts")

        # Get sign-ins for each admin (limited to 5 admins to avoid rate limits)
        suspicious: list[dict] = []
        for upn in list(admin_upns)[:5]:
            try:
                sign_ins = await client.get_all_pages(
                    f"/auditLogs/signIns?$filter=createdDateTime ge {since} and userPrincipalName eq '{upn}'"
                    "&$select=userPrincipalName,ipAddress,location,riskLevelDuringSignIn,riskState,createdDateTime,status",
                    max_items=50,
                )
                for s in sign_ins:
                    risk = s.get("riskLevelDuringSignIn", "none")
                    if risk not in ("none", "hidden", "notSet", None):
                        suspicious.append({
                            "upn": upn,
                            "ip": s.get("ipAddress", ""),
                            "riskLevel": risk,
                            "location": s.get("location", {}),
                            "time": s.get("createdDateTime", ""),
                        })
            except Exception:
                pass

        if not suspicious:
            return Finding(
                id="AZURE-RISK-005",
                category="Risk & Threats",
                title="Admin Sign-ins: No Risky Events",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description=f"Checked {len(admin_upns)} Global Admin accounts. No risky sign-ins detected.",
                remediation="No action required.",
            )

        return Finding(
            id="AZURE-RISK-005",
            category="Risk & Threats",
            title=f"Risky Admin Sign-ins: {len(suspicious)} Events",
            severity=Severity.CRITICAL,
            status=FindingStatus.FAIL,
            description=(
                f"{len(suspicious)} risky sign-in events detected for Global Administrator accounts. "
                "Admin accounts signing in under risk conditions are a critical threat indicator."
            ),
            remediation=(
                "Investigate each risky admin sign-in immediately. Force credential reset and "
                "MFA re-registration for affected admins. Enforce Privileged Access Workstations (PAWs) "
                "for admin sign-ins via Conditional Access."
            ),
            affected_count=len(suspicious),
            affected_resources=suspicious[:30],
        )
    except PermissionError:
        return _skip("AZURE-RISK-005", "Admin Sign-in Analysis", "Requires AuditLog.Read.All + RoleManagement.Read.Directory")
    except Exception as e:
        return _skip("AZURE-RISK-005", "Admin Sign-in Analysis", str(e))


async def run_all(client: GraphClient) -> list[Finding]:
    results = await asyncio.gather(
        check_risky_users(client),
        check_risk_detections(client),
        check_password_spray(client),
        check_legacy_auth_signins(client),
        check_admin_signins(client),
        return_exceptions=True,
    )
    findings = []
    for r in results:
        if isinstance(r, Exception):
            logger.error("Risky check raised: %s", r)
        else:
            findings.append(r)
    return findings
