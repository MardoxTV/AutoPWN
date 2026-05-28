from __future__ import annotations
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from ..client import GraphClient, PermissionError
from ..models import Finding, FindingStatus, Severity

logger = logging.getLogger("autopwn.azure.checks.identity")


def _skip(check_id: str, title: str, reason: str) -> Finding:
    return Finding(
        id=check_id,
        category="Identity",
        title=title,
        severity=Severity.INFO,
        status=FindingStatus.SKIP,
        description=f"Check skipped: {reason}",
        remediation="Ensure the authenticated account has the required Graph API permissions.",
    )


async def check_security_defaults(client: GraphClient) -> Finding:
    try:
        data = await client.get("/policies/identitySecurityDefaultsEnforcementPolicy")
        if data.get("isEnabled", False):
            return Finding(
                id="AZURE-ID-001",
                category="Identity",
                title="Security Defaults Enabled",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description="Azure Security Defaults are enabled, providing baseline MFA and legacy-auth protections.",
                remediation="No action required. Consider Conditional Access for more granular control.",
            )
        return Finding(
            id="AZURE-ID-001",
            category="Identity",
            title="Security Defaults Disabled",
            severity=Severity.HIGH,
            status=FindingStatus.FAIL,
            description=(
                "Security Defaults are disabled. Without Security Defaults or equivalent "
                "Conditional Access policies, MFA is not enforced and legacy authentication "
                "protocols are not blocked."
            ),
            remediation=(
                "Re-enable Security Defaults in Azure AD > Properties > Manage Security Defaults, "
                "or implement Conditional Access policies covering: MFA for all users, blocking "
                "legacy authentication, and requiring MFA for admins."
            ),
        )
    except PermissionError:
        return _skip("AZURE-ID-001", "Security Defaults", "Requires Policy.Read.All")
    except Exception as e:
        return _skip("AZURE-ID-001", "Security Defaults", str(e))


async def check_mfa_registration(client: GraphClient) -> Finding:
    try:
        users = await client.get_all_pages(
            "/reports/credentialUserRegistrationDetails", max_items=5000
        )
        if not users:
            return _skip("AZURE-ID-002", "MFA Registration Rate", "No data (requires Reports.Read.All)")

        total = len(users)
        no_mfa = [u for u in users if not u.get("isMfaRegistered", False)]
        count = len(no_mfa)
        pct = count / total * 100

        if count == 0:
            return Finding(
                id="AZURE-ID-002",
                category="Identity",
                title="MFA Registration: 100% Enrolled",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description=f"All {total} users have an MFA method registered.",
                remediation="No action required.",
            )

        severity = Severity.CRITICAL if pct > 50 else Severity.HIGH if pct > 20 else Severity.MEDIUM
        return Finding(
            id="AZURE-ID-002",
            category="Identity",
            title=f"Users Without MFA: {count}/{total} ({pct:.0f}%)",
            severity=severity,
            status=FindingStatus.FAIL,
            description=(
                f"{count} of {total} users ({pct:.0f}%) have not registered any MFA method. "
                "Accounts without MFA are trivially compromised by credential stuffing or phishing."
            ),
            remediation=(
                "Enforce MFA registration via a Conditional Access policy targeting all users and "
                "all cloud apps. Use the Azure AD Authentication Methods Activity report to monitor progress."
            ),
            affected_count=count,
            affected_resources=[
                {"displayName": u.get("userDisplayName", ""), "upn": u.get("userPrincipalName", "")}
                for u in no_mfa[:50]
            ],
        )
    except PermissionError:
        return _skip("AZURE-ID-002", "MFA Registration Rate", "Requires Reports.Read.All")
    except Exception as e:
        return _skip("AZURE-ID-002", "MFA Registration Rate", str(e))


async def check_privileged_roles(client: GraphClient) -> Finding:
    HIGH_PRIV = {
        "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
        "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
        "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
        "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
        "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    }
    try:
        assignments = await client.get_all_pages(
            "/roleManagement/directory/roleAssignments?$expand=principal", max_items=2000
        )
        high_priv: list[dict] = []
        role_counts: dict[str, int] = {}
        for a in assignments:
            role_name = HIGH_PRIV.get(a.get("roleDefinitionId", ""))
            if not role_name:
                continue
            principal = a.get("principal") or {}
            high_priv.append({
                "role": role_name,
                "principal": principal.get("displayName", "Unknown"),
                "upn": principal.get("userPrincipalName") or principal.get("appId", ""),
                "type": (principal.get("@odata.type") or "").split(".")[-1],
            })
            role_counts[role_name] = role_counts.get(role_name, 0) + 1

        ga_count = role_counts.get("Global Administrator", 0)
        if not high_priv:
            return Finding(
                id="AZURE-ID-003",
                category="Identity",
                title="Privileged Role Assignments",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description="No high-privilege assignments found (or insufficient permissions to list them).",
                remediation="No action required.",
            )

        severity = Severity.CRITICAL if ga_count > 10 else Severity.HIGH if ga_count > 5 else Severity.MEDIUM
        status = FindingStatus.FAIL if ga_count > 5 else FindingStatus.WARN
        return Finding(
            id="AZURE-ID-003",
            category="Identity",
            title=f"Privileged Roles: {len(high_priv)} Assignments (Global Admins: {ga_count})",
            severity=severity,
            status=status,
            description=(
                f"Found {len(high_priv)} high-privilege role assignments across {len(role_counts)} roles. "
                f"Global Administrators: {ga_count}. Microsoft recommends 2–4 Global Admins with PIM."
            ),
            remediation=(
                "Reduce Global Admin count to 2–5. Migrate privileged assignments to PIM for "
                "just-in-time access. Review all permanent role assignments."
            ),
            affected_count=len(high_priv),
            affected_resources=high_priv[:50],
        )
    except PermissionError:
        return _skip("AZURE-ID-003", "Privileged Role Assignments", "Requires RoleManagement.Read.Directory")
    except Exception as e:
        return _skip("AZURE-ID-003", "Privileged Role Assignments", str(e))


async def check_guest_accounts(client: GraphClient) -> Finding:
    try:
        guests = await client.get_all_pages(
            "/users?$filter=userType eq 'Guest'"
            "&$select=id,displayName,userPrincipalName,createdDateTime",
            max_items=2000,
        )
        count = len(guests)
        if count == 0:
            return Finding(
                id="AZURE-ID-004",
                category="Identity",
                title="No Guest Accounts",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description="No external guest accounts found in the tenant.",
                remediation="No action required.",
            )

        severity = Severity.MEDIUM if count > 50 else Severity.LOW
        return Finding(
            id="AZURE-ID-004",
            category="Identity",
            title=f"Guest Accounts: {count} External Users",
            severity=severity,
            status=FindingStatus.WARN,
            description=(
                f"{count} guest (external) accounts exist. Each extends the trust boundary "
                "to an external identity provider. Stale guests increase attack surface."
            ),
            remediation=(
                "Enable recurring Azure AD Access Reviews for guest accounts. "
                "Remove guests who no longer need access. Restrict guest invitation settings "
                "in Azure AD > External Identities > External collaboration settings."
            ),
            affected_count=count,
            affected_resources=[
                {"displayName": g.get("displayName", ""), "upn": g.get("userPrincipalName", "")}
                for g in guests[:50]
            ],
        )
    except PermissionError:
        return _skip("AZURE-ID-004", "Guest Accounts", "Requires User.Read.All")
    except Exception as e:
        return _skip("AZURE-ID-004", "Guest Accounts", str(e))


async def check_stale_accounts(client: GraphClient) -> Finding:
    try:
        users = await client.get_all_pages(
            "/users?$select=id,displayName,userPrincipalName,accountEnabled,signInActivity"
            "&$filter=accountEnabled eq true and userType eq 'Member'",
            max_items=5000,
        )
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        stale = []
        for u in users:
            activity = u.get("signInActivity") or {}
            last = activity.get("lastSignInDateTime")
            if last:
                try:
                    dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                    if dt < cutoff:
                        stale.append({
                            "displayName": u.get("displayName", ""),
                            "upn": u.get("userPrincipalName", ""),
                            "lastSignIn": last,
                        })
                except ValueError:
                    pass

        if not stale:
            return Finding(
                id="AZURE-ID-005",
                category="Identity",
                title="No Stale Active Accounts",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description="All enabled member accounts signed in within the last 90 days.",
                remediation="No action required. Continue monitoring via Azure AD Access Reviews.",
            )

        return Finding(
            id="AZURE-ID-005",
            category="Identity",
            title=f"Stale Active Accounts: {len(stale)} Inactive 90+ Days",
            severity=Severity.MEDIUM,
            status=FindingStatus.FAIL,
            description=(
                f"{len(stale)} enabled member accounts have not signed in for over 90 days. "
                "Stale accounts may belong to ex-employees or abandoned service accounts."
            ),
            remediation=(
                "Disable accounts inactive for 90+ days. Use Azure AD Access Reviews with "
                "auto-apply to disable stale accounts automatically."
            ),
            affected_count=len(stale),
            affected_resources=stale[:50],
        )
    except PermissionError:
        return _skip("AZURE-ID-005", "Stale Accounts", "Requires User.Read.All and AuditLog.Read.All")
    except Exception as e:
        return _skip("AZURE-ID-005", "Stale Accounts", str(e))


async def check_conditional_access(client: GraphClient) -> Finding:
    try:
        policies = await client.get_all_pages("/policies/conditionalAccessPolicies", max_items=200)
        enabled = [p for p in policies if p.get("state") == "enabled"]

        if not enabled:
            return Finding(
                id="AZURE-ID-006",
                category="Identity",
                title="No Active Conditional Access Policies",
                severity=Severity.HIGH,
                status=FindingStatus.FAIL,
                description=(
                    "No enabled Conditional Access policies found. Without CA policies there is no "
                    "enforcement of MFA, device compliance, or legacy authentication blocking."
                ),
                remediation=(
                    "Create CA policies for: (1) Require MFA for all users on all apps, "
                    "(2) Block legacy authentication protocols, (3) Require MFA for Azure management."
                ),
            )

        issues: list[str] = []

        # Look for a policy that grants MFA or authentication strength
        has_mfa = any(
            "mfa" in str(p.get("grantControls") or {}).lower()
            or "authenticationStrength" in str(p.get("grantControls") or {})
            for p in enabled
        )
        if not has_mfa:
            issues.append("No MFA-enforcement policy detected")

        # Look for a policy that targets legacy auth client app types
        has_legacy_block = any(
            set((p.get("conditions") or {}).get("clientAppTypes") or [])
            & {"exchangeActiveSync", "other"}
            for p in enabled
        )
        if not has_legacy_block:
            issues.append("No legacy authentication block policy detected")

        if not issues:
            return Finding(
                id="AZURE-ID-006",
                category="Identity",
                title=f"Conditional Access: {len(enabled)} Active Policies",
                severity=Severity.INFO,
                status=FindingStatus.PASS,
                description=f"{len(enabled)} CA policies active. MFA enforcement and legacy-auth blocking detected.",
                remediation="Continue reviewing CA policies to ensure all users and apps are covered.",
            )

        return Finding(
            id="AZURE-ID-006",
            category="Identity",
            title=f"Conditional Access Gaps: {', '.join(issues)}",
            severity=Severity.HIGH,
            status=FindingStatus.WARN,
            description=(
                f"{len(enabled)} CA policies are active but critical gaps were found: {'; '.join(issues)}."
            ),
            remediation=(
                "Review Microsoft's CA policy templates at aka.ms/ConditionalAccessTemplates. "
                "Ensure MFA is enforced for all users and legacy authentication is blocked."
            ),
            affected_count=len(issues),
            affected_resources=[{"gap": i} for i in issues],
        )
    except PermissionError:
        return _skip("AZURE-ID-006", "Conditional Access Policies", "Requires Policy.Read.All")
    except Exception as e:
        return _skip("AZURE-ID-006", "Conditional Access Policies", str(e))


async def run_all(client: GraphClient) -> list[Finding]:
    results = await asyncio.gather(
        check_security_defaults(client),
        check_mfa_registration(client),
        check_privileged_roles(client),
        check_guest_accounts(client),
        check_stale_accounts(client),
        check_conditional_access(client),
        return_exceptions=True,
    )
    findings = []
    for r in results:
        if isinstance(r, Exception):
            logger.error("Identity check raised: %s", r)
        else:
            findings.append(r)
    return findings
