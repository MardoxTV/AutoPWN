from __future__ import annotations
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    FAIL = "FAIL"
    PASS = "PASS"
    WARN = "WARN"
    SKIP = "SKIP"


class Finding(BaseModel):
    id: str
    category: str
    title: str
    severity: Severity
    status: FindingStatus
    description: str
    remediation: str
    affected_count: int = 0
    affected_resources: list[dict[str, Any]] = []


class AssessmentSummary(BaseModel):
    tenant_id: str
    tenant_name: str
    assessed_at: str
    total_checks: int
    passed: int
    failed: int
    warnings: int
    skipped: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    subscriptions_assessed: int
    arm_available: bool
    secure_score: Optional[float] = None


class AssessmentResult(BaseModel):
    job_id: str
    summary: AssessmentSummary
    findings: list[Finding]
