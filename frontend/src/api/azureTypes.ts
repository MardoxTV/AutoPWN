export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type FindingStatus = 'FAIL' | 'PASS' | 'WARN' | 'SKIP'

export interface Finding {
  id: string
  category: string
  title: string
  severity: Severity
  status: FindingStatus
  description: string
  remediation: string
  affected_count: number
  affected_resources: Record<string, unknown>[]
}

export interface AssessmentSummary {
  tenant_id: string
  tenant_name: string
  assessed_at: string
  total_checks: number
  passed: number
  failed: number
  warnings: number
  skipped: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  subscriptions_assessed: number
  arm_available: boolean
  secure_score: number | null
}

export interface AssessmentResult {
  job_id: string
  summary: AssessmentSummary
  findings: Finding[]
}

export interface AuthStatus {
  status: 'pending' | 'success' | 'error'
  tenant_id: string | null
  user_name: string | null
  arm_available: boolean
  error: string | null
}

export interface JobStatus {
  status: 'queued' | 'running' | 'complete' | 'error'
  progress: number
  phase: string
  error: string | null
}
