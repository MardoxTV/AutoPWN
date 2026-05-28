import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import axios from 'axios'
import {
  Shield, AlertTriangle, CheckCircle, Info, ChevronDown, ChevronRight,
  Loader2, ArrowLeft, XCircle, AlertCircle, SkipForward,
} from 'lucide-react'
import { clsx } from 'clsx'
import type { AssessmentResult, Finding, Severity, FindingStatus, JobStatus } from '../api/azureTypes'

const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: 'bg-danger/15 text-danger border-danger/30',
  HIGH: 'bg-warning/15 text-warning border-warning/30',
  MEDIUM: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-accent/10 text-accent border-accent/20',
  INFO: 'bg-gray-800 text-gray-400 border-gray-700',
}

const STATUS_ICON: Record<FindingStatus, React.ReactNode> = {
  FAIL: <XCircle size={14} className="text-danger" />,
  WARN: <AlertCircle size={14} className="text-warning" />,
  PASS: <CheckCircle size={14} className="text-success" />,
  SKIP: <SkipForward size={14} className="text-gray-500" />,
}

const CATEGORIES = ['All', 'Identity', 'Risk & Threats', 'Network', 'Storage & Secrets', 'Defender & Compliance']

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={clsx('text-xs font-mono px-2 py-0.5 rounded border', SEVERITY_STYLES[severity])}>
      {severity}
    </span>
  )
}

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false)
  const isActionable = finding.status === 'FAIL' || finding.status === 'WARN'

  return (
    <div
      className={clsx(
        'border rounded-lg overflow-hidden transition-colors',
        finding.status === 'PASS' ? 'border-gray-800 opacity-60' :
        finding.status === 'SKIP' ? 'border-gray-800 opacity-40' :
        finding.severity === 'CRITICAL' ? 'border-danger/30' :
        finding.severity === 'HIGH' ? 'border-warning/20' :
        'border-gray-800'
      )}
    >
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-gray-900/50 transition-colors"
        onClick={() => isActionable && setOpen(o => !o)}
      >
        <div className="shrink-0">{STATUS_ICON[finding.status]}</div>
        <div className="flex-1 min-w-0">
          <p className={clsx('text-sm font-medium truncate', finding.status === 'PASS' ? 'text-gray-500' : 'text-gray-200')}>
            {finding.title}
          </p>
          <p className="text-xs text-gray-600 mt-0.5">{finding.category}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <SeverityBadge severity={finding.severity} />
          {isActionable && (
            open ? <ChevronDown size={14} className="text-gray-500" /> : <ChevronRight size={14} className="text-gray-500" />
          )}
        </div>
      </button>

      {open && isActionable && (
        <div className="px-4 pb-4 border-t border-gray-800 pt-3 space-y-3">
          <p className="text-sm text-gray-400 leading-relaxed">{finding.description}</p>

          <div className="bg-gray-900 border border-gray-800 rounded p-3">
            <p className="text-xs font-medium text-accent mb-1">Remediation</p>
            <p className="text-xs text-gray-400 leading-relaxed">{finding.remediation}</p>
          </div>

          {finding.affected_resources.length > 0 && (
            <div>
              <p className="text-xs font-medium text-gray-500 mb-2">
                Affected Resources ({finding.affected_count})
              </p>
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {finding.affected_resources.map((r, i) => (
                  <div key={i} className="text-xs font-mono text-gray-400 bg-gray-900 px-3 py-1.5 rounded border border-gray-800">
                    {Object.entries(r)
                      .filter(([, v]) => v !== null && v !== '' && v !== undefined)
                      .map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`)
                      .join(' · ')}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className={clsx('rounded-lg border p-4', color)}>
      <p className="text-2xl font-bold">{value}</p>
      <p className="text-xs mt-0.5 opacity-70">{label}</p>
    </div>
  )
}

export default function AzureResults() {
  const { jobId } = useParams<{ jobId: string }>()
  const navigate = useNavigate()
  const [jobStatus, setJobStatus] = useState<JobStatus | null>(null)
  const [result, setResult] = useState<AssessmentResult | null>(null)
  const [category, setCategory] = useState('All')
  const [showPassSkip, setShowPassSkip] = useState(false)

  useEffect(() => {
    if (!jobId) return

    const poll = setInterval(async () => {
      try {
        const status = await axios.get<JobStatus>(`/api/azure/assess/${jobId}/status`)
        setJobStatus(status.data)
        if (status.data.status === 'complete') {
          clearInterval(poll)
          const res = await axios.get<AssessmentResult>(`/api/azure/assess/${jobId}/results`)
          setResult(res.data)
        } else if (status.data.status === 'error') {
          clearInterval(poll)
        }
      } catch {
        // keep polling on network blip
      }
    }, 2000)

    return () => clearInterval(poll)
  }, [jobId])

  // --- Still running ---
  if (!result) {
    return (
      <div className="p-8 max-w-xl mx-auto">
        <button
          onClick={() => navigate('/azure')}
          className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-300 mb-6 transition-colors"
        >
          <ArrowLeft size={14} /> Back
        </button>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-8">
          <div className="flex items-center gap-3 mb-6">
            <Loader2 size={20} className="animate-spin text-accent" />
            <div>
              <p className="text-sm font-medium text-gray-200">Assessment Running</p>
              <p className="text-xs text-gray-500">{jobStatus?.phase || 'Initialising…'}</p>
            </div>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-2">
            <div
              className="bg-accent h-2 rounded-full transition-all duration-500"
              style={{ width: `${jobStatus?.progress || 0}%` }}
            />
          </div>
          <p className="text-xs text-gray-600 mt-2 text-right">{jobStatus?.progress || 0}%</p>

          {jobStatus?.status === 'error' && (
            <div className="mt-4 bg-danger/10 border border-danger/30 rounded p-3 text-sm text-danger">
              Assessment failed: {jobStatus.error}
            </div>
          )}
        </div>
      </div>
    )
  }

  const { summary, findings } = result
  const filtered = findings.filter(f => {
    if (category !== 'All' && f.category !== category) return false
    if (!showPassSkip && (f.status === 'PASS' || f.status === 'SKIP')) return false
    return true
  })

  const sortOrder: Record<FindingStatus, number> = { FAIL: 0, WARN: 1, SKIP: 3, PASS: 4 }
  const sevOrder: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }
  filtered.sort((a, b) => {
    const sd = sortOrder[a.status] - sortOrder[b.status]
    if (sd !== 0) return sd
    return sevOrder[a.severity] - sevOrder[b.severity]
  })

  return (
    <div className="p-6">
      <button
        onClick={() => navigate('/azure')}
        className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-300 mb-5 transition-colors"
      >
        <ArrowLeft size={14} /> New Assessment
      </button>

      {/* Header */}
      <div className="mb-6">
        <h1 className="text-xl font-semibold text-gray-100">{summary.tenant_name}</h1>
        <p className="text-sm text-gray-500 mt-0.5">
          Tenant: <code className="font-mono text-xs text-gray-400">{summary.tenant_id}</code>
          {' · '}
          Assessed {new Date(summary.assessed_at).toLocaleString()}
          {' · '}
          {summary.subscriptions_assessed} subscription{summary.subscriptions_assessed !== 1 ? 's' : ''}
          {!summary.arm_available && (
            <span className="ml-2 text-warning text-xs">(ARM unavailable — network/storage checks skipped)</span>
          )}
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        <StatCard label="Critical" value={summary.critical_count} color="border-danger/30 bg-danger/5 text-danger" />
        <StatCard label="High" value={summary.high_count} color="border-warning/30 bg-warning/5 text-warning" />
        <StatCard label="Medium" value={summary.medium_count} color="border-yellow-500/30 bg-yellow-500/5 text-yellow-400" />
        <StatCard label="Low" value={summary.low_count} color="border-accent/20 bg-accent/5 text-accent" />
      </div>

      {/* Secondary stats */}
      <div className="flex flex-wrap gap-4 text-sm text-gray-500 mb-6">
        <span><span className="text-success">{summary.passed}</span> passed</span>
        <span><span className="text-danger">{summary.failed}</span> failed</span>
        <span><span className="text-warning">{summary.warnings}</span> warnings</span>
        <span><span className="text-gray-600">{summary.skipped}</span> skipped</span>
        {summary.secure_score !== null && (
          <span>Secure score: <span className={clsx(
            'font-semibold',
            summary.secure_score >= 70 ? 'text-success' : summary.secure_score >= 50 ? 'text-warning' : 'text-danger'
          )}>{summary.secure_score?.toFixed(0)}%</span></span>
        )}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 mb-4 flex-wrap">
        <div className="flex gap-1 flex-wrap">
          {CATEGORIES.map(cat => (
            <button
              key={cat}
              onClick={() => setCategory(cat)}
              className={clsx(
                'px-3 py-1 rounded text-xs transition-colors',
                category === cat
                  ? 'bg-accent/15 text-accent border border-accent/30'
                  : 'text-gray-500 hover:text-gray-300 border border-gray-800 hover:border-gray-700'
              )}
            >
              {cat}
            </button>
          ))}
        </div>
        <button
          onClick={() => setShowPassSkip(s => !s)}
          className={clsx(
            'ml-auto px-3 py-1 rounded text-xs border transition-colors',
            showPassSkip
              ? 'bg-gray-800 text-gray-300 border-gray-700'
              : 'text-gray-600 border-gray-800 hover:border-gray-700 hover:text-gray-400'
          )}
        >
          {showPassSkip ? 'Hide' : 'Show'} Passed / Skipped
        </button>
      </div>

      {/* Finding count */}
      <p className="text-xs text-gray-600 mb-3">
        Showing {filtered.length} finding{filtered.length !== 1 ? 's' : ''}
      </p>

      {/* Findings list */}
      <div className="space-y-2">
        {filtered.length === 0 ? (
          <div className="text-center py-12 text-gray-600">
            <Info size={24} className="mx-auto mb-2 opacity-40" />
            <p className="text-sm">No findings match the current filter.</p>
          </div>
        ) : (
          filtered.map(f => <FindingCard key={f.id} finding={f} />)
        )}
      </div>
    </div>
  )
}
