import { useParams, Link } from 'react-router-dom'
import { Terminal, BarChart2, XCircle } from 'lucide-react'
import { useJobSocket } from '../hooks/useJobSocket'
import { useJobStore } from '../store/jobStore'
import { useCancelJob } from '../hooks/useJobs'
import LogTerminal from '../components/LogTerminal'
import PhaseProgress from '../components/PhaseProgress'
import FlagBanner from '../components/FlagBanner'

export default function LiveView() {
  const { jobId } = useParams<{ jobId: string }>()
  const cancelJob = useCancelJob()

  const activeJob    = useJobStore(s => s.activeJob)
  const lines        = useJobStore(s => s.terminalLines)
  const currentPhase = useJobStore(s => s.currentPhase)
  const phaseStatus  = useJobStore(s => s.phaseStatus)
  const recentFlags  = useJobStore(s => s.recentFlags)
  const queuePosition = useJobStore(s => s.queuePosition)

  useJobSocket(jobId ?? null)

  const isRunning = activeJob?.status === 'running' || activeJob?.status === 'created'

  return (
    <div className="p-6 space-y-4 h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Terminal size={20} className="text-accent" />
          <div>
            <h1 className="text-xl font-bold text-gray-100">
              {activeJob?.target_name ?? activeJob?.target_ip ?? 'Attack'}
            </h1>
            <p className="text-xs text-gray-500 font-mono">{jobId}</p>
          </div>
          <span className={`text-xs px-2 py-0.5 rounded-full border font-mono ${
            activeJob?.status === 'completed' ? 'border-success/40 text-success' :
            activeJob?.status === 'failed' ? 'border-danger/40 text-danger' :
            activeJob?.status === 'running' ? 'border-accent/40 text-accent' :
            'border-gray-600 text-gray-400'
          }`}>
            {activeJob?.status ?? 'unknown'}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {jobId && (
            <Link
              to={`/results/${jobId}`}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-sm border border-gray-700 text-gray-400 hover:text-gray-100 hover:border-gray-500 transition-colors"
            >
              <BarChart2 size={14} /> Results
            </Link>
          )}
          {isRunning && jobId && (
            <button
              onClick={() => cancelJob.mutate(jobId)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-sm border border-danger/40 text-danger hover:bg-danger/10 transition-colors"
            >
              <XCircle size={14} /> Cancel
            </button>
          )}
        </div>
      </div>

      {/* Queue position banner */}
      {queuePosition !== null && queuePosition > 0 && (
        <div className="text-sm text-yellow-400 bg-yellow-400/10 border border-yellow-400/30 rounded px-3 py-2 font-mono">
          Queued — position {queuePosition + 1} in line. Waiting for current job to finish…
        </div>
      )}
      {queuePosition === 0 && activeJob?.status === 'created' && (
        <div className="text-sm text-blue-400 bg-blue-400/10 border border-blue-400/30 rounded px-3 py-2 font-mono">
          Next in queue — will start shortly…
        </div>
      )}

      {/* Phase progress */}
      <PhaseProgress currentPhase={currentPhase} phaseStatus={phaseStatus} />

      {/* Flags */}
      {recentFlags.length > 0 && <FlagBanner flags={recentFlags} />}

      {/* Terminal */}
      <div className="flex-1 min-h-0">
        <LogTerminal lines={lines} height="h-full" />
      </div>
    </div>
  )
}
