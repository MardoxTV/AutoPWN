import { clsx } from 'clsx'
import { Check, Loader2, X, SkipForward } from 'lucide-react'

const PHASES = ['recon', 'enumeration', 'exploitation', 'post_exploitation']
const LABELS: Record<string, string> = {
  recon: 'Recon',
  enumeration: 'Enum',
  exploitation: 'Exploit',
  post_exploitation: 'PostEx',
}

interface Props {
  currentPhase?: string | null
  phaseStatus: Record<string, string>
}

function PhaseIcon({ status }: { status?: string }) {
  if (status === 'completed') return <Check size={12} className="text-success" />
  if (status === 'running')   return <Loader2 size={12} className="text-accent animate-spin" />
  if (status === 'failed')    return <X size={12} className="text-danger" />
  if (status === 'skipped')   return <SkipForward size={12} className="text-gray-500" />
  return <div className="w-3 h-3 rounded-full border border-gray-600" />
}

export default function PhaseProgress({ currentPhase, phaseStatus }: Props) {
  return (
    <div className="flex items-center gap-2">
      {PHASES.map((phase, i) => {
        const status = phaseStatus[phase]
        const isActive = currentPhase === phase
        return (
          <div key={phase} className="flex items-center gap-2">
            <div className={clsx(
              'flex items-center gap-1.5 px-2 py-1 rounded text-xs border',
              isActive ? 'border-accent text-accent bg-accent/10' :
              status === 'completed' ? 'border-success/30 text-success bg-success/5' :
              status === 'failed' ? 'border-danger/30 text-danger bg-danger/5' :
              'border-gray-700 text-gray-500'
            )}>
              <PhaseIcon status={status} />
              {LABELS[phase]}
            </div>
            {i < PHASES.length - 1 && (
              <div className="w-4 h-px bg-gray-700" />
            )}
          </div>
        )
      })}
    </div>
  )
}
