import { clsx } from 'clsx'
import { CheckCircle2, XCircle, AlertTriangle, Clock, Download, RefreshCw } from 'lucide-react'
import type { ToolInfo } from '../api/types'
import { installTool } from '../api/client'
import { useQueryClient } from '@tanstack/react-query'

const StatusIcon = ({ status }: { status: ToolInfo['status'] }) => {
  if (status === 'ok')      return <CheckCircle2 size={14} className="text-success" />
  if (status === 'missing') return <XCircle size={14} className="text-danger" />
  if (status === 'outdated') return <AlertTriangle size={14} className="text-warning" />
  return <Clock size={14} className="text-gray-500" />
}

interface Props { name: string; info: ToolInfo }

export default function ToolCard({ name, info }: Props) {
  const qc = useQueryClient()

  const handleInstall = async () => {
    await installTool(name)
    qc.invalidateQueries({ queryKey: ['tools'] })
  }

  return (
    <div className={clsx(
      'flex items-center justify-between p-3 rounded-md border text-sm',
      info.status === 'ok' ? 'border-success/20 bg-success/5' :
      info.status === 'missing' ? 'border-danger/20 bg-danger/5' :
      info.status === 'outdated' ? 'border-warning/20 bg-warning/5' :
      'border-gray-700 bg-gray-900'
    )}>
      <div className="flex items-center gap-2 min-w-0">
        <StatusIcon status={info.status} />
        <div className="min-w-0">
          <p className="font-semibold text-gray-200 truncate">{name}</p>
          <p className="text-xs text-gray-500 truncate">{info.description}</p>
          {info.version && (
            <p className="text-xs text-gray-600">v{info.version}</p>
          )}
          {info.message && (
            <p className="text-xs text-warning mt-0.5">{info.message}</p>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0 ml-3">
        <span className={clsx(
          'text-xs px-2 py-0.5 rounded-full border',
          info.category === 'recon' ? 'border-blue-500/30 text-blue-400' :
          info.category === 'enumeration' ? 'border-purple-500/30 text-purple-400' :
          info.category === 'exploitation' ? 'border-red-500/30 text-red-400' :
          'border-gray-600 text-gray-500'
        )}>
          {info.category}
        </span>

        {info.status === 'missing' && (
          <button
            onClick={handleInstall}
            className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-accent/10 text-accent border border-accent/30 hover:bg-accent/20 transition-colors"
          >
            <Download size={11} /> Install
          </button>
        )}
        {info.status === 'outdated' && (
          <button
            onClick={handleInstall}
            className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-warning/10 text-warning border border-warning/30 hover:bg-warning/20 transition-colors"
          >
            <RefreshCw size={11} /> Update
          </button>
        )}
      </div>
    </div>
  )
}
