import { Trophy } from 'lucide-react'
import type { Flag } from '../api/types'

interface Props { flags: Flag[] }

export default function FlagBanner({ flags }: Props) {
  if (!flags.length) return null
  return (
    <div className="space-y-2">
      {flags.map(flag => (
        <div
          key={flag.id}
          className="flex items-center gap-3 px-4 py-3 rounded-lg border border-yellow-500/40 bg-yellow-500/10 text-yellow-300"
        >
          <Trophy size={18} className="shrink-0" />
          <div>
            <p className="text-xs text-yellow-500 uppercase tracking-wider font-bold">
              {flag.flag_type === 'user' ? 'User Flag' : flag.flag_type === 'root' ? 'Root Flag' : 'Flag Found'}
            </p>
            <code className="text-sm font-mono">{flag.value}</code>
            {flag.path && <p className="text-xs text-yellow-600 mt-0.5">{flag.path}</p>}
          </div>
        </div>
      ))}
    </div>
  )
}
