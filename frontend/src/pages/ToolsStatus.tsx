import { RefreshCw, Wifi, WifiOff, Shield } from 'lucide-react'
import { useToolsStatus } from '../hooks/useJobs'
import { checkAllTools } from '../api/client'
import ToolCard from '../components/ToolCard'
import { useQueryClient } from '@tanstack/react-query'

export default function ToolsStatus() {
  const { data, isLoading } = useToolsStatus()
  const qc = useQueryClient()

  const handleRecheck = async () => {
    await checkAllTools()
    qc.invalidateQueries({ queryKey: ['tools'] })
  }

  const tools = data?.tools ?? {}
  const pip = data?.pip_packages ?? {}
  const network = data?.network ?? {}

  const counts = {
    ok: Object.values(tools).filter(t => t.status === 'ok').length,
    missing: Object.values(tools).filter(t => t.status === 'missing').length,
    outdated: Object.values(tools).filter(t => t.status === 'outdated').length,
  }

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield size={20} className="text-accent" />
          <h1 className="text-2xl font-bold text-gray-100">Tools Status</h1>
        </div>
        <button
          onClick={handleRecheck}
          className="flex items-center gap-2 px-3 py-1.5 rounded border border-gray-700 text-gray-400 hover:text-gray-100 text-sm transition-colors"
        >
          <RefreshCw size={14} /> Re-check All
        </button>
      </div>

      {/* Summary */}
      <div className="flex gap-4">
        {[
          { label: 'OK', count: counts.ok, color: 'text-success' },
          { label: 'Missing', count: counts.missing, color: 'text-danger' },
          { label: 'Outdated', count: counts.outdated, color: 'text-warning' },
        ].map(({ label, count, color }) => (
          <div key={label} className="px-4 py-3 rounded-lg border border-gray-800 bg-gray-900">
            <p className={`text-2xl font-bold ${color}`}>{count}</p>
            <p className="text-xs text-gray-500">{label}</p>
          </div>
        ))}
      </div>

      {/* Network prerequisite */}
      <section>
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Network</h2>
        <div className="flex items-center gap-2 p-3 rounded border border-gray-800 bg-gray-900 text-sm">
          {network['tun0'] ? (
            <><Wifi size={14} className="text-success" /><span className="text-success">tun0 (VPN) is up</span></>
          ) : (
            <><WifiOff size={14} className="text-danger" /><span className="text-danger">tun0 (VPN) not detected — connect to HTB VPN first</span></>
          )}
        </div>
      </section>

      {/* Tools by category */}
      {isLoading ? (
        <p className="text-gray-500 text-sm">Running dependency check...</p>
      ) : (
        <>
          {(['recon', 'enumeration', 'exploitation', 'post_exploitation', 'python'] as const).map(cat => {
            const catTools = Object.entries(tools).filter(([, t]) => t.category === cat)
            const catPip   = cat === 'python' ? Object.entries(pip) : []
            const allItems = [...catTools, ...catPip]
            if (!allItems.length) return null
            return (
              <section key={cat}>
                <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 capitalize">
                  {cat.replace('_', ' ')}
                </h2>
                <div className="space-y-2">
                  {allItems.map(([name, info]) => (
                    <ToolCard key={name} name={name} info={info} />
                  ))}
                </div>
              </section>
            )
          })}
        </>
      )}
    </div>
  )
}
