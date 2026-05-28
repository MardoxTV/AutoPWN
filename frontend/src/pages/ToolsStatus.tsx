import { useState, useRef, useEffect } from 'react'
import { RefreshCw, Wifi, WifiOff, Shield, Download, X } from 'lucide-react'
import { useToolsStatus } from '../hooks/useJobs'
import { checkAllTools, installAllMissing, API_TOKEN } from '../api/client'
import ToolCard from '../components/ToolCard'
import { useQueryClient } from '@tanstack/react-query'

export default function ToolsStatus() {
  const { data, isLoading } = useToolsStatus()
  const qc = useQueryClient()
  const [installing, setInstalling] = useState(false)
  const [logs, setLogs] = useState<string[]>([])
  const [showPanel, setShowPanel] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const logEndRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  useEffect(() => () => { wsRef.current?.close() }, [])

  const handleRecheck = async () => {
    await checkAllTools()
    qc.invalidateQueries({ queryKey: ['tools'] })
  }

  const handleInstallAll = async () => {
    setLogs([])
    setShowPanel(true)
    setInstalling(true)

    // Kick off the background install via REST
    const res = await installAllMissing()
    if (res.count === 0) {
      setLogs(['No missing tools — nothing to install.'])
      setInstalling(false)
      return
    }

    // Open WebSocket to stream live output
    const tokenParam = API_TOKEN ? `?token=${encodeURIComponent(API_TOKEN)}` : ''
    const wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/tools/_all/install${tokenParam}`
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.type === 'log') {
          setLogs(prev => [...prev, msg.message])
        } else if (msg.type === 'done') {
          setInstalling(false)
          qc.invalidateQueries({ queryKey: ['tools'] })
        }
      } catch {
        // ignore malformed messages
      }
    }
    ws.onerror = () => {
      setLogs(prev => [...prev, '[ws error]'])
      setInstalling(false)
    }
    ws.onclose = () => {
      setInstalling(false)
    }
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
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <Shield size={20} className="text-accent" />
          <h1 className="text-2xl font-bold text-gray-100">Tools Status</h1>
        </div>
        <div className="flex items-center gap-2">
          {counts.missing > 0 && (
            <button
              onClick={handleInstallAll}
              disabled={installing}
              className="flex items-center gap-2 px-3 py-1.5 rounded bg-accent/10 text-accent border border-accent/30 hover:bg-accent/20 text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Download size={14} />
              {installing ? `Installing ${counts.missing}…` : `Install All Missing (${counts.missing})`}
            </button>
          )}
          <button
            onClick={handleRecheck}
            className="flex items-center gap-2 px-3 py-1.5 rounded border border-gray-700 text-gray-400 hover:text-gray-100 text-sm transition-colors"
          >
            <RefreshCw size={14} /> Re-check All
          </button>
        </div>
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

      {/* Live install log panel */}
      {showPanel && (
        <section className="rounded-lg border border-gray-800 bg-gray-900 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 border-b border-gray-800 bg-gray-950">
            <div className="flex items-center gap-2">
              <Download size={14} className="text-accent" />
              <span className="text-sm font-semibold text-gray-200">Install Log</span>
              {installing && <span className="text-xs text-accent animate-pulse">running…</span>}
            </div>
            <button
              onClick={() => setShowPanel(false)}
              disabled={installing}
              className="text-gray-500 hover:text-gray-200 disabled:opacity-30"
              title={installing ? 'Wait for install to finish' : 'Hide log'}
            >
              <X size={14} />
            </button>
          </div>
          <div className="p-3 max-h-72 overflow-y-auto font-mono text-xs leading-relaxed text-gray-300 bg-terminal">
            {logs.length === 0 ? (
              <p className="text-gray-600">Waiting for output…</p>
            ) : (
              logs.map((line, i) => (
                <div key={i} className="whitespace-pre-wrap break-all">{line || ' '}</div>
              ))
            )}
            <div ref={logEndRef} />
          </div>
        </section>
      )}

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
