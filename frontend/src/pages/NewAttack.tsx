import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Crosshair, Zap } from 'lucide-react'
import { useCreateJob } from '../hooks/useJobs'
import { useJobStore } from '../store/jobStore'

const PROFILES = [
  { id: 'quick',      label: 'Quick',      desc: 'Top 1000 ports, basic enum only' },
  { id: 'standard',   label: 'Standard',   desc: 'Full scan, all phases, common wordlists' },
  { id: 'aggressive', label: 'Aggressive', desc: 'Full TCP+UDP, brute force, all exploits' },
  { id: 'web_focus',  label: 'Web Focus',  desc: 'Deep HTTP/S, SQLi, XSS, LFI, gobuster' },
  { id: 'ad_windows', label: 'AD/Windows', desc: 'SMB, LDAP, Kerberos, impacket suite' },
  { id: 'custom',     label: 'Custom',     desc: 'Pick your own modules' },
]

export default function NewAttack() {
  const navigate = useNavigate()
  const createJob = useCreateJob()
  const setActiveJob = useJobStore(s => s.setActiveJob)
  const setQueuePosition = useJobStore(s => s.setQueuePosition)

  const [targetIp, setTargetIp] = useState('')
  const [targetName, setTargetName] = useState('')
  const [profile, setProfile] = useState('standard')
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (!targetIp.trim()) { setError('Target IP is required'); return }
    try {
      const job = await createJob.mutateAsync({ target_ip: targetIp, target_name: targetName, profile })
      setActiveJob(job)
      if (typeof job.queue_position === 'number') {
        setQueuePosition(job.queue_position)
      }
      navigate(`/live/${job.id}`)
    } catch {
      setError('Failed to create job. Is the backend running?')
    }
  }

  return (
    <div className="p-8 max-w-2xl mx-auto">
      <div className="flex items-center gap-3 mb-8">
        <Crosshair size={24} className="text-accent" />
        <h1 className="text-2xl font-bold text-gray-100">New Attack</h1>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target */}
        <div className="space-y-4 p-5 rounded-lg border border-gray-800 bg-gray-900">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Target</h2>
          <div>
            <label className="block text-sm text-gray-400 mb-1">IP Address *</label>
            <input
              type="text"
              value={targetIp}
              onChange={e => setTargetIp(e.target.value)}
              placeholder="10.10.11.x"
              className="w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-gray-100 font-mono text-sm focus:outline-none focus:border-accent"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Machine Name (optional)</label>
            <input
              type="text"
              value={targetName}
              onChange={e => setTargetName(e.target.value)}
              placeholder="e.g. Cicada"
              className="w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-accent"
            />
          </div>
        </div>

        {/* Profile */}
        <div className="space-y-3 p-5 rounded-lg border border-gray-800 bg-gray-900">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Attack Profile</h2>
          <div className="grid grid-cols-2 gap-2">
            {PROFILES.map(p => (
              <button
                key={p.id}
                type="button"
                onClick={() => setProfile(p.id)}
                className={`text-left px-3 py-2.5 rounded border transition-colors ${
                  profile === p.id
                    ? 'border-accent bg-accent/10 text-accent'
                    : 'border-gray-700 text-gray-400 hover:border-gray-500 hover:text-gray-200'
                }`}
              >
                <div className="font-semibold text-sm">{p.label}</div>
                <div className="text-xs opacity-70 mt-0.5">{p.desc}</div>
              </button>
            ))}
          </div>
        </div>

        {error && (
          <p className="text-danger text-sm bg-danger/10 border border-danger/30 px-3 py-2 rounded">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={createJob.isPending}
          className="w-full flex items-center justify-center gap-2 py-3 rounded-lg bg-accent text-gray-950 font-bold hover:bg-accent/90 transition-colors disabled:opacity-50"
        >
          <Zap size={16} />
          {createJob.isPending ? 'Launching...' : 'Launch Attack'}
        </button>
      </form>
    </div>
  )
}
