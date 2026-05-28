import { useState, useEffect } from 'react'
import { Settings as SettingsIcon, Save } from 'lucide-react'
import { getSettings, updateSettings } from '../api/client'

export default function Settings() {
  const [settings, setSettings] = useState<Record<string, unknown>>({})
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    getSettings().then(setSettings).catch(() => {})
  }, [])

  const handleSave = async () => {
    await updateSettings(settings)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const set = (path: string[], value: unknown) => {
    setSettings(prev => {
      const next = structuredClone(prev)
      let obj: Record<string, unknown> = next
      for (let i = 0; i < path.length - 1; i++) {
        obj = obj[path[i]] as Record<string, unknown>
      }
      obj[path[path.length - 1]] = value
      return next
    })
  }

  const net = settings.network as Record<string, unknown> ?? {}
  const server = settings.server as Record<string, unknown> ?? {}
  const msf = settings.msfrpc as Record<string, unknown> ?? {}

  return (
    <div className="p-8 max-w-2xl space-y-8">
      <div className="flex items-center gap-3">
        <SettingsIcon size={20} className="text-accent" />
        <h1 className="text-2xl font-bold text-gray-100">Settings</h1>
      </div>

      <section className="space-y-4 p-5 rounded-lg border border-gray-800 bg-gray-900">
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Network</h2>
        <Field label="VPN Interface" value={String(net.vpn_interface ?? 'tun0')}
          onChange={v => set(['network', 'vpn_interface'], v)} />
        <Field label="Default Timeout (s)" value={String(net.default_timeout_s ?? 30)}
          onChange={v => set(['network', 'default_timeout_s'], Number(v))} type="number" />
      </section>

      <section className="space-y-4 p-5 rounded-lg border border-gray-800 bg-gray-900">
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Server</h2>
        <Field label="Host" value={String(server.host ?? '0.0.0.0')}
          onChange={v => set(['server', 'host'], v)} />
        <Field label="Port" value={String(server.port ?? 8000)}
          onChange={v => set(['server', 'port'], Number(v))} type="number" />
      </section>

      <section className="space-y-4 p-5 rounded-lg border border-gray-800 bg-gray-900">
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Metasploit MSFRPC</h2>
        <Field label="Host" value={String(msf.host ?? '127.0.0.1')}
          onChange={v => set(['msfrpc', 'host'], v)} />
        <Field label="Port" value={String(msf.port ?? 55553)}
          onChange={v => set(['msfrpc', 'port'], Number(v))} type="number" />
        <Field label="Password" value={String(msf.password ?? '')}
          onChange={v => set(['msfrpc', 'password'], v)} type="password" />
      </section>

      <button
        onClick={handleSave}
        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-accent text-gray-950 font-bold text-sm hover:bg-accent/90 transition-colors"
      >
        <Save size={14} />
        {saved ? 'Saved!' : 'Save Settings'}
      </button>
    </div>
  )
}

function Field({ label, value, onChange, type = 'text' }: {
  label: string; value: string; onChange: (v: string) => void; type?: string
}) {
  return (
    <div>
      <label className="block text-xs text-gray-500 mb-1">{label}</label>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        className="w-full bg-gray-950 border border-gray-700 rounded px-3 py-1.5 text-gray-100 font-mono text-sm focus:outline-none focus:border-accent"
      />
    </div>
  )
}
