import { useParams } from 'react-router-dom'
import { Trophy, Key, AlertTriangle, FileText } from 'lucide-react'
import { useResults } from '../hooks/useJobs'
import FlagBanner from '../components/FlagBanner'
import { getPdfReport } from '../api/client'

export default function Results() {
  const { jobId } = useParams<{ jobId: string }>()
  const { data, isLoading } = useResults(jobId!)

  if (isLoading) return <div className="p-8 text-gray-500">Loading results...</div>
  if (!data) return <div className="p-8 text-danger">Job not found</div>

  const { findings, credentials, flags } = data

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">Results</h1>
        <a
          href={getPdfReport(jobId!)}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 px-3 py-1.5 rounded border border-gray-700 text-gray-400 hover:text-gray-100 text-sm transition-colors"
        >
          <FileText size={14} /> Download Report
        </a>
      </div>

      {/* Flags */}
      {flags.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <Trophy size={14} /> Flags ({flags.length})
          </h2>
          <FlagBanner flags={flags} />
        </section>
      )}

      {/* Credentials */}
      {credentials.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <Key size={14} /> Credentials ({credentials.length})
          </h2>
          <div className="overflow-x-auto rounded-lg border border-gray-800">
            <table className="w-full text-sm">
              <thead className="bg-gray-900 text-gray-500 text-xs uppercase">
                <tr>
                  {['Service', 'Username', 'Password', 'Port', 'Found By'].map(h => (
                    <th key={h} className="px-4 py-2 text-left">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {credentials.map(c => (
                  <tr key={c.id} className="border-t border-gray-800 hover:bg-gray-900/50">
                    <td className="px-4 py-2 text-accent">{c.service}</td>
                    <td className="px-4 py-2 font-mono">{c.username}</td>
                    <td className="px-4 py-2 font-mono text-danger">{c.password}</td>
                    <td className="px-4 py-2 text-gray-500">{c.port ?? '-'}</td>
                    <td className="px-4 py-2 text-gray-500">{c.found_by ?? '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Findings */}
      <section>
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
          <AlertTriangle size={14} /> Findings ({findings.length})
        </h2>
        <div className="space-y-1">
          {findings.map(f => (
            <div key={f.id} className="flex items-start gap-3 px-3 py-2 rounded border border-gray-800 bg-gray-900 text-sm hover:border-gray-700 transition-colors">
              <span className={`text-xs px-1.5 py-0.5 rounded shrink-0 font-mono ${
                f.severity === 'critical' ? 'bg-danger/20 text-danger' :
                f.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                f.severity === 'medium' ? 'bg-warning/20 text-warning' :
                'bg-gray-700 text-gray-400'
              }`}>
                {f.severity}
              </span>
              <span className="text-gray-500 text-xs shrink-0">{f.tool}</span>
              <span className="text-gray-200 font-mono text-xs break-all">{f.value}</span>
              <span className="text-gray-600 text-xs ml-auto shrink-0">{f.phase}</span>
            </div>
          ))}
          {!findings.length && <p className="text-gray-600 text-sm">No findings yet.</p>}
        </div>
      </section>
    </div>
  )
}
