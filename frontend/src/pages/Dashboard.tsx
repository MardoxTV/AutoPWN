import { Link } from 'react-router-dom'
import { Crosshair, Terminal, Trophy, Clock } from 'lucide-react'
import { useJobs } from '../hooks/useJobs'
import type { Job } from '../api/types'
import { clsx } from 'clsx'

function StatusBadge({ status }: { status: Job['status'] }) {
  return (
    <span className={clsx('text-xs px-2 py-0.5 rounded-full border font-mono', {
      'border-success/40 text-success': status === 'completed',
      'border-accent/40 text-accent':   status === 'running',
      'border-danger/40 text-danger':   status === 'failed',
      'border-gray-600 text-gray-500':  status === 'created' || status === 'cancelled',
    })}>
      {status}
    </span>
  )
}

function JobCard({ job }: { job: Job }) {
  return (
    <div className="p-4 rounded-lg border border-gray-800 bg-gray-900 hover:border-gray-700 transition-colors">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="font-semibold text-gray-200 truncate">
            {job.target_name ?? job.target_ip}
          </p>
          <p className="text-xs text-gray-500 font-mono">{job.target_ip} · {job.profile}</p>
        </div>
        <StatusBadge status={job.status} />
      </div>
      <div className="flex items-center gap-3 mt-3">
        {(job.status === 'running' || job.status === 'created') && (
          <Link
            to={`/live/${job.id}`}
            className="flex items-center gap-1 text-xs text-accent hover:underline"
          >
            <Terminal size={12} /> Live
          </Link>
        )}
        <Link
          to={`/results/${job.id}`}
          className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200"
        >
          <Trophy size={12} /> Results
        </Link>
        <span className="text-xs text-gray-600 ml-auto flex items-center gap-1">
          <Clock size={11} />
          {new Date(job.created_at).toLocaleString()}
        </span>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const { data: jobs, isLoading } = useJobs()

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <h1 className="text-2xl font-bold text-gray-100">Dashboard</h1>
        <Link
          to="/attack"
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-accent text-gray-950 font-bold text-sm hover:bg-accent/90 transition-colors"
        >
          <Crosshair size={14} /> New Attack
        </Link>
      </div>

      {isLoading && (
        <p className="text-gray-500 text-sm">Loading jobs...</p>
      )}

      {!isLoading && !jobs?.length && (
        <div className="text-center py-20 text-gray-600">
          <Crosshair size={48} className="mx-auto mb-4 opacity-30" />
          <p className="text-lg">No attacks yet</p>
          <p className="text-sm mt-1">
            <Link to="/attack" className="text-accent hover:underline">Launch your first attack</Link>
          </p>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {jobs?.map(job => <JobCard key={job.id} job={job} />)}
      </div>
    </div>
  )
}
