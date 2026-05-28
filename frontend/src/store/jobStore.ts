import { create } from 'zustand'
import type { Job, WsMessage, Flag } from '../api/types'

interface JobStore {
  activeJob: Job | null
  terminalLines: string[]
  currentPhase: string | null
  phaseStatus: Record<string, string>
  recentFlags: Flag[]
  queuePosition: number | null
  setActiveJob: (job: Job | null) => void
  setQueuePosition: (pos: number | null) => void
  handleWsMessage: (msg: WsMessage) => void
  clearTerminal: () => void
}

export const useJobStore = create<JobStore>((set) => ({
  activeJob: null,
  terminalLines: [],
  currentPhase: null,
  phaseStatus: {},
  recentFlags: [],
  queuePosition: null,

  setActiveJob: (job) => set({ activeJob: job, terminalLines: [], currentPhase: null, phaseStatus: {}, queuePosition: null }),
  setQueuePosition: (pos) => set({ queuePosition: pos }),

  handleWsMessage: (msg) => set((state) => {
    switch (msg.type) {
      case 'tool_output':
        return { terminalLines: [...state.terminalLines.slice(-4999), msg.data ?? ''] }

      case 'log':
        return { terminalLines: [...state.terminalLines.slice(-4999), msg.message ?? ''] }

      case 'phase_change':
        return {
          currentPhase: msg.phase ?? state.currentPhase,
          phaseStatus: { ...state.phaseStatus, [msg.phase ?? '']: msg.status ?? '' },
        }

      case 'finding':
        if (msg.finding_type === 'flag' && msg.value) {
          const flag: Flag = {
            id: Date.now(),
            job_id: msg.job_id,
            flag_type: (msg.metadata?.flag_type as 'user' | 'root') ?? 'unknown',
            value: msg.value,
            submitted: false,
            timestamp: msg.timestamp,
          }
          return { recentFlags: [...state.recentFlags, flag] }
        }
        return {}

      case 'job_status':
        if (state.activeJob && msg.status) {
          // Once the job starts running, it's out of the queue
          const cleared = msg.status === 'running' ? { queuePosition: null } : {}
          return { activeJob: { ...state.activeJob, status: msg.status as Job['status'] }, ...cleared }
        }
        return {}

      default:
        return {}
    }
  }),

  clearTerminal: () => set({ terminalLines: [] }),
}))
