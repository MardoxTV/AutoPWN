import axios from 'axios'
import type { Job, ToolsStatusResponse, Finding, Credential, Flag } from './types'

// Set VITE_API_TOKEN in frontend/.env.local to match AUTOPWN_API_TOKEN on the backend.
export const API_TOKEN: string = import.meta.env.VITE_API_TOKEN ?? ''

const api = axios.create({ baseURL: '/api/v1' })

// Attach Bearer token if one is configured
api.interceptors.request.use((config) => {
  if (API_TOKEN) {
    config.headers.Authorization = `Bearer ${API_TOKEN}`
  }
  return config
})

// Jobs
export const createJob = (body: {
  target_ip: string
  target_name?: string
  profile: string
  options?: Record<string, unknown>
}) => api.post<Job>('/jobs', body).then(r => r.data)

export const listJobs = () => api.get<Job[]>('/jobs').then(r => r.data)
export const getJob = (id: string) => api.get<Job>(`/jobs/${id}`).then(r => r.data)
export const cancelJob = (id: string) => api.delete(`/jobs/${id}`)

// Results
export const getResults = (jobId: string) =>
  api.get<{ job_id: string; findings: Finding[]; credentials: Credential[]; flags: Flag[] }>(
    `/results/${jobId}`
  ).then(r => r.data)

export const getFlags = (jobId: string) =>
  api.get<Flag[]>(`/results/${jobId}/flags`).then(r => r.data)

export const getLogs = (jobId: string, limit = 500, offset = 0) =>
  api.get(`/results/${jobId}/logs`, { params: { limit, offset } }).then(r => r.data)

// Tools
export const getToolsStatus = () =>
  api.get<ToolsStatusResponse>('/tools').then(r => r.data)

export const installTool = (name: string) =>
  api.post(`/tools/${name}/install`).then(r => r.data)

export const checkAllTools = () =>
  api.post('/tools/check-all').then(r => r.data)

// Settings
export const getSettings = () => api.get('/settings').then(r => r.data)
export const updateSettings = (s: Record<string, unknown>) =>
  api.put('/settings', s).then(r => r.data)

// Reports
export const getHtmlReport = (jobId: string) =>
  `/api/v1/reports/${jobId}/html`
export const getPdfReport = (jobId: string) =>
  `/api/v1/reports/${jobId}/pdf`
