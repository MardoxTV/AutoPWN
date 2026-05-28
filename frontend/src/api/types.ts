export type JobStatus =
  | 'created' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled'

export type Phase =
  | 'recon' | 'enumeration' | 'exploitation' | 'post_exploitation'

export interface Job {
  id: string
  target_ip: string
  target_name?: string
  profile: string
  status: JobStatus
  current_phase?: Phase
  created_at: string
  started_at?: string
  completed_at?: string
  error_msg?: string
  queue_position?: number
}

export interface Finding {
  id: number
  job_id: string
  phase: string
  tool: string
  finding_type: string
  severity: string
  value: string
  metadata: Record<string, unknown>
  timestamp: string
}

export interface Credential {
  id: number
  job_id: string
  service: string
  username: string
  password: string
  port?: number
  valid: boolean
  found_by?: string
  timestamp: string
}

export interface Flag {
  id: number
  job_id: string
  flag_type: 'user' | 'root' | 'unknown'
  value: string
  path?: string
  submitted: boolean
  timestamp: string
}

export interface LogEntry {
  id: number
  job_id: string
  phase?: string
  tool?: string
  level: string
  message: string
  timestamp: string
}

export interface ToolInfo {
  name: string
  status: 'ok' | 'missing' | 'outdated' | 'timeout' | 'error'
  version?: string
  required: boolean
  category: string
  description: string
  install_method: string
  message?: string
}

export interface ToolsStatusResponse {
  tools: Record<string, ToolInfo>
  pip_packages: Record<string, ToolInfo>
  network: Record<string, boolean>
}

// WebSocket message types
export type WsMessageType =
  | 'log' | 'tool_output' | 'phase_change' | 'finding' | 'job_status' | 'error' | 'pong'

export interface WsMessage {
  type: WsMessageType
  job_id: string
  timestamp: string
  phase?: string
  tool?: string
  level?: string
  message?: string
  data?: string          // raw ANSI terminal output
  finding_type?: string
  severity?: string
  value?: string
  metadata?: Record<string, unknown>
  status?: string
}
