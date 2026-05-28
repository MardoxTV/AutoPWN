import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import type { WsMessage } from '../api/types'
import { useJobStore } from '../store/jobStore'
import { API_TOKEN } from '../api/client'

const WS_BASE = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`
const BACKOFF_BASE_MS = 1_000
const BACKOFF_MAX_MS = 30_000

export function useJobSocket(jobId: string | null) {
  const ws = useRef<WebSocket | null>(null)
  const retryCount = useRef(0)
  const retryTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const intentionalClose = useRef(false)
  const handleWsMessage = useJobStore(s => s.handleWsMessage)
  const qc = useQueryClient()

  useEffect(() => {
    if (!jobId) return

    // Clear per-job ephemeral state when switching jobs — terminal lines, phase, flags
    useJobStore.setState({
      terminalLines: [],
      currentPhase: null,
      phaseStatus: {},
      recentFlags: [],
    })

    intentionalClose.current = false
    retryCount.current = 0

    const connect = () => {
      const qs = API_TOKEN ? `?token=${encodeURIComponent(API_TOKEN)}` : ''
      const socket = new WebSocket(`${WS_BASE}/ws/jobs/${jobId}/logs${qs}`)
      ws.current = socket

      socket.onopen = () => {
        retryCount.current = 0  // reset backoff on successful connect
      }

      socket.onmessage = (event) => {
        try {
          const msg: WsMessage = JSON.parse(event.data)
          handleWsMessage(msg)
          // Status changes affect queue_position too — refresh the API view immediately
          if (msg.type === 'job_status' || msg.type === 'phase_change') {
            qc.invalidateQueries({ queryKey: ['job', jobId] })
            qc.invalidateQueries({ queryKey: ['jobs'] })
          }
        } catch { /* ignore parse errors */ }
      }

      socket.onclose = () => {
        if (intentionalClose.current) return
        // Exponential backoff: 1s, 2s, 4s, 8s … capped at 30s
        const delay = Math.min(BACKOFF_BASE_MS * 2 ** retryCount.current, BACKOFF_MAX_MS)
        retryCount.current += 1
        retryTimer.current = setTimeout(connect, delay)
      }

      socket.onerror = () => socket.close()
    }

    connect()

    // Ping every 30s to keep connection alive through idle proxies
    const pingInterval = setInterval(() => {
      if (ws.current?.readyState === WebSocket.OPEN) {
        ws.current.send(JSON.stringify({ type: 'ping' }))
      }
    }, 30_000)

    return () => {
      intentionalClose.current = true
      clearInterval(pingInterval)
      if (retryTimer.current) clearTimeout(retryTimer.current)
      ws.current?.close()
      ws.current = null
    }
  }, [jobId, handleWsMessage, qc])
}
