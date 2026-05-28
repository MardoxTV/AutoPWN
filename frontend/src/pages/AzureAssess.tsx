import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import { Cloud, Shield, ExternalLink, CheckCircle, AlertTriangle, Loader2, Copy } from 'lucide-react'
import { clsx } from 'clsx'
import type { AuthStatus } from '../api/azureTypes'

type Step = 'idle' | 'connecting' | 'waiting' | 'authenticated' | 'starting' | 'error'

export default function AzureAssess() {
  const navigate = useNavigate()
  const [step, setStep] = useState<Step>('idle')
  const [sessionId, setSessionId] = useState('')
  const [userCode, setUserCode] = useState('')
  const [verifyUri, setVerifyUri] = useState('')
  const [authInfo, setAuthInfo] = useState<AuthStatus | null>(null)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }

  useEffect(() => () => stopPolling(), [])

  const handleConnect = async () => {
    setStep('connecting')
    setError('')
    try {
      const res = await axios.post('/api/azure/auth/start')
      setSessionId(res.data.session_id)
      setUserCode(res.data.user_code)
      setVerifyUri(res.data.verification_uri)
      setStep('waiting')

      pollRef.current = setInterval(async () => {
        try {
          const status = await axios.get<AuthStatus>(`/api/azure/auth/status/${res.data.session_id}`)
          if (status.data.status === 'success') {
            stopPolling()
            setAuthInfo(status.data)
            setStep('authenticated')
          } else if (status.data.status === 'error') {
            stopPolling()
            setError(status.data.error || 'Authentication failed')
            setStep('error')
          }
        } catch {
          // network blip — keep polling
        }
      }, 3000)
    } catch (e: unknown) {
      const msg = axios.isAxiosError(e) ? (e.response?.data?.detail ?? e.message) : String(e)
      setError(msg)
      setStep('error')
    }
  }

  const handleStartAssessment = async () => {
    setStep('starting')
    try {
      const res = await axios.post(`/api/azure/assess/start/${sessionId}`)
      navigate(`/azure/results/${res.data.job_id}`)
    } catch (e: unknown) {
      const msg = axios.isAxiosError(e) ? (e.response?.data?.detail ?? e.message) : String(e)
      setError(msg)
      setStep('error')
    }
  }

  const copyCode = () => {
    navigator.clipboard.writeText(userCode)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="p-8 max-w-2xl mx-auto">
      <div className="flex items-center gap-3 mb-8">
        <div className="w-10 h-10 rounded-lg bg-accent/10 flex items-center justify-center">
          <Cloud size={20} className="text-accent" />
        </div>
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Azure Security Assessment</h1>
          <p className="text-gray-500 text-sm">Assess the security posture of an Azure tenancy</p>
        </div>
      </div>

      {/* What this checks */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 mb-6">
        <h2 className="text-sm font-medium text-gray-300 mb-3">Assessment Coverage</h2>
        <div className="grid grid-cols-2 gap-2">
          {[
            'Identity & Access (MFA, Roles, CA)',
            'Risky Users & Sign-in Threats',
            'Password Spray & Brute Force',
            'Legacy Authentication Usage',
            'Network Security Groups',
            'Storage Account Configuration',
            'Key Vault Security',
            'Defender for Cloud Score',
          ].map(item => (
            <div key={item} className="flex items-center gap-2 text-xs text-gray-400">
              <Shield size={12} className="text-accent shrink-0" />
              {item}
            </div>
          ))}
        </div>
        <p className="text-xs text-gray-600 mt-3">
          Network, storage, and Defender checks require Azure Resource Manager access (ARM token).
          ARM access is attempted automatically after Graph authentication.
        </p>
      </div>

      {/* Auth flow */}
      {step === 'idle' && (
        <button
          onClick={handleConnect}
          className="w-full py-3 rounded-lg bg-accent text-gray-950 font-semibold text-sm hover:bg-accent/90 transition-colors flex items-center justify-center gap-2"
        >
          <Cloud size={16} />
          Connect Azure Tenant
        </button>
      )}

      {step === 'connecting' && (
        <div className="flex items-center justify-center gap-3 py-8 text-gray-400">
          <Loader2 size={20} className="animate-spin" />
          <span className="text-sm">Starting device authentication flow…</span>
        </div>
      )}

      {step === 'waiting' && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 space-y-5">
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-full bg-warning/10 flex items-center justify-center shrink-0 mt-0.5">
              <span className="text-warning text-sm font-bold">1</span>
            </div>
            <div>
              <p className="text-sm text-gray-300 font-medium">Open the verification URL</p>
              <a
                href={verifyUri}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-accent flex items-center gap-1 mt-1 hover:underline"
              >
                {verifyUri} <ExternalLink size={11} />
              </a>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-full bg-warning/10 flex items-center justify-center shrink-0 mt-0.5">
              <span className="text-warning text-sm font-bold">2</span>
            </div>
            <div className="flex-1">
              <p className="text-sm text-gray-300 font-medium mb-2">Enter this code</p>
              <div className="flex items-center gap-3">
                <span className="font-mono text-2xl font-bold text-accent tracking-widest bg-gray-800 px-4 py-2 rounded">
                  {userCode}
                </span>
                <button
                  onClick={copyCode}
                  className={clsx(
                    'p-2 rounded transition-colors text-xs flex items-center gap-1',
                    copied ? 'text-success bg-success/10' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
                  )}
                >
                  <Copy size={14} />
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs text-gray-500 pt-2 border-t border-gray-800">
            <Loader2 size={12} className="animate-spin" />
            Waiting for authentication… polling every 3 seconds
          </div>
        </div>
      )}

      {step === 'authenticated' && authInfo && (
        <div className="space-y-4">
          <div className="bg-gray-900 border border-success/30 rounded-lg p-5">
            <div className="flex items-center gap-2 mb-3">
              <CheckCircle size={16} className="text-success" />
              <span className="text-sm font-medium text-success">Authentication Successful</span>
            </div>
            <div className="space-y-1 text-sm text-gray-400">
              <div><span className="text-gray-500">User: </span>{authInfo.user_name}</div>
              <div><span className="text-gray-500">Tenant ID: </span><code className="text-xs font-mono text-gray-300">{authInfo.tenant_id}</code></div>
              <div className="flex items-center gap-2">
                <span className="text-gray-500">ARM Access: </span>
                {authInfo.arm_available ? (
                  <span className="text-success text-xs">Available — network/storage/defender checks enabled</span>
                ) : (
                  <span className="text-warning text-xs">Not available — ARM checks will be skipped</span>
                )}
              </div>
            </div>
          </div>

          {!authInfo.arm_available && (
            <div className="bg-warning/5 border border-warning/20 rounded-lg p-4 text-xs text-warning">
              <AlertTriangle size={13} className="inline mr-1.5" />
              ARM token could not be acquired silently. Network security, storage, and Defender checks
              will be skipped. Identity and risk checks will still run.
            </div>
          )}

          <button
            onClick={handleStartAssessment}
            className="w-full py-3 rounded-lg bg-accent text-gray-950 font-semibold text-sm hover:bg-accent/90 transition-colors flex items-center justify-center gap-2"
          >
            <Shield size={16} />
            Start Security Assessment
          </button>
        </div>
      )}

      {step === 'starting' && (
        <div className="flex items-center justify-center gap-3 py-8 text-gray-400">
          <Loader2 size={20} className="animate-spin" />
          <span className="text-sm">Launching assessment…</span>
        </div>
      )}

      {step === 'error' && (
        <div className="space-y-4">
          <div className="bg-danger/5 border border-danger/30 rounded-lg p-5">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle size={16} className="text-danger" />
              <span className="text-sm font-medium text-danger">Error</span>
            </div>
            <p className="text-sm text-gray-400">{error}</p>
          </div>
          <button
            onClick={() => { setStep('idle'); setError('') }}
            className="w-full py-2 rounded-lg border border-gray-700 text-gray-400 text-sm hover:border-gray-600 hover:text-gray-200 transition-colors"
          >
            Try Again
          </button>
        </div>
      )}
    </div>
  )
}
