import React, { useState, useEffect, useCallback } from 'react'
import { reasoning } from '../api/client'
import { CheckCircle, XCircle, Clock, AlertTriangle, ShieldAlert, RefreshCw } from 'lucide-react'

export default function ApprovalQueue({ engagementId, userRole = 'lead', onActionResolved }) {
  const [queue, setQueue] = useState([])
  const [loading, setLoading] = useState(false)
  const [actionLoading, setActionLoading] = useState({})

  const isLead = (userRole || '').toLowerCase() === 'lead'

  const loadQueue = useCallback(async () => {
    if (!engagementId) return
    try {
      const res = await reasoning.queue(engagementId)
      setQueue(res?.data || [])
    } catch (err) {
      console.error('Failed to fetch approval queue:', err)
    }
  }, [engagementId])

  useEffect(() => {
    loadQueue()
    const interval = setInterval(loadQueue, 4000)
    return () => clearInterval(interval)
  }, [loadQueue])

  const handleDecision = async (logId, approved, rationale = '') => {
    if (!isLead) return
    setActionLoading(prev => ({ ...prev, [logId]: true }))

    try {
      if (approved) {
        await reasoning.approve(logId, true)
      } else {
        await reasoning.approve(logId, false, rationale || 'Rejected by Lead operator')
      }
      
      // Optimistically remove from queue immediately
      setQueue(prev => prev.filter(item => item.id !== logId))
      
      if (onActionResolved) {
        onActionResolved(logId, approved)
      }
    } catch (err) {
      console.error(`Failed to ${approved ? 'approve' : 'reject'} action:`, err)
      loadQueue()
    } finally {
      setActionLoading(prev => ({ ...prev, [logId]: false }))
    }
  }

  const riskColor = {
    low: 'text-green-400',
    medium: 'text-yellow-400',
    high: 'text-red-400',
    critical: 'text-red-500 font-bold',
  }

  return (
    <div className="space-y-4">
      {/* Lead Authorization Alert */}
      {!isLead && (
        <div className="p-3 bg-blue-950/40 border border-blue-800/60 rounded-lg text-xs text-blue-300 flex items-center gap-2">
          <AlertTriangle size={15} className="text-blue-400 flex-shrink-0" />
          <span>
            Read-only mode. Approving or rejecting high-risk exploits requires the <strong>Lead</strong> role.
          </span>
        </div>
      )}

      {queue.length === 0 ? (
        <div className="text-center py-16 text-gray-600">
          <CheckCircle size={48} className="mx-auto mb-4 opacity-50 text-green-500" />
          <p className="text-sm font-medium">No pending actions — queue is clear</p>
          <p className="text-xs text-gray-500 mt-1">Autonomous agent is operating within authorized limits.</p>
        </div>
      ) : (
        queue.map(item => {
          const isProcessing = !!actionLoading[item.id]
          const riskLevel = item.proposed_action?.risk_level?.toLowerCase() || 'unknown'

          return (
            <div key={item.id} className="card border-yellow-900/40 bg-pentest-900/60 p-4 rounded-lg border">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2 flex-wrap">
                    <Clock size={16} className="text-yellow-400 flex-shrink-0" />
                    <span className="font-semibold text-sm uppercase tracking-wide">
                      {item.action_type}
                    </span>
                    <span className={`text-xs uppercase px-2 py-0.5 rounded bg-black/40 border border-gray-800 ${riskColor[riskLevel] || 'text-gray-400'}`}>
                      Risk: {riskLevel}
                    </span>
                    {item.proposed_action?.tool && (
                      <span className="text-xs font-mono text-cyan-400 bg-cyan-950/50 px-2 py-0.5 rounded border border-cyan-800/50">
                        {item.proposed_action.tool}
                      </span>
                    )}
                  </div>

                  <p className="text-sm text-gray-300 mb-1 font-mono">
                    <strong className="text-gray-400 font-sans">Target:</strong> {item.target}
                  </p>
                  <p className="text-sm text-gray-400 mb-2 leading-relaxed">
                    <strong className="text-gray-300">Reasoning:</strong> {item.reasoning}
                  </p>

                  {item.proposed_action?.parameters && (
                    <details className="text-xs text-gray-400 mt-2">
                      <summary className="cursor-pointer text-cyan-400 hover:text-cyan-300 transition-colors font-mono">
                        View Payload Parameters
                      </summary>
                      <pre className="bg-pentest-950 border border-pentest-800 rounded p-2.5 mt-1.5 overflow-auto max-h-36 font-mono text-[11px] text-emerald-400">
                        {JSON.stringify(item.proposed_action.parameters, null, 2)}
                      </pre>
                    </details>
                  )}
                </div>

                <div className="flex gap-2 ml-4 flex-shrink-0">
                  <button
                    onClick={() => handleDecision(item.id, true)}
                    disabled={!isLead || isProcessing}
                    className="btn-primary text-sm flex items-center gap-1.5 px-3 py-1.5 rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                  >
                    <CheckCircle size={14} />
                    {isProcessing ? 'Processing...' : 'Approve'}
                  </button>
                  <button
                    onClick={() => handleDecision(item.id, false)}
                    disabled={!isLead || isProcessing}
                    className="btn-danger text-sm flex items-center gap-1.5 px-3 py-1.5 rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                  >
                    <XCircle size={14} />
                    Reject
                  </button>
                </div>
              </div>
            </div>
          )
        })
      )}
    </div>
  )
}
