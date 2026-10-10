import React, { useState, useEffect, useCallback } from 'react'
import { reasoning } from '../api/client'
import { format } from 'date-fns'
import {
  Scan, Target, Shield, Brain, CheckCircle, XCircle, Clock, AlertTriangle,
  Terminal, Zap, ChevronDown, ChevronUp
} from 'lucide-react'

const actionIcons = {
  scan: Scan,
  exploit_attempt: Zap,
  credential_test: Terminal,
  interpretation: Brain,
  stop: Shield,
}

const statusStyles = {
  proposed: 'bg-yellow-900/30 border-yellow-700',
  approved: 'bg-green-900/30 border-green-700',
  rejected: 'bg-red-900/30 border-red-700',
  executed: 'bg-blue-900/30 border-blue-700',
  failed: 'bg-red-900/30 border-red-700',
}

export default function ReasoningTimeline({
  engagementId,
  autoRefresh = true,
  onApproveAction,
}) {
  const [trail, setTrail] = useState([])
  const [expandedItems, setExpandedItems] = useState({})
  const [actionLoading, setActionLoading] = useState({})

  const fetchTrail = useCallback(() => {
    if (!engagementId) return
    reasoning
      .trail(engagementId)
      .then((r) => {
        const data = r?.data || []
        // Ensure chronological order
        data.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
        setTrail(data)
      })
      .catch((err) => console.error('Error fetching reasoning trail:', err))
  }, [engagementId])

  useEffect(() => {
    fetchTrail()
    if (!autoRefresh) return

    const interval = setInterval(fetchTrail, 3500)
    return () => clearInterval(interval)
  }, [fetchTrail, autoRefresh])

  // Live SSE attempt — falls back to polling above if SSE fails
  useEffect(() => {
    if (!engagementId || !autoRefresh) return
    let cancelled = false
    let reader = null
    const trySse = async () => {
      try {
        const token = localStorage.getItem("token")
        const res = await fetch(`/api/reasoning/engagement/${engagementId}/stream`, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        })
        if (!res.ok || !res.body) throw new Error("SSE not available")
        reader = res.body.getReader()
        const decoder = new TextDecoder()
        let buf = ""
        while (!cancelled) {
          const { value, done } = await reader.read()
          if (done) break
          buf += decoder.decode(value, { stream: true })
          const parts = buf.split("\n\n")
          buf = parts.pop() || ""
          for (const chunk of parts) {
            const line = chunk.trim()
            if (line.startsWith("data:")) {
              try {
                const payload = JSON.parse(line.slice(5).trim())
                if (payload.jobs || payload.trail) {
                  // Refresh full trail to keep UI consistent, but we have live hint
                  fetchTrail()
                }
                if (payload.done) {
                  cancelled = true
                  break
                }
              } catch {}
            }
          }
        }
      } catch {
        // SSE failed — polling already handles it
      }
    }
    trySse()
    return () => {
      cancelled = true
      try { reader?.cancel() } catch {}
    }
  }, [engagementId, autoRefresh, fetchTrail])

  const toggleExpand = (id) => {
    setExpandedItems((prev) => ({ ...prev, [id]: !prev[id] }))
  }

  const handleDecision = async (entry, approved) => {
    setActionLoading((prev) => ({ ...prev, [entry.id]: true }))
    try {
      if (onApproveAction) {
        await onApproveAction(entry.id, approved)
      } else {
        // Fallback directly hitting reasoning client if handler not supplied
        await reasoning.approve(entry.id, { approved })
      }
      fetchTrail()
    } catch (err) {
      console.error('Failed to update action status:', err)
    } finally {
      setActionLoading((prev) => ({ ...prev, [entry.id]: false }))
    }
  }

  const Icon = ({ actionType }) => {
    const Ico = actionIcons[actionType] || Brain
    return <Ico size={18} className="text-neon-blue" />
  }

  return (
    <div className="relative">
      {trail.length > 0 && (
        <div className="absolute left-6 top-0 bottom-0 w-px bg-pentest-600" />
      )}
      <div className="space-y-4">
        {trail.map((entry) => {
          const isExpanded = !!expandedItems[entry.id]
          const isPending = entry.status === 'proposed'
          const isLoadingThis = !!actionLoading[entry.id]

          return (
            <div key={entry.id} className="relative flex gap-4">
              <div className="relative z-10 w-12 h-12 bg-pentest-800 border border-pentest-600 rounded-full flex items-center justify-center flex-shrink-0 shadow-lg">
                <Icon actionType={entry.action_type} />
              </div>

              <div
                className={`flex-1 rounded-lg border p-4 transition-all ${
                  statusStyles[entry.status] || 'border-pentest-600'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-sm capitalize">
                      {entry.action_type?.replace('_', ' ') || 'Action'}
                    </span>
                    <span
                      className={`text-xs px-2 py-0.5 rounded-full ${
                        entry.actor === 'ai'
                          ? 'bg-purple-900/50 text-purple-300'
                          : 'bg-blue-900/50 text-blue-300'
                      }`}
                    >
                      {entry.actor}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span
                      className={`text-xs px-2 py-0.5 rounded font-mono uppercase ${
                        entry.status === 'executed'
                          ? 'bg-green-900/50 text-green-300'
                          : entry.status === 'proposed'
                          ? 'bg-yellow-900/50 text-yellow-300 animate-pulse'
                          : entry.status === 'rejected'
                          ? 'bg-red-900/50 text-red-300'
                          : 'bg-gray-800 text-gray-400'
                      }`}
                    >
                      {entry.status}
                    </span>

                    {entry.timestamp && (
                      <span className="text-xs text-gray-400 font-mono">
                        {format(new Date(entry.timestamp), 'HH:mm:ss')}
                      </span>
                    )}

                    {(entry.tool_payload || entry.observation) && (
                      <button
                        onClick={() => toggleExpand(entry.id)}
                        className="text-gray-400 hover:text-white transition-colors ml-1 p-0.5"
                        title={isExpanded ? 'Hide raw details' : 'Show raw details'}
                      >
                        {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                      </button>
                    )}
                  </div>
                </div>

                {entry.target && (
                  <p className="text-sm text-gray-300 mb-1 font-mono">
                    <Target size={13} className="inline mr-1 text-neon-blue" />
                    {entry.target}
                  </p>
                )}

                <p className="text-sm text-gray-300 leading-relaxed font-sans">
                  {entry.reasoning || entry.reasoning_text || 'Evaluating target response...'}
                </p>

                {/* HITL: Lead Approval controls for high-risk proposed actions */}
                {isPending && (
                  <div className="mt-3 p-3 bg-pentest-900/90 border border-yellow-700/60 rounded-md flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs text-yellow-300">
                      <AlertTriangle size={15} className="flex-shrink-0" />
                      <span>High-risk action requires Lead authorization.</span>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        disabled={isLoadingThis}
                        onClick={() => handleDecision(entry, true)}
                        className="px-3 py-1 text-xs bg-green-700 hover:bg-green-600 disabled:opacity-50 text-white rounded font-medium flex items-center gap-1 transition-colors"
                      >
                        <CheckCircle size={13} />
                        Approve
                      </button>
                      <button
                        disabled={isLoadingThis}
                        onClick={() => handleDecision(entry, false)}
                        className="px-3 py-1 text-xs bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white rounded font-medium flex items-center gap-1 transition-colors"
                      >
                        <XCircle size={13} />
                        Reject
                      </button>
                    </div>
                  </div>
                )}

                {/* Collapsible Tool Payload / Observation Block */}
                {isExpanded && (
                  <div className="mt-3 pt-3 border-t border-pentest-700/70 space-y-2 font-mono text-xs">
                    {entry.tool_payload && (
                      <div>
                        <div className="text-[10px] uppercase tracking-wider text-gray-400 mb-1">
                          Tool Payload / Dispatched Command:
                        </div>
                        <pre className="p-2.5 rounded bg-black/60 border border-pentest-700 text-emerald-400 overflow-x-auto text-[11px]">
                          {typeof entry.tool_payload === 'object'
                            ? JSON.stringify(entry.tool_payload, null, 2)
                            : entry.tool_payload}
                        </pre>
                      </div>
                    )}

                    {entry.observation && (
                      <div>
                        <div className="text-[10px] uppercase tracking-wider text-gray-400 mb-1">
                          Tool Raw Observation:
                        </div>
                        <pre className="p-2.5 rounded bg-black/60 border border-pentest-700 text-gray-300 max-h-44 overflow-y-auto whitespace-pre-wrap text-[11px]">
                          {entry.observation}
                        </pre>
                      </div>
                    )}
                  </div>
                )}

                {entry.result_summary && !isExpanded && (
                  <p className="text-xs text-gray-400 mt-2 border-t border-pentest-700 pt-2 font-mono">
                    Result: {entry.result_summary}
                  </p>
                )}
              </div>
            </div>
          )
        })}

        {trail.length === 0 && (
          <div className="text-center py-16 text-gray-500">
            <Brain size={48} className="mx-auto mb-4 opacity-40 text-gray-400" />
            <p className="text-sm font-medium">No reasoning trail recorded yet</p>
            <p className="text-xs text-gray-600 mt-1">Start an orchestration scan to observe autonomous agent decisions</p>
          </div>
        )}
      </div>
    </div>
  )
}