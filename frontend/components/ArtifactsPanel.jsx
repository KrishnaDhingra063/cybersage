import React, { useEffect, useState } from 'react'
import { Network, AlertTriangle, Loader, Boxes } from 'lucide-react'
import { reasoning, findings } from '../api/client'
import FindingInline from './FindingInline'
import MiniGraph from './MiniGraph'

const tabs = [
  { id: 'findings', label: 'Findings', icon: AlertTriangle },
  { id: 'graph', label: 'Attack Graph', icon: Network },
  { id: 'jobs', label: 'Jobs', icon: Boxes },
]

export default function ArtifactsPanel({ engagementId, isLead }) {
  const [tab, setTab] = useState('findings')
  const [findingsList, setFindingsList] = useState([])
  const [graph, setGraph] = useState(null)
  const [jobs, setJobs] = useState([])

  useEffect(() => {
    if (!engagementId) return
    findings.list(engagementId).then(r => setFindingsList(r.data))
    reasoning.graph(engagementId).then(r => setGraph(r.data)).catch(() => {})
    reasoning.jobs(engagementId).then(r => setJobs(r.data)).catch(() => {})
  }, [engagementId])

  return (
    <div className="h-full flex flex-col bg-slate-900/40 border-l border-slate-800">
      <div className="flex border-b border-slate-800">
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex-1 flex items-center justify-center gap-1.5 px-2 py-3 text-xs transition-colors ${
              tab === t.id ? 'text-cyan-300 border-b-2 border-cyan-500' : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            <t.icon size={13} /> {t.label}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-auto p-3 space-y-3">
        {tab === 'findings' && (
          findingsList.length === 0 ? (
            <p className="text-xs text-slate-600 text-center py-10">No findings yet — ask the agent to scan.</p>
          ) : (
            findingsList.map(f => <FindingInline key={f.id} finding={f} engagementId={engagementId} isLead={isLead} />)
          )
        )}

        {tab === 'graph' && (
          graph ? <MiniGraph nodes={graph.nodes} edges={graph.edges} /> : <p className="text-xs text-slate-600 text-center py-10"><Loader size={14} className="inline animate-spin mr-1" />Loading graph…</p>
        )}

        {tab === 'jobs' && (
          jobs.length === 0 ? (
            <p className="text-xs text-slate-600 text-center py-10">No tool jobs yet.</p>
          ) : (
            jobs.map(job => (
              <div key={job.id} className="rounded border border-slate-800 bg-slate-900/60 px-3 py-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-slate-200">{job.tool_name}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded ${job.status === 'completed' ? 'bg-green-900/40 text-green-300' : job.status === 'failed' ? 'bg-rose-900/40 text-rose-300' : 'bg-slate-800 text-slate-400'}`}>
                    {job.status}
                  </span>
                </div>
              </div>
            ))
          )
        )}
      </div>
    </div>
  )
}
