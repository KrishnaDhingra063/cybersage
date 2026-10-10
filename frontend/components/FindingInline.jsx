import React, { useState } from 'react'
import { AlertTriangle, Wand2, Shield, FileText, Loader, GitPullRequest, Check, X } from 'lucide-react'
import { fixes } from '../api/client'

const severityColor = {
  critical: 'bg-rose-600', high: 'bg-red-600', medium: 'bg-amber-600',
  low: 'bg-yellow-600', info: 'bg-slate-500',
}

export default function FindingInline({ finding, engagementId, isLead }) {
  const [fix, setFix] = useState(null)
  const [generating, setGenerating] = useState(false)
  const [showFix, setShowFix] = useState(false)
  const [prUrl, setPrUrl] = useState('')

  const generateFix = async () => {
    setGenerating(true)
    setShowFix(true)
    try {
      await fixes.generate(engagementId, finding.id)
      const r = await fixes.list(engagementId)
      const found = r.data.find(f => f.finding_id === finding.id)
      setFix(found || null)
      setPrUrl(found?.pr_url || '')
    } catch (e) {
      console.error(e)
      setFix({ lint_check: 'FAIL', explanation: 'Fix generation failed: ' + (e.response?.data?.detail || e.message || e) })
    }
    setGenerating(false)
  }

  const fixAction = async (action) => {
    if (!fix) return
    try {
      const r = await fixes[action](fix.id)
      if (r.data?.pr_url) setPrUrl(r.data.pr_url)
      const res = await fixes.list(engagementId)
      const found = res.data.find(f => f.finding_id === finding.id)
      setFix(found || null)
    } catch (e) {
      console.error(e)
    }
  }

  return (
    <div className="card overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3">
        <span className={`px-2 py-0.5 rounded text-xs font-bold text-white ${severityColor[finding.severity] || 'bg-slate-500'}`}>
          {finding.severity}
        </span>
        <span className="font-mono font-semibold text-slate-100 flex-1">{finding.vuln_type}</span>
        <span className="text-xs text-slate-500">{finding.source_tool}</span>
      </div>

      {finding.description && (
        <p className="px-4 pb-2 text-sm text-slate-300">{finding.description}</p>
      )}
      {finding.parameter && (
        <p className="px-4 pb-2 text-xs text-slate-500">param: {finding.parameter}</p>
      )}
      {finding.evidence && (
        <pre className="bg-slate-950 mx-4 mb-3 rounded p-2 text-xs text-slate-400 overflow-auto max-h-24">{finding.evidence}</pre>
      )}

      <div className="px-4 pb-3 flex items-center gap-2 border-t border-slate-800 pt-3">
        <button onClick={generateFix} disabled={generating}
          className="btn-primary text-xs flex items-center gap-2">
          <Wand2 size={13} /> {generating ? <Loader size={13} className="animate-spin" /> : 'Generate Fix'}
        </button>
        {fix && fix.git_diff && (
          <span className="text-xs text-green-400 flex items-center gap-1"><Check size={12} /> fix ready</span>
        )}
      </div>

      {showFix && (
        <div className="px-4 pb-4 space-y-3">
          {generating && (
            <p className="text-xs text-slate-400 flex items-center gap-2">
              <Loader size={12} className="animate-spin" /> Generating AI fix suggestion…
            </p>
          )}
          {!generating && fix && (
            <>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-green-400 flex items-center gap-1"><Shield size={12} /> Proposed fix</span>
                <span className={`text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300`}>{fix.status}</span>
                {fix.lint_check && <span className="text-xs text-slate-500">{fix.lint_check}</span>}
              </div>

              {fix.git_diff && (
                <div>
                  <p className="text-xs text-slate-500 mb-1 flex items-center gap-1"><FileText size={11} /> Patch</p>
                  <pre className="bg-slate-950 rounded p-2 text-xs text-green-400 overflow-auto max-h-48">{fix.git_diff}</pre>
                </div>
              )}
              {fix.waf_rule && (
                <div>
                  <p className="text-xs text-slate-500 mb-1 flex items-center gap-1"><Shield size={11} /> WAF shield ({fix.waf_engine})</p>
                  <pre className="bg-slate-950 rounded p-2 text-xs text-slate-300 overflow-auto max-h-32">{fix.waf_rule}</pre>
                </div>
              )}
              {fix.explanation && (
                <p className="text-xs text-slate-400">{fix.explanation}</p>
              )}

              {fix.pr_url && (
                <a href={fix.pr_url} target="_blank" rel="noreferrer" className="text-xs text-green-400 hover:underline">
                  PR opened: {fix.pr_url}
                </a>
              )}
              {prUrl && !fix.pr_url && (
                <a href={prUrl} target="_blank" rel="noreferrer" className="text-xs text-green-400 hover:underline">
                  PR opened: {prUrl}
                </a>
              )}
              {isLead && fix.status === 'suggested' && (
                <div className="flex gap-2">
                  <button onClick={() => fixAction('approve')} className="btn-primary text-xs flex items-center gap-1">
                    <Check size={12} /> Approve
                  </button>
                  <button onClick={() => fixAction('reject')} className="btn-danger text-xs flex items-center gap-1">
                    <X size={12} /> Reject
                  </button>
                </div>
              )}
              {isLead && fix.status === 'approved' && (
                <div className="flex gap-2">
                  <button onClick={() => fixAction('apply')} className="btn-primary text-xs">Mark Applied</button>
                  <button onClick={() => fixAction('createPR')} className="btn-secondary text-xs flex items-center gap-1">
                    <GitPullRequest size={12} /> 1-Click PR
                  </button>
                </div>
              )}
            </>
          )}
          {!generating && !fix && (
            <p className="text-xs text-slate-500">No fix available yet.</p>
          )}
        </div>
      )}
    </div>
  )
}
