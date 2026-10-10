import React, { useState } from 'react'
import { CheckCircle2, Loader2, ShieldAlert, Clock, ChevronDown, ChevronRight } from 'lucide-react'

const toolIcons = {
  nmap: '🛰️', nuclei: '🧬', zap: '🕷️', crawler: '🕸️',
  shadow_api: '🔎', sqlmap: '💉', metasploit: '🧨', hashcat: '🔑', web_vuln_check: '🌐',
}

const statusMeta = {
  executed: { icon: CheckCircle2, color: 'text-green-400', border: 'border-green-700', label: 'Completed' },
  needs_approval: { icon: Clock, color: 'text-amber-400', border: 'border-amber-700', label: 'Needs approval' },
  blocked: { icon: ShieldAlert, color: 'text-rose-400', border: 'border-rose-700', label: 'Blocked by scope' },
  running: { icon: Loader2, color: 'text-cyan-400', border: 'border-cyan-700', label: 'Running' },
}

export default function ToolCard({ tool, expanded, onToggle }) {
  const meta = statusMeta[tool.status] || statusMeta.executed
  const Icon = meta.icon
  return (
    <div className={`border rounded-lg bg-slate-900/60 ${meta.border} overflow-hidden`}>
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-slate-800/40 transition-colors"
      >
        <span className="text-lg">{toolIcons[tool.tool] || '🔧'}</span>
        <Icon size={16} className={meta.color} />
        <span className="font-mono text-sm text-slate-200 flex-1 text-left">{tool.tool}</span>
        <span className="text-sm text-slate-400">{tool.summary || tool.message}</span>
        {tool.findings_count > 0 && (
          <span className="text-xs px-2 py-0.5 rounded-full bg-rose-900/40 text-rose-300">
            {tool.findings_count} finding{tool.findings_count > 1 ? 's' : ''}
          </span>
        )}
        {expanded ? <ChevronDown size={16} className="text-slate-500" /> : <ChevronRight size={16} className="text-slate-500" />}
      </button>
      {expanded && (
        <div className="px-4 pb-3 pt-1 space-y-2">
          {tool.message && (
            <pre className="bg-slate-950 rounded p-3 text-xs text-slate-400 overflow-auto max-h-32 whitespace-pre-wrap">
              {tool.message}
            </pre>
          )}
          {Array.isArray(tool.findings) && tool.findings.length > 0 ? (
            <div className="space-y-1.5">
              {tool.findings.map((f, i) => (
                <div key={i} className="flex items-start gap-2 rounded-lg bg-slate-950 border border-slate-800 px-2.5 py-1.5">
                  <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded shrink-0 ${
                    (f.severity || '').toLowerCase() === 'critical' ? 'bg-rose-950 text-rose-300'
                    : (f.severity || '').toLowerCase() === 'high' ? 'bg-orange-950 text-orange-300'
                    : (f.severity || '').toLowerCase() === 'medium' ? 'bg-amber-950 text-amber-300'
                    : 'bg-slate-800 text-slate-400'
                  }`}>
                    {f.severity || 'info'}
                  </span>
                  <div className="min-w-0">
                    <p className="text-xs text-slate-200 font-mono truncate">{f.vuln_type || 'finding'}</p>
                    {f.parameter && <p className="text-[11px] text-cyan-400/80 font-mono truncate">{f.parameter}</p>}
                    {f.description && <p className="text-[11px] text-slate-500 truncate">{f.description}</p>}
                  </div>
                </div>
              ))}
              <p className="text-[10px] text-slate-600">Full rows live in Findings Matrix / Remediation.</p>
            </div>
          ) : (
            !tool.message && <p className="text-xs text-slate-600">No extra details — see Findings Matrix for stored results.</p>
          )}
        </div>
      )}
    </div>
  )
}
