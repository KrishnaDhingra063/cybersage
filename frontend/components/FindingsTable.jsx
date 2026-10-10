import React, { useState, useEffect, useMemo } from 'react'
import { findings } from '../api/client'
import {
  AlertTriangle,
  Filter,
  Search,
  Wrench,
  ChevronDown,
  ChevronUp,
  ShieldAlert,
  Terminal,
  Download,
  CheckSquare,
  Square,
} from 'lucide-react'

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

const severityBadge = {
  critical: 'bg-rose-950/80 text-rose-300 border-rose-700/60',
  high: 'bg-orange-950/80 text-orange-300 border-orange-700/60',
  medium: 'bg-amber-950/80 text-amber-300 border-amber-700/60',
  low: 'bg-blue-950/80 text-blue-300 border-blue-700/60',
  info: 'bg-slate-800 text-slate-400 border-slate-700',
}

export default function FindingsTable({
  engagementId,
  onSelectFinding,
  onRequestFix,
}) {
  const [items, setItems] = useState([])
  const [filter, setFilter] = useState({ severity: '', status: '' })
  const [searchQuery, setSearchQuery] = useState('')
  const [expanded, setExpanded] = useState(null)
  const [loading, setLoading] = useState(false)
  const [page, setPage] = useState(1)
  const pageSize = 10
  const [selected, setSelected] = useState(new Set())

  useEffect(() => {
    if (!engagementId) return
    setLoading(true)
    findings
      .list(engagementId, filter)
      .then((r) => {
        const sorted = [...(r?.data || [])].sort(
          (a, b) =>
            (severityOrder[a.severity?.toLowerCase()] ?? 5) -
            (severityOrder[b.severity?.toLowerCase()] ?? 5)
        )
        setItems(sorted)
      })
      .catch((err) => console.error('Failed to load findings:', err))
      .finally(() => setLoading(false))
  }, [engagementId, filter])

  const markStatus = async (id, status) => {
    try {
      await findings.update(id, { status })
      setItems((prev) =>
        prev.map((f) => (f.id === id ? { ...f, status } : f))
      )
    } catch (err) {
      console.error('Failed to update finding status:', err)
    }
  }

  // Filter items in memory by keyword across vulnerability, parameter, and description
  const filteredItems = useMemo(() => {
    if (!searchQuery.trim()) return items
    const q = searchQuery.toLowerCase()
    return items.filter(
      (f) =>
        f.vuln_type?.toLowerCase().includes(q) ||
        f.parameter?.toLowerCase().includes(q) ||
        f.description?.toLowerCase().includes(q) ||
        f.source_tool?.toLowerCase().includes(q)
    )
  }, [items, searchQuery])

  const totalPages = Math.ceil(filteredItems.length / pageSize) || 1
  const paginated = useMemo(() => {
    const start = (page - 1) * pageSize
    return filteredItems.slice(start, start + pageSize)
  }, [filteredItems, page, pageSize])

  // Bulk helpers
  const toggleSelect = (id) => {
    setSelected((prev) => {
      const n = new Set(prev)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })
  }
  const toggleAll = () => {
    if (selected.size === paginated.length) setSelected(new Set())
    else setSelected(new Set(paginated.map((f) => f.id)))
  }
  const bulkMark = async (status) => {
    if (selected.size === 0) return
    try {
      await findings.bulkUpdate(Array.from(selected), status)
      setItems((prev) => prev.map((f) => (selected.has(f.id) ? { ...f, status } : f)))
      setSelected(new Set())
    } catch (e) {
      console.error(e)
    }
  }
  const doExport = async (fmt) => {
    try {
      if (fmt === "csv") {
        const r = await findings.exportCsv(engagementId)
        const url = window.URL.createObjectURL(new Blob([r.data]))
        const a = document.createElement("a")
        a.href = url
        a.download = `findings-${engagementId}.csv`
        a.click()
      } else {
        const r = await findings.exportSarif(engagementId)
        const blob = new Blob([JSON.stringify(r.data, null, 2)], { type: "application/json" })
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement("a")
        a.href = url
        a.download = `findings-${engagementId}.sarif`
        a.click()
      }
    } catch (e) {
      console.error(e)
    }
  }

  // Reset page when filter changes
  useEffect(() => { setPage(1); setSelected(new Set()) }, [filteredItems.length, filter, searchQuery])

  return (
    <div className="space-y-4">
      {/* Search & Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-pentest-900/60 p-3 rounded-lg border border-pentest-700">
        <div className="flex items-center gap-2 flex-1 min-w-[220px]">
          <Search size={16} className="text-gray-400" />
          <input
            type="text"
            placeholder="Search by vulnerability, parameter, or tool..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-pentest-950 border border-pentest-700 text-xs text-gray-200 rounded px-3 py-1.5 focus:outline-none focus:border-neon-blue font-mono"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter size={15} className="text-gray-400" />
          <select
            className="bg-pentest-950 border border-pentest-700 text-xs text-gray-300 rounded px-2.5 py-1.5 focus:outline-none focus:border-neon-blue"
            value={filter.severity}
            onChange={(e) => setFilter({ ...filter, severity: e.target.value })}
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>

          <select
            className="bg-pentest-950 border border-pentest-700 text-xs text-gray-300 rounded px-2.5 py-1.5 focus:outline-none focus:border-neon-blue"
            value={filter.status}
            onChange={(e) => setFilter({ ...filter, status: e.target.value })}
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="confirmed_duplicate">Duplicate</option>
            <option value="merged">Merged</option>
            <option value="fixed">Fixed</option>
            <option value="accepted_risk">Accepted Risk</option>
          </select>

          <span className="text-xs text-gray-400 font-mono ml-1">
            {filteredItems.length} findings
          </span>
          <div className="flex items-center gap-1.5 ml-2">
            <button onClick={() => doExport("csv")} className="flex items-center gap-1 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-1 rounded border border-slate-700"><Download size={12} /> CSV</button>
            <button onClick={() => doExport("sarif")} className="flex items-center gap-1 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-1 rounded border border-slate-700"><Download size={12} /> SARIF</button>
          </div>
        </div>
      </div>

      {/* Bulk bar */}
      <div className="flex flex-wrap items-center gap-2 bg-slate-900/40 p-2 rounded-lg border border-slate-800 text-xs">
        <button onClick={toggleAll} className="flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">
          {selected.size === paginated.length && paginated.length>0 ? <CheckSquare size={14} className="text-cyan-400" /> : <Square size={14} />} Select page ({selected.size})
        </button>
        <span className="text-slate-500">{selected.size} selected</span>
        <div className="flex gap-1 ml-2">
          {['fixed','accepted_risk','confirmed_duplicate'].map(s=>(
            <button key={s} onClick={()=>bulkMark(s)} disabled={selected.size===0} className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 border border-slate-700">Bulk {s.replace('_',' ')}</button>
          ))}
        </div>
        <span className="ml-auto text-slate-500">Page {page}/{totalPages} · {filteredItems.length} total</span>
      </div>

      {/* Findings List */}
      <div className="space-y-2">
        {paginated.map((f) => {
          const isExpanded = expanded === f.id
          const severity = (f.severity || 'info').toLowerCase()
          const badgeStyle = severityBadge[severity] || severityBadge.info

          return (
            <div
              key={f.id}
              className="card bg-pentest-900/80 border border-pentest-700 hover:border-pentest-500 transition-all rounded-lg p-3"
            >
              {/* Row Header */}
              <div
                className="flex items-center justify-between cursor-pointer select-none"
                onClick={() => setExpanded(isExpanded ? null : f.id)}
              >
                <div className="flex items-center gap-3">
                  <button onClick={(e)=>{e.stopPropagation(); toggleSelect(f.id)}} className="text-slate-400 hover:text-cyan-400">
                    {selected.has(f.id) ? <CheckSquare size={14} className="text-cyan-400" /> : <Square size={14} />}
                  </button>
                  <span
                    className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border font-mono ${badgeStyle}`}
                  >
                    {severity}
                  </span>
                  <span className="font-semibold text-sm text-slate-200">
                    {f.vuln_type}
                  </span>
                  {f.cvss_score && (
                    <span className="text-xs font-mono text-gray-400 bg-pentest-950 px-1.5 py-0.5 rounded border border-pentest-800">
                      CVSS {f.cvss_score}
                    </span>
                  )}
                  {f.parameter && (
                    <span className="text-xs font-mono text-cyan-400/90 truncate max-w-[200px]">
                      param: {f.parameter}
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono text-gray-400">
                    {f.source_tool || 'Engine'}
                  </span>
                  <span
                    className={`text-[11px] font-mono px-2 py-0.5 rounded uppercase border ${
                      f.status === 'open'
                        ? 'bg-emerald-950/60 text-emerald-400 border-emerald-700/60'
                        : f.status === 'fixed'
                        ? 'bg-blue-950/60 text-blue-400 border-blue-700/60'
                        : 'bg-gray-800 text-gray-400 border-gray-700'
                    }`}
                  >
                    {f.status}
                  </span>
                  <span className="text-gray-400">
                    {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                  </span>
                </div>
              </div>

              {/* Collapsible Details Drawer */}
              {isExpanded && (
                <div className="mt-3 pt-3 border-t border-pentest-700 space-y-3">
                  <p className="text-xs text-gray-300 leading-relaxed font-sans">
                    {f.description || 'No detailed description available.'}
                  </p>

                  {f.evidence && (
                    <div>
                      <p className="text-[11px] uppercase tracking-wider text-gray-400 mb-1 font-mono flex items-center gap-1">
                        <Terminal size={13} />
                        Proof of Concept Evidence:
                      </p>
                      <pre className="bg-black/70 border border-pentest-700 rounded p-2.5 text-xs text-gray-300 font-mono overflow-auto max-h-48 whitespace-pre-wrap">
                        {f.evidence.slice(0, 2500)}
                      </pre>
                    </div>
                  )}

                  {/* Operational Action Toolbar */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-pentest-800">
                    {/* Status Triage Gating */}
                    <div className="flex gap-1.5">
                      {['confirmed_duplicate', 'fixed', 'accepted_risk'].map((s) => (
                        <button
                          key={s}
                          onClick={(e) => {
                            e.stopPropagation()
                            markStatus(f.id, s)
                          }}
                          className="text-[11px] bg-pentest-800 border border-pentest-600 text-gray-300 px-2 py-1 rounded hover:bg-pentest-700 transition-colors font-mono"
                        >
                          Mark {s.replace('_', ' ')}
                        </button>
                      ))}
                    </div>

                    {/* AI Remediation Bridge */}
                    <div className="flex items-center gap-2">
                      {onRequestFix && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            onRequestFix(f)
                          }}
                          className="text-xs bg-cyan-700 hover:bg-cyan-600 text-white font-medium px-3 py-1 rounded flex items-center gap-1.5 shadow transition-colors"
                        >
                          <Wrench size={13} />
                          Generate Fix
                        </button>
                      )}
                      {onSelectFinding && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            onSelectFinding(f)
                          }}
                          className="text-xs bg-pentest-700 hover:bg-pentest-600 text-gray-200 font-medium px-2.5 py-1 rounded border border-pentest-500 transition-colors"
                        >
                          Inspect Graph Node
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )
        })}

        {!loading && filteredItems.length === 0 && (
          <div className="text-center py-12 text-gray-500">
            <AlertTriangle size={32} className="mx-auto mb-3 opacity-40 text-gray-400" />
            <p className="text-sm font-medium">No findings match current filters</p>
          </div>
        )}

        {/* Pagination */}
        <div className="flex items-center justify-center gap-2 pt-2">
          <button disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))} className="px-3 py-1 rounded bg-slate-800 text-slate-300 disabled:opacity-40 border border-slate-700 text-xs">Prev</button>
          <span className="text-xs text-slate-400 font-mono">Page {page} / {totalPages}</span>
          <button disabled={page >= totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))} className="px-3 py-1 rounded bg-slate-800 text-slate-300 disabled:opacity-40 border border-slate-700 text-xs">Next</button>
        </div>
      </div>
    </div>
  )
}