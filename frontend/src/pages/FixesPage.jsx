import React, { useState, useEffect } from 'react'
import { engagements, findings, fixes } from '../api/client'
import { useAuth } from '../auth'
import {
  Wand2,
  GitPullRequest,
  CheckCircle,
  XCircle,
  FileText,
  Terminal,
  Shield,
  ShieldCheck,
  RefreshCw,
  Code,
  Copy,
  Check,
  ExternalLink,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'

const statusColors = {
  suggested: 'bg-yellow-900/50 text-yellow-300 border border-yellow-700',
  approved: 'bg-green-900/50 text-green-300 border border-green-700',
  rejected: 'bg-red-900/50 text-red-300 border border-red-700',
  applied: 'bg-blue-900/50 text-blue-300 border border-blue-700',
  verified: 'bg-teal-900/50 text-teal-300 border border-teal-700',
  failed_lint: 'bg-rose-900/50 text-rose-300 border border-rose-700',
}

export default function FixesPage() {
  const { isLead } = useAuth()
  const [engList, setEngList] = useState([])
  const [engagementId, setEngagementId] = useState('')
  const [findingsList, setFindingsList] = useState([])
  const [fixesList, setFixesList] = useState([])
  const [selectedFinding, setSelectedFinding] = useState('')
  const [styleRules, setStyleRules] = useState('')
  const [generating, setGenerating] = useState(false)
  const [generateError, setGenerateError] = useState('')
  const [expanded, setExpanded] = useState(null)
  const [copiedId, setCopiedId] = useState('')
  const [wafView, setWafView] = useState({})
  
  // GitHub PR modal configuration state
  const [prModalFix, setPrModalFix] = useState(null)
  const [targetRepo, setTargetRepo] = useState('')
  const [baseBranch, setBaseBranch] = useState('main')
  const [dispatchingPr, setDispatchingPr] = useState(false)
  const [verifyingId, setVerifyingId] = useState(null)
  const [verifyResults, setVerifyResults] = useState({})

  useEffect(() => {
    engagements.list().then((r) => setEngList(r.data || []))
  }, [])

  useEffect(() => {
    if (!engagementId) return
    findings.list(engagementId).then((r) => setFindingsList(r.data || []))
    fixes.list(engagementId).then((r) => setFixesList(r.data || []))
    fixes
      .listStyles(engagementId)
      .then((r) => {
        if (r.data?.length) setStyleRules(r.data[0].style_rules)
      })
      .catch(() => {})
  }, [engagementId])

  const generate = async () => {
    if (!engagementId || !selectedFinding) return
    setGenerating(true)
    setGenerateError('')
    try {
      await fixes.generate(engagementId, selectedFinding, styleRules || undefined)
      const r = await fixes.list(engagementId)
      setFixesList(r.data || [])
    } catch (e) {
      console.error('Failed to generate fix:', e)
      setGenerateError(e.response?.data?.detail || e.message || 'Failed to generate fix')
    }
    setGenerating(false)
  }

  const saveStyle = async () => {
    await fixes.saveStyle({
      engagement_id: engagementId,
      name: 'default',
      style_rules: styleRules,
    })
  }

  const runFixAction = async (id, action) => {
    try {
      await fixes[action](id)
      const r = await fixes.list(engagementId)
      setFixesList(r.data || [])
    } catch (e) {
      console.error(`Failed to execute ${action}:`, e)
    }
  }

  const runVerify = async (id) => {
    setVerifyingId(id)
    try {
      const res = await fixes.verify(id)
      setVerifyResults((prev) => ({ ...prev, [id]: res.data }))
      const r = await fixes.list(engagementId)
      setFixesList(r.data || [])
    } catch (e) {
      console.error('Failed to verify fix:', e)
      setVerifyResults((prev) => ({ ...prev, [id]: { status: 'error', detail: e.response?.data?.detail || e.message } }))
    } finally {
      setVerifyingId(null)
    }
  }

  const handleOpenPr = async () => {
    if (!prModalFix || !targetRepo) return
    setDispatchingPr(true)
    try {
      await fixes.createPR(prModalFix.id, {
        owner_repo: targetRepo,
        base_branch: baseBranch || 'main',
      })
      const r = await fixes.list(engagementId)
      setFixesList(r.data || [])
      setPrModalFix(null)
    } catch (e) {
      console.error('Failed to create Pull Request:', e)
    } finally {
      setDispatchingPr(false)
    }
  }

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text)
    setCopiedId(key)
    setTimeout(() => setCopiedId(''), 2000)
  }

  // Syntax highlighting for Unified Git Diff
  const renderUnifiedDiff = (diffText) => {
    if (!diffText) return <span className="text-gray-500"># No diff generated</span>
    return diffText.split('\n').map((line, idx) => {
      let lineClass = 'text-gray-300'
      if (line.startsWith('+') && !line.startsWith('+++')) {
        lineClass = 'bg-emerald-950/60 text-emerald-300 block px-1'
      } else if (line.startsWith('-') && !line.startsWith('---')) {
        lineClass = 'bg-rose-950/60 text-rose-300 block px-1'
      } else if (line.startsWith('@@')) {
        lineClass = 'text-cyan-400 font-bold block px-1'
      }
      return (
        <span key={idx} className={lineClass}>
          {line}
          {'\n'}
        </span>
      )
    })
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-bold text-white tracking-wide">Remediation Center</h2>
          <p className="text-gray-400 mt-1 text-sm">
            AST-validated AI code patches, unified diffs, WAF shields & automated GitHub PR orchestration
          </p>
        </div>
        <select
          className="input-field w-72 bg-pentest-900 border border-pentest-700 text-sm text-gray-200 rounded px-3 py-2"
          value={engagementId}
          onChange={(e) => {
            setEngagementId(e.target.value)
            setExpanded(null)
          }}
        >
          <option value="">Select engagement…</option>
          {engList.map((e) => (
            <option key={e.id} value={e.id}>
              {e.name}
            </option>
          ))}
        </select>
      </div>

      {engagementId && (
        <>
          {/* Patch Synthesis Studio */}
          <div className="card bg-pentest-900 border border-pentest-700 rounded-xl p-5 space-y-4">
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              <Wand2 size={18} className="text-neon-green" />x
              Synthesize AI Remediation Patch
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="md:col-span-2">
                <label className="block text-xs uppercase font-mono text-gray-400 mb-1">
                  Target Finding
                </label>
                <select
                  className="input-field w-full bg-pentest-950 border border-pentest-700 text-xs text-gray-200 rounded p-2.5"
                  value={selectedFinding}
                  onChange={(e) => setSelectedFinding(e.target.value)}
                >
                  <option value="">Select a finding…</option>
                  {findingsList.map((f) => (
                    <option key={f.id} value={f.id}>
                      [{f.severity?.toUpperCase()}] {f.vuln_type} — {f.description?.slice(0, 75)}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-end">
                <button
                  onClick={generate}
                  disabled={generating || !selectedFinding}
                  className="btn-primary w-full flex items-center justify-center gap-2 py-2.5 text-xs font-semibold rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 transition-colors"
                >
                  <Wand2 size={14} /> {generating ? 'Synthesizing...' : 'Generate Fix'}
                </button>
              </div>
            </div>
            {generateError && (
              <div className="rounded-lg border border-rose-800 bg-rose-950/40 px-3 py-2 text-xs text-rose-300">
                {generateError}
              </div>
            )}

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs uppercase font-mono text-gray-400">
                  Coding Style Guide {isLead ? '(Lead Editable)' : '(View Only)'}
                </label>
                {isLead && (
                  <button
                    onClick={saveStyle}
                    className="text-xs text-cyan-400 hover:underline font-mono"
                  >
                    Save Style Guide
                  </button>
                )}
              </div>
              <textarea
                className="input-field w-full font-mono text-xs bg-pentest-950 border border-pentest-700 rounded p-2.5 text-gray-300"
                rows={3}
                value={styleRules}
                onChange={(e) => isLead && setStyleRules(e.target.value)}
                readOnly={!isLead}
                placeholder="e.g. Use parameterized queries; sanitize HTML input; keep patches minimal..."
              />
            </div>
          </div>

          {/* Generated Fixes Ledger */}
          <div className="space-y-4">
            {fixesList.length === 0 && (
              <div className="text-center py-16 text-gray-600">
                <Code size={48} className="mx-auto mb-3 opacity-40 text-gray-400" />
                <p className="text-sm font-medium">No remediations generated yet</p>
                <p className="text-xs text-gray-500 mt-1">
                  Select a confirmed finding above to generate unified diffs and edge rules.
                </p>
              </div>
            )}

            {fixesList.map((fix) => {
              const isExpanded = expanded === fix.id
              return (
                <div
                  key={fix.id}
                  className="card bg-pentest-900 border border-pentest-700 rounded-xl p-4 transition-all"
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-sm text-cyan-400 font-semibold">
                        {fix.file_path || 'Perimeter Shield'}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-mono uppercase ${
                          statusColors[fix.status] || 'bg-gray-800 text-gray-400'
                        }`}
                      >
                        {fix.status}
                      </span>
                      {fix.language && (
                        <span className="text-xs font-mono text-gray-500 bg-pentest-950 px-1.5 py-0.5 rounded border border-pentest-800">
                          {fix.language}
                        </span>
                      )}
                      {fix.lint_check && (
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono border ${fix.lint_check.startsWith('PASS') ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800' : fix.lint_check.startsWith('FAIL') ? 'bg-rose-950/60 text-rose-300 border-rose-800' : 'bg-slate-800 text-slate-400 border-slate-700'}`}>
                          {fix.lint_check.startsWith('PASS') ? '✓ PASS' : fix.lint_check.startsWith('FAIL') ? '✗ FAIL' : '• SKIP'} {fix.lint_check.slice(0,30)}
                        </span>
                      )}
                    </div>

                    {/* RBAC-governed Actions */}
                    <div className="flex items-center gap-2">
                      {isLead && fix.status === 'suggested' && (
                        <>
                          <button
                            onClick={() => runFixAction(fix.id, 'approve')}
                            className="text-xs bg-emerald-700 hover:bg-emerald-600 text-white font-medium px-2.5 py-1 rounded flex items-center gap-1 transition-colors"
                          >
                            <CheckCircle size={13} /> Approve
                          </button>
                          <button
                            onClick={() => runFixAction(fix.id, 'reject')}
                            className="text-xs bg-rose-800 hover:bg-rose-700 text-white font-medium px-2.5 py-1 rounded flex items-center gap-1 transition-colors"
                          >
                            <XCircle size={13} /> Reject
                          </button>
                        </>
                      )}

                      {isLead && fix.status === 'approved' && (
                        <>
                          <button
                            onClick={() => runFixAction(fix.id, 'apply')}
                            className="text-xs bg-blue-700 hover:bg-blue-600 text-white font-medium px-2.5 py-1 rounded transition-colors"
                          >
                            Mark Applied
                          </button>
                          <button
                            onClick={() => {
                              setPrModalFix(fix)
                              setTargetRepo('')
                            }}
                            className="text-xs bg-purple-700 hover:bg-purple-600 text-white font-medium px-3 py-1 rounded flex items-center gap-1.5 shadow transition-colors"
                          >
                            <GitPullRequest size={13} /> 1-Click PR
                          </button>
                        </>
                      )}

                      {['approved', 'applied', 'verified'].includes(fix.status) && (
                        <button
                          onClick={() => runVerify(fix.id)}
                          disabled={verifyingId === fix.id}
                          className="text-xs bg-teal-700 hover:bg-teal-600 disabled:opacity-50 text-white font-medium px-2.5 py-1 rounded flex items-center gap-1 transition-colors"
                        >
                          {verifyingId === fix.id ? (
                            <><RefreshCw size={13} className="animate-spin" /> Verifying...</>
                          ) : fix.status === 'verified' ? (
                            <><ShieldCheck size={13} /> Re-Verify</>
                          ) : (
                            <><ShieldCheck size={13} /> Verify Fix</>
                          )}
                        </button>
                      )}

                      <button
                        onClick={() => setExpanded(isExpanded ? null : fix.id)}
                        className="text-xs bg-pentest-800 hover:bg-pentest-700 text-gray-300 px-3 py-1 rounded border border-pentest-600 font-mono flex items-center gap-1"
                      >
                        {isExpanded ? (
                          <>
                            Hide <ChevronUp size={13} />
                          </>
                        ) : (
                          <>
                            Details <ChevronDown size={13} />
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Collapsed verify summary (always visible after verify) */}
                  {verifyResults[fix.id] && !isExpanded && (
                    <div className={`mt-3 rounded-lg border px-3 py-2 text-xs font-sans ${
                      verifyResults[fix.id].status === 'verified' ? 'bg-teal-950/30 border-teal-800 text-teal-300' :
                      verifyResults[fix.id].status === 'still_vulnerable' ? 'bg-amber-950/30 border-amber-800 text-amber-300' :
                      'bg-rose-950/30 border-rose-800 text-rose-300'
                    }`}>
                      <span className="font-semibold">{verifyResults[fix.id].status === 'verified' ? '✓ Verified' : verifyResults[fix.id].status === 'still_vulnerable' ? '✗ Still vulnerable' : '⚠ ' + verifyResults[fix.id].status}</span>
                      <span className="opacity-80"> — {verifyResults[fix.id].detail || verifyResults[fix.id].reason}</span>
                    </div>
                  )}

                  {/* Expandable Artifact Dossier */}
                  {isExpanded && (
                    <div className="mt-4 pt-4 border-t border-pentest-800 space-y-4 text-xs font-mono">
                      {/* Verify Result Banner */}
                      {verifyResults[fix.id] && (
                        <div className={`rounded-lg border p-3 text-xs font-sans leading-relaxed ${
                          verifyResults[fix.id].status === 'verified' ? 'bg-teal-950/50 border-teal-800 text-teal-300' :
                          verifyResults[fix.id].status === 'still_vulnerable' ? 'bg-amber-950/50 border-amber-800 text-amber-300' :
                          verifyResults[fix.id].status === 'blocked' ? 'bg-slate-800 border-slate-700 text-slate-300' :
                          'bg-rose-950/50 border-rose-800 text-rose-300'
                        }`}>
                          <p className="font-semibold flex items-center gap-1.5">
                            {verifyResults[fix.id].status === 'verified' && <><ShieldCheck size={14} /> Verified Fixed</>}
                            {verifyResults[fix.id].status === 'still_vulnerable' && <><Shield size={14} /> Still Vulnerable</>}
                            {verifyResults[fix.id].status === 'error' && <>⚠ Verify Error</>}
                            {verifyResults[fix.id].status === 'blocked' && <>⛔ Blocked (Out of Scope)</>}
                            <span className="font-mono text-[11px] opacity-70">via {verifyResults[fix.id].tool} on {verifyResults[fix.id].target}</span>
                          </p>
                          <p className="mt-1 text-[11px] opacity-90">{verifyResults[fix.id].detail || verifyResults[fix.id].reason}</p>
                          {verifyResults[fix.id].new_findings_count !== undefined && (
                            <p className="text-[10px] opacity-60 mt-1">new findings this scan: {verifyResults[fix.id].new_findings_count} · finding {verifyResults[fix.id].finding_status} · fix {verifyResults[fix.id].fix_status}</p>
                          )}
                        </div>
                      )}
                      {fix.status === 'verified' && !verifyResults[fix.id] && (
                        <div className="rounded-lg border bg-teal-950/30 border-teal-800 text-teal-300 p-2.5 text-xs font-sans flex items-center gap-1.5">
                          <ShieldCheck size={14} /> Already verified — re-run Verify to re-scan target
                        </div>
                      )}
                      {/* AST Lint Validation Check */}
                      {fix.lint_check && (
                        <div>
                          <p className="text-[11px] text-gray-400 mb-1 flex items-center gap-1 font-sans">
                            <Shield size={13} className="text-emerald-400" />
                            AST Lint & Syntax Validation
                          </p>
                          <pre className="bg-black/60 border border-pentest-800 rounded p-2.5 text-slate-300 overflow-x-auto whitespace-pre-wrap text-[11px]">
                            {fix.lint_check}
                          </pre>
                        </div>
                      )}

                      {/* Explanation */}
                      {fix.explanation && (
                        <div>
                          <p className="text-[11px] text-gray-400 mb-1 font-sans font-semibold">
                            Remediation Rationale
                          </p>
                          <p className="text-gray-300 font-sans leading-relaxed text-xs bg-pentest-950 p-2.5 rounded border border-pentest-800">
                            {fix.explanation}
                          </p>
                        </div>
                      )}

                      {/* Interactive Unified Git Diff */}
                      {fix.git_diff && (
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <p className="text-[11px] text-gray-400 flex items-center gap-1 font-sans">
                              <FileText size={13} className="text-cyan-400" />
                              Unified Git Diff
                            </p>
                            <button
                              onClick={() => copyToClipboard(fix.git_diff, `diff-${fix.id}`)}
                              className="text-[10px] text-gray-400 hover:text-white flex items-center gap-1 font-mono"
                            >
                              {copiedId === `diff-${fix.id}` ? (
                                <>
                                  <Check size={11} className="text-emerald-400" /> Copied
                                </>
                              ) : (
                                <>
                                  <Copy size={11} /> Copy Diff
                                </>
                              )}
                            </button>
                          </div>
                          <pre className="bg-black/80 border border-pentest-800 rounded p-3 overflow-x-auto max-h-72 text-[11px] leading-relaxed">
                            <code>{renderUnifiedDiff(fix.git_diff)}</code>
                          </pre>
                        </div>
                      )}

                      {/* Perimeter WAF Rule with toggle */}
                      {fix.waf_rule && (
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <div className="flex items-center gap-2">
                              <p className="text-[11px] text-gray-400 flex items-center gap-1 font-sans">
                                <Shield size={13} className="text-amber-400" />
                                Virtual WAF Rule
                              </p>
                              <div className="flex rounded overflow-hidden border border-slate-700 text-[10px] font-mono">
                                {['nginx','cloudflare'].map((eng) => (
                                  <button key={eng} onClick={() => setWafView((p)=>({...p,[fix.id]:eng}))} className={`px-2 py-0.5 ${((wafView[fix.id]||fix.waf_engine||'nginx')===eng)?'bg-amber-600 text-white':'bg-slate-800 text-slate-400'}`}>{eng}</button>
                                ))}
                              </div>
                            </div>
                            <button
                              onClick={() => copyToClipboard(fix.waf_rule, `waf-${fix.id}`)}
                              className="text-[10px] text-gray-400 hover:text-white flex items-center gap-1 font-mono"
                            >
                              {copiedId === `waf-${fix.id}` ? (
                                <>
                                  <Check size={11} className="text-emerald-400" /> Copied
                                </>
                              ) : (
                                <>
                                  <Copy size={11} /> Copy WAF Rule
                                </>
                              )}
                            </button>
                          </div>
                          <pre className="bg-black/80 border border-pentest-800 rounded p-3 overflow-x-auto max-h-40 text-amber-300 text-[11px]">
                            {fix.waf_rule}
                          </pre>
                        </div>
                      )}

                      {/* Proof of Concept / cURL Replay */}
                      {fix.curl_replay && (
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <p className="text-[11px] text-gray-400 flex items-center gap-1 font-sans">
                              <Terminal size={13} className="text-neon-blue" />
                              Verification Replay (cURL)
                            </p>
                            <button
                              onClick={() => copyToClipboard(fix.curl_replay, `curl-${fix.id}`)}
                              className="text-[10px] text-gray-400 hover:text-white flex items-center gap-1 font-mono"
                            >
                              {copiedId === `curl-${fix.id}` ? (
                                <>
                                  <Check size={11} className="text-emerald-400" /> Copied
                                </>
                              ) : (
                                <>
                                  <Copy size={11} /> Copy cURL
                                </>
                              )}
                            </button>
                          </div>
                          <pre className="bg-black/80 border border-pentest-800 rounded p-3 overflow-x-auto text-emerald-400 text-[11px]">
                            {fix.curl_replay}
                          </pre>
                        </div>
                      )}

                      {/* Active PR Link */}
                      {fix.pr_url && (
                        <div className="pt-2 border-t border-pentest-800">
                          <a
                            href={fix.pr_url}
                            target="_blank"
                            rel="noreferrer"
                            className="text-xs text-emerald-400 hover:underline flex items-center gap-1 font-mono"
                          >
                            <ExternalLink size={13} />
                            Pull Request Active: {fix.pr_url}
                          </a>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </>
      )}

      {/* GitHub PR Dispatch Modal (Lead Only) */}
      {prModalFix && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-pentest-900 border border-pentest-700 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-2 text-white font-bold text-lg">
              <GitPullRequest size={20} className="text-purple-400" />
              Open Remediation Pull Request
            </div>

            <p className="text-xs text-gray-300">
              The platform will branch the repository, commit the validated diff, and open a PR with CVSS metrics and WAF documentation.
            </p>

            <div className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-gray-400 mb-1">Target Repository (owner/repo)</label>
                <input
                  type="text"
                  placeholder="e.g. org/security-backend"
                  value={targetRepo}
                  onChange={(e) => setTargetRepo(e.target.value)}
                  className="w-full bg-pentest-950 border border-pentest-700 rounded p-2 text-white focus:outline-none focus:border-purple-500"
                />
              </div>

              <div>
                <label className="block text-gray-400 mb-1">Base Branch</label>
                <input
                  type="text"
                  value={baseBranch}
                  onChange={(e) => setBaseBranch(e.target.value)}
                  className="w-full bg-pentest-950 border border-pentest-700 rounded p-2 text-white focus:outline-none focus:border-purple-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-pentest-800">
              <button
                disabled={dispatchingPr}
                onClick={() => setPrModalFix(null)}
                className="px-3 py-1.5 text-xs text-gray-300 hover:text-white bg-pentest-800 rounded transition-colors"
              >
                Cancel
              </button>
              <button
                disabled={dispatchingPr || !targetRepo}
                onClick={handleOpenPr}
                className="px-4 py-1.5 text-xs bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-semibold rounded flex items-center gap-1.5 shadow transition-colors"
              >
                <GitPullRequest size={14} />
                {dispatchingPr ? 'Opening PR...' : 'Dispatch PR'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}