import React, { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { reports } from '../api/client'
import { FileText, Download, Copy, Check, Share2 } from 'lucide-react'

export default function ReportPreview() {
  const { id } = useParams()
  const [markdown, setMarkdown] = useState('')
  const [reportType, setReportType] = useState('technical')
  const [loading, setLoading] = useState(false)
  const [findingsCount, setFindingsCount] = useState(0)
  const [copied, setCopied] = useState(false)

  const generate = async () => {
    setLoading(true)
    try {
      const r = await reports.generate(id, reportType)
      setMarkdown(r.data.markdown)
      setFindingsCount(r.data.findings_count)
    } catch (e) {
      console.error(e)
    }
    setLoading(false)
  }

  useEffect(() => { generate() }, [reportType])

  const copyMarkdown = async () => {
    await navigator.clipboard.writeText(markdown)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  const downloadPdf = async () => {
    try {
      const r = await reports.downloadPdf(id, reportType)
      const url = window.URL.createObjectURL(new Blob([r.data], { type: "application/pdf" }))
      const a = document.createElement("a")
      a.href = url
      a.download = `report-${id}-${reportType}.pdf`
      a.click()
    } catch (e) {
      console.error(e)
      alert("PDF generation failed, try again")
    }
  }
  const shareLink = async () => {
    const url = `${window.location.origin}/engagement/${id}/report?type=${reportType}`
    await navigator.clipboard.writeText(url)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white tracking-wide">Report</h2>
          <p className="text-gray-400 text-sm">{findingsCount} findings included · Shareable link preserves type</p>
        </div>
        <div className="flex gap-2">
          <select
            className="input-field bg-slate-900 border border-slate-700 text-white rounded px-3 py-2 text-sm"
            value={reportType}
            onChange={e => setReportType(e.target.value)}
          >
            <option value="executive">Executive Summary</option>
            <option value="technical">Technical Detail</option>
            <option value="both">Full Report</option>
          </select>
          <button onClick={generate} disabled={loading} className="btn-primary flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-white px-3 py-2 rounded text-xs border border-slate-700">
            <FileText size={16} />
            {loading ? 'Generating...' : 'Regenerate'}
          </button>
          <button onClick={copyMarkdown} disabled={!markdown} className="flex items-center gap-1 px-3 py-2 rounded text-xs bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-40">
            {copied ? <Check size={14} /> : <Copy size={14} />} Copy MD
          </button>
          <button onClick={downloadPdf} disabled={!markdown} className="flex items-center gap-1 px-3 py-2 rounded text-xs bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-40">
            <Download size={14} /> PDF
          </button>
          <button onClick={shareLink} className="flex items-center gap-1 px-3 py-2 rounded text-xs bg-slate-800 hover:bg-slate-700 text-white border border-slate-700">
            <Share2 size={14} /> Link
          </button>
        </div>
      </div>

      <div className="card">
        <div className="prose prose-invert max-w-none">
          {markdown ? (
            <pre className="whitespace-pre-wrap text-sm text-gray-300 font-mono leading-relaxed">
              {markdown}
            </pre>
          ) : (
            <p className="text-gray-600">Generating report...</p>
          )}
        </div>
      </div>
    </div>
  )
}
