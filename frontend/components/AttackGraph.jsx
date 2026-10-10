import React, { useState, useEffect, useCallback } from 'react'
import ReactFlow, {
  Controls,
  Background,
  MarkerType,
  applyNodeChanges,
  applyEdgeChanges,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { reasoning, findings } from '../api/client'

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#64748b',
}

const ACTION_COLORS = {
  scan: '#00aaff',
  exploit_attempt: '#ff3366',
  credential_test: '#ffaa00',
  interpretation: '#aa44ff',
  finding: '#ff6600',
  host: '#00ff88',
  stop: '#666666',
}

export default function AttackGraph({ engagementId, onSelectFinding }) {
  const [nodes, setNodes] = useState([])
  const [edges, setEdges] = useState([])
  const [loading, setLoading] = useState(false)

  const onNodesChange = useCallback(
    (changes) => setNodes((nds) => applyNodeChanges(changes, nds)),
    []
  )

  const onEdgesChange = useCallback(
    (changes) => setEdges((eds) => applyEdgeChanges(changes, eds)),
    []
  )

  const handleNodeClick = useCallback(
    (_, node) => {
      if (node.id.startsWith('finding-') && onSelectFinding && node.data?.raw) {
        onSelectFinding(node.data.raw)
      }
    },
    [onSelectFinding]
  )

  useEffect(() => {
    if (!engagementId) return
    let isMounted = true
    setLoading(true)

    Promise.all([
      reasoning.trail(engagementId),
      findings.list(engagementId),
    ])
      .then(([trailRes, findingsRes]) => {
        if (!isMounted) return
        const trailData = trailRes?.data || []
        const findingsData = findingsRes?.data || []
        buildGraph(trailData, findingsData)
      })
      .catch((err) => {
        console.error('Failed to load attack graph data:', err)
      })
      .finally(() => {
        if (isMounted) setLoading(false)
      })

    return () => {
      isMounted = false
    }
  }, [engagementId])

  const buildGraph = (trail, items) => {
    const newNodes = []
    const newEdges = []

    // 1. Map Agent Reasoning & Action Trail
    trail.forEach((entry, i) => {
      const x = (i % 4) * 260 + 50
      const y = Math.floor(i / 4) * 180 + 50

      newNodes.push({
        id: `reason-${entry.id}`,
        position: { x, y },
        data: {
          label: (
            <div className="text-xs text-center select-none">
              <div className="font-bold tracking-wide uppercase text-[11px]">
                {entry.action_type || 'Action'}
              </div>
              <div className="text-gray-300 truncate max-w-[180px] font-mono text-[10px] mt-0.5">
                {entry.target || 'N/A'}
              </div>
              <div
                className={`mt-1.5 px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider ${
                  entry.status === 'executed'
                    ? 'bg-green-900/60 text-green-300 border border-green-700/50'
                    : entry.status === 'proposed'
                    ? 'bg-yellow-900/60 text-yellow-300 border border-yellow-700/50'
                    : entry.status === 'rejected'
                    ? 'bg-red-900/60 text-red-300 border border-red-700/50'
                    : 'bg-gray-800 text-gray-400'
                }`}
              >
                {entry.status}
              </div>
            </div>
          ),
        },
        style: {
          background: '#131b2e',
          border: `2px solid ${ACTION_COLORS[entry.action_type] || '#2d3b52'}`,
          borderRadius: '8px',
          padding: '10px',
          width: 210,
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.4)',
        },
      })

      // Link child actions to parent actions in the DAG
      if (entry.parent_event_id) {
        newEdges.push({
          id: `e-reason-${entry.parent_event_id}-${entry.id}`,
          source: `reason-${entry.parent_event_id}`,
          target: `reason-${entry.id}`,
          animated: entry.status === 'proposed',
          style: { stroke: '#4a5568', strokeWidth: 1.5 },
          markerEnd: { type: MarkerType.ArrowClosed, color: '#4a5568' },
        })
      }
    })

    // 2. Map Vulnerability Finding Nodes
    const startY = (Math.ceil(trail.length / 4) + 1) * 180 + 50

    items.forEach((finding, idx) => {
      const fid = `finding-${finding.id || idx}`
      const fx = (idx % 4) * 260 + 50
      const fy = startY + Math.floor(idx / 4) * 140

      const severity = (finding.severity || 'info').toLowerCase()
      const sevColor = SEVERITY_COLORS[severity] || SEVERITY_COLORS.info

      newNodes.push({
        id: fid,
        position: { x: fx, y: fy },
        data: {
          raw: finding,
          label: (
            <div className="text-xs text-left cursor-pointer select-none">
              <div className="flex items-center justify-between mb-1">
                <span
                  className="text-[9px] uppercase font-bold px-1.5 py-0.2 rounded text-slate-950"
                  style={{ backgroundColor: sevColor }}
                >
                  {severity}
                </span>
                {finding.cvss_score && (
                  <span className="text-[10px] font-mono text-gray-400">
                    CVSS {finding.cvss_score}
                  </span>
                )}
              </div>
              <div className="font-semibold text-slate-200 truncate max-w-[170px]">
                {finding.vuln_type || finding.title || 'Vulnerability'}
              </div>
              <div className="text-[10px] text-gray-400 font-mono truncate">
                {finding.parameter || finding.target_ip || 'Target Parameter'}
              </div>
            </div>
          ),
        },
        style: {
          background: '#0d1322',
          border: `2px solid ${sevColor}`,
          borderRadius: '8px',
          padding: '8px 10px',
          width: 210,
          boxShadow: `0 2px 10px ${sevColor}25`,
        },
      })

      // Link finding to associated tool execution event if reasoning ID is present
      if (finding.reasoning_id) {
        newEdges.push({
          id: `e-reason-${finding.reasoning_id}-${fid}`,
          source: `reason-${finding.reasoning_id}`,
          target: fid,
          animated: true,
          style: { stroke: sevColor, strokeWidth: 1.8 },
          markerEnd: { type: MarkerType.ArrowClosed, color: sevColor },
        })
      }
    })

    setNodes(newNodes)
    setEdges(newEdges)
  }

  return (
    <div className="h-[600px] w-full bg-[#070b14] rounded-lg border border-slate-800 overflow-hidden relative">
      {loading && (
        <div className="absolute inset-0 z-10 flex items-center justify-center bg-black/40 backdrop-blur-sm">
          <span className="text-xs text-slate-300 font-mono">Generating topological graph...</span>
        </div>
      )}
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        fitView
        proOptions={{ hideAttribution: true }}
        minZoom={0.2}
        maxZoom={1.5}
      >
        <Controls className="fill-slate-400 stroke-slate-400 bg-slate-900 border border-slate-700" />
        <Background color="#1e293b" gap={20} size={1} />
      </ReactFlow>
    </div>
  )
}