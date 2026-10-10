import React, { useMemo } from 'react'

const severityColor = {
  critical: '#f43f5e', high: '#ef4444', medium: '#f59e0b', low: '#eab308', info: '#64748b',
}

export default function MiniGraph({ nodes = [], edges = [] }) {
  const layout = useMemo(() => {
    // Simple horizontal layered layout: reasoning nodes then findings.
    const reasoning = nodes.filter(n => n.type === 'reasoning')
    const findings = nodes.filter(n => n.type === 'finding')
    const pos = {}
    const W = 120, H = 56, PAD = 10
    const setRow = (list, y) => list.forEach((n, i) => {
      pos[n.id] = { x: PAD + i * (W + 20), y }
    })
    setRow(reasoning, 10)
    setRow(findings, 10 + H + 30)
    const edgesSet = new Set(edges.map(e => `${e.source}|${e.target}`))
    return { pos, reasoning, findings, W, H, edgesSet }
  }, [nodes, edges])

  const width = useMemo(() => {
    const maxX = Object.values(layout.pos).reduce((m, p) => Math.max(m, p.x), 0)
    return maxX + layout.W + 20
  }, [layout])

  return (
    <div className="overflow-auto">
      {nodes.length === 0 ? (
        <p className="text-xs text-slate-600 text-center py-10">No attack path yet.</p>
      ) : (
        <svg width={width} height="170">
          {edges.map((e, i) => {
            const s = layout.pos[e.source], t = layout.pos[e.target]
            if (!s || !t) return null
            return <line key={i} x1={s.x + layout.W / 2} y1={s.y + layout.H / 2}
              x2={t.x + layout.W / 2} y2={t.y + layout.H / 2} stroke="#334155" strokeWidth="1" />
          })}
          {nodes.map(n => {
            const p = layout.pos[n.id]
            if (!p) return null
            const isFinding = n.type === 'finding'
            const fill = isFinding ? (severityColor[n.data?.severity] || '#475569') : '#0e7490'
            return (
              <g key={n.id}>
                <rect x={p.x} y={p.y} width={layout.W} height={layout.H} rx="8"
                  fill={fill} fillOpacity="0.15" stroke={fill} strokeWidth="1.5" />
                <text x={p.x + 8} y={p.y + 18} fontSize="11" fill={fill} fontWeight="600">
                  {n.data?.label?.split('\n')[0]?.slice(0, 16)}
                </text>
                <text x={p.x + 8} y={p.y + 36} fontSize="9" fill="#94a3b8">
                  {(n.data?.reasoning || n.data?.description || '').slice(0, 22)}
                </text>
              </g>
            )
          })}
        </svg>
      )}
    </div>
  )
}
