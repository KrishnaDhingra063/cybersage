import React, { useState, useEffect } from "react";
import { Clock, AlertTriangle, Shield, Activity, TrendingUp, Layers } from "lucide-react";
import { engagements, reasoning, findings } from "../api/client";
import api from "../api/client";

export default function DashboardCards({ engagementId }) {
  const [stats, setStats] = useState(null);
  const [engList, setEngList] = useState([]);
  const [queueCount, setQueueCount] = useState(null);
  const [summary, setSummary] = useState(null);

  useEffect(() => {
    // Global stats
    api.get("/stats").then((r) => setStats(r.data)).catch(() => {});
    engagements.list().then((r) => setEngList(r.data?.slice(0, 3) || [])).catch(() => {});
  }, []);

  useEffect(() => {
    if (!engagementId) return;
    reasoning.queue(engagementId).then((r) => setQueueCount(r.data?.length ?? 0)).catch(() => setQueueCount(0));
    findings.summary(engagementId).then((r) => setSummary(r.data)).catch(() => {});
  }, [engagementId]);

  const peak = summary ? Math.max(...Object.entries(summary.by_severity || {}).map(([k, v]) => (k === "critical" ? v * 10 : k === "high" ? v * 7 : 0)), 0) : null;

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {/* Recent */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3">
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <Clock size={14} className="text-cyan-400" /> Recent Engagements
        </div>
        <div className="mt-2 space-y-1">
          {engList.length === 0 ? (
            <p className="text-xs text-slate-500">No recent</p>
          ) : (
            engList.map((e) => (
              <div key={e.id} className="text-xs text-slate-200 truncate">
                {e.name} <span className="text-slate-500">· {e.status}</span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Queue */}
      <div className="rounded-xl border border-amber-900/40 bg-amber-950/20 p-3">
        <div className="flex items-center gap-2 text-xs text-amber-300">
          <AlertTriangle size={14} /> Approval Queue
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-xl font-bold text-amber-300">{queueCount ?? "—"}</span>
          <span className="text-xs text-amber-200/70">awaiting Lead</span>
        </div>
        {queueCount > 0 && <p className="text-[11px] text-amber-400 mt-1">Needs review before exploit</p>}
      </div>

      {/* Findings */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3">
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <Layers size={14} className="text-violet-400" /> Findings
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-xl font-bold text-slate-100">{summary?.total ?? stats?.findings ?? "—"}</span>
          <span className="text-xs text-slate-500">total</span>
        </div>
        {summary && (
          <div className="text-[11px] text-slate-400 mt-1">
            C:{summary.by_severity?.critical || 0} H:{summary.by_severity?.high || 0} M:{summary.by_severity?.medium || 0}
          </div>
        )}
      </div>

      {/* CVSS Trend */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3">
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <TrendingUp size={14} className="text-emerald-400" /> Peak Risk
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-xl font-bold text-emerald-300">{summary ? (summary.by_severity?.critical > 0 ? "Critical" : summary.by_severity?.high > 0 ? "High" : "Low") : stats ? `${stats.findings} findings` : "—"}</span>
        </div>
        <p className="text-[11px] text-slate-500 mt-1">via findings/summary + stats</p>
      </div>
    </div>
  );
}
