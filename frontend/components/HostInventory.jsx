import React, { useState, useEffect } from "react";
import { Server, Layers, Cpu, Globe, Shield } from "lucide-react";
import { engagements } from "../api/client";

export default function HostInventory({ engagementId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!engagementId) return;
    setLoading(true);
    engagements.inventory(engagementId)
      .then((r) => setData(r.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [engagementId]);

  if (loading) return <p className="text-xs text-slate-500">Loading inventory...</p>;
  if (!data || data.total_hosts === 0) return <p className="text-xs text-slate-500">No hosts discovered yet. Run a scan to populate inventory.</p>;

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-xs text-slate-400">
        <Server size={14} className="text-cyan-400" /> {data.total_hosts} hosts · {data.total_services} services
      </div>
      {data.hosts.map((h) => (
        <div key={h.id} className="rounded-lg border border-slate-800 bg-slate-900/40 p-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe size={14} className="text-emerald-400" />
              <span className="text-sm font-mono text-slate-200">{h.ip_address}</span>
              {h.hostname && <span className="text-xs text-slate-400">{h.hostname}</span>}
              {h.os_guess && <span className="text-xs bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded border border-slate-700">{h.os_guess}</span>}
            </div>
            <span className={`text-[10px] px-1.5 py-0.5 rounded uppercase font-bold ${h.status === "up" ? "bg-emerald-950 text-emerald-300 border border-emerald-800" : "bg-slate-800 text-slate-400"}`}>{h.status || "up"}</span>
          </div>
          {h.services.length > 0 ? (
            <div className="mt-2 grid gap-1.5">
              {h.services.map((s) => (
                <div key={s.id} className="flex items-center gap-2 text-xs bg-slate-950/60 border border-slate-800 rounded px-2 py-1.5">
                  <Layers size={12} className="text-violet-400" />
                  <span className="font-mono text-slate-200">{s.port}/{s.protocol}</span>
                  <span className="text-slate-300">{s.service_name}</span>
                  {s.version && <span className="text-slate-500">{s.version}</span>}
                  {s.banner && <span className="text-slate-500 truncate max-w-[200px]">{s.banner}</span>}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-500 mt-2">No services enumerated</p>
          )}
        </div>
      ))}
    </div>
  );
}
