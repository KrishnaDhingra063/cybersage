import React, { useState, useEffect } from "react";
import { Search, Terminal, User } from "lucide-react";
import { groups } from "../api/client";

export default function GroupActivityFeed({ groupId }) {
  const [items, setItems] = useState([]);
  const [search, setSearch] = useState("");
  const [userF, setUserF] = useState("");
  const [toolF, setToolF] = useState("");
  const [loading, setLoading] = useState(false);

  const load = async () => {
    if (!groupId) return;
    setLoading(true);
    try {
      const r = await groups.activity(groupId, {
        search: search || undefined,
        user: userF || undefined,
        tool: toolF || undefined,
        limit: 30,
      });
      setItems(r.data || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [groupId]); // eslint-disable-line

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2 bg-slate-900/60 border border-slate-800 rounded-lg p-2">
        <div className="flex items-center gap-1 flex-1 min-w-[180px] bg-slate-950 border border-slate-800 rounded px-2">
          <Search size={13} className="text-slate-500" />
          <input value={search} onChange={(e) => setSearch(e.target.value)} onKeyDown={(e) => e.key === "Enter" && load()} placeholder="Search nmap, port scan, 192.168..." className="flex-1 bg-transparent text-xs text-slate-200 py-1.5 focus:outline-none" />
        </div>
        <input value={userF} onChange={(e) => setUserF(e.target.value)} placeholder="User: depanshu" className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs text-slate-200 w-32" />
        <select value={toolF} onChange={(e) => setToolF(e.target.value)} className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs text-slate-200">
          <option value="">All tools</option>
          <option value="nmap">nmap</option>
          <option value="crawler">crawler</option>
          <option value="zap">zap</option>
          <option value="nuclei">nuclei</option>
          <option value="subdomain">subdomain</option>
          <option value="dirsearch">dirsearch</option>
          <option value="masscan">masscan</option>
        </select>
        <button onClick={load} className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs">Search</button>
      </div>

      {loading ? <p className="text-xs text-slate-500">Loading...</p> : items.length === 0 ? <p className="text-xs text-slate-500 text-center py-8">No activity yet. Analyst runs will appear as “Depanshu started nmap port scanning”.</p> : (
        <div className="space-y-2">
          {items.map((a) => (
            <div key={a.id} className="flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-900/40 p-2.5 text-xs">
              <div className="w-6 h-6 rounded-full bg-cyan-700 flex items-center justify-center shrink-0"><User size={12} className="text-white" /></div>
              <div className="flex-1 min-w-0">
                <p className="text-slate-200"><span className="font-semibold">{a.full_name || a.username}</span> <span className="text-slate-400">{a.action_type.replace(/_/g, " ")}</span></p>
                <p className="text-slate-500 font-mono text-[11px] truncate">{a.target} {a.tool && `· ${a.tool}`}</p>
                {a.result_summary && <p className="text-slate-400 mt-1 text-[11px]">{a.result_summary.slice(0, 200)}</p>}
              </div>
              <span className="text-[10px] text-slate-500 font-mono shrink-0">{a.created_at?.slice(0, 16).replace("T", " ")}</span>
            </div>
          ))}
        </div>
      )}
      <p className="text-[11px] text-slate-600 flex items-center gap-1"><Terminal size={11} /> Tip: search “nmap” to find which ports were open without re-scanning.</p>
    </div>
  );
}
