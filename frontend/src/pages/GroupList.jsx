import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Users, Plus } from "lucide-react";
import { groups, engagements } from "../api/client";
import { useAuth } from "../auth";

export default function GroupList() {
  const { user, isLead, refreshProfile } = useAuth();
  const [list, setList] = useState([]);
  const [engList, setEngList] = useState([]);
  const [showCreate, setShowCreate] = useState(false);
  const [engId, setEngId] = useState("");
  const [name, setName] = useState("");
  const [err, setErr] = useState("");
  const isFounder = user?.is_founder;
  const canCreate = isFounder || isLead; // backend enforces founder-only, UI shows for leads with clear error

  useEffect(() => {
    if (refreshProfile) refreshProfile().catch(() => {});
    groups.list().then((r) => setList(r.data || [])).catch(() => {});
    engagements.list().then((r) => setEngList(r.data || [])).catch(() => {});
  }, []); // eslint-disable-line

  const create = async () => {
    if (!engId || !name.trim()) return;
    setErr("");
    try {
      const r = await groups.create(engId, name.trim());
      setList([r.data, ...list]);
      setShowCreate(false);
      setEngId("");
      setName("");
    } catch (e) {
      const msg = e.response?.data?.detail || e.message;
      setErr(msg);
      if (!isFounder) {
        // lead but not founder sees why
      }
    }
  };

  const navigate = useNavigate();

  return (
    <div className="p-6 space-y-4 overflow-y-auto h-full">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2"><Users size={22} className="text-cyan-400" /> Groups</h2>
          <p className="text-xs text-slate-400 mt-1">One group per engagement. Founder creates, lead adds analysts, promotes max 2 co-leads.</p>
        </div>
        {canCreate && <button onClick={() => setShowCreate(true)} className="flex items-center gap-1 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs"><Plus size={14} /> New Group</button>}
      </div>
      {!isFounder && canCreate && <p className="text-[11px] text-amber-300/80">Only the founder (you, {user?.username}) can create — leads will see “Only founder/head lead can create a group”.</p>}

      {showCreate && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
          <p className="text-xs text-slate-400">Founder only. One group per engagement. Name by app type, e.g. E-Commerce — Q3 Audit.</p>
          {err && <p className="text-xs text-rose-300 bg-rose-950/40 border border-rose-800 rounded p-2">{err}</p>}
          <select value={engId} onChange={(e) => setEngId(e.target.value)} className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-white">
            <option value="">Select engagement…</option>
            {engList.map((e) => <option key={e.id} value={e.id}>{e.name} — {e.client_name}</option>)}
          </select>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Group name (app type)" className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-white" />
          <div className="flex justify-end gap-2">
            <button onClick={() => setShowCreate(false)} className="px-3 py-1.5 rounded text-xs bg-slate-800 text-slate-300">Cancel</button>
            <button onClick={create} className="px-4 py-1.5 rounded text-xs bg-emerald-600 text-white">Create</button>
          </div>
        </div>
      )}

      <div className="rounded-xl border border-dashed border-slate-800 bg-slate-900/20 p-4 text-xs text-slate-400 leading-relaxed">
        <p className="font-semibold text-slate-300">How to add people — example</p>
        <p className="mt-1">1. Open a group → Members tab → type <span className="font-mono text-cyan-300">krishna</span> (username or email) → Add analyst.</p>
        <p>2. Click <span className="font-mono text-amber-300">Co-lead</span> next to Krishna (max 2 per group). Co-lead can approve + mute when lead is on leave.</p>
        <p>3. Chat tab → ask “did you run nmap? send output”. Mute takes custom minutes (e.g. 30) — muted analyst still sees + sends, but no popup/notify.</p>
      </div>

      <div className="grid gap-3">
        {list.map((g) => (
          <div key={g.id} onClick={() => navigate(`/groups/${g.id}`)} className="rounded-xl border border-slate-800 bg-slate-900/40 p-4 cursor-pointer hover:border-cyan-500/50">
            <p className="font-semibold text-slate-100">{g.name}</p>
            <p className="text-xs text-slate-500 font-mono mt-1">engagement {String(g.engagement_id).slice(0, 8)}…</p>
          </div>
        ))}
        {list.length === 0 && <p className="text-xs text-slate-500 text-center py-10">No groups yet. Founder creates one per engagement.</p>}
      </div>
    </div>
  );
}
