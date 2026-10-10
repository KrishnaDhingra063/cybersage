import React, { useState, useEffect } from "react";
import { useParams } from "react-router-dom";
import { Users, Share2, VolumeX, Volume2, Crown } from "lucide-react";
import { groups } from "../api/client";
import { useAuth } from "../auth";
import GroupActivityFeed from "../components/GroupActivityFeed";
import GroupChat from "../components/GroupChat";

export default function GroupDetail() {
  const { id } = useParams();
  const { user } = useAuth();
  const [detail, setDetail] = useState(null);
  const [tab, setTab] = useState("activity");
  const [addUser, setAddUser] = useState("");
  const [muteMins, setMuteMins] = useState({}); // userId -> minutes
  const [shares, setShares] = useState([]);
  const [shareForm, setShareForm] = useState({ payload_type: "finding", payload_id: "", note: "" });

  const load = async () => {
    try {
      const r = await groups.get(id);
      setDetail(r.data);
      const s = await groups.shares(id).catch(() => ({ data: [] }));
      setShares(s.data || []);
    } catch (e) { console.error(e); }
  };
  useEffect(() => { load(); }, [id]); // eslint-disable-line

  const isLead = detail?.members?.find((m) => m.user_id === user?.user_id)?.role === "lead" || user?.is_founder;
  const isCoLead = detail?.members?.find((m) => m.user_id === user?.user_id)?.role === "co_lead";

  const doAdd = async () => {
    try { await groups.addMember(id, addUser); setAddUser(""); load(); }
    catch (e) { alert(e.response?.data?.detail || e.message); }
  };
  const doPromote = async (uid) => { try { await groups.promote(id, uid); load(); } catch (e) { alert(e.response?.data?.detail || e.message); } };
  const doDemote = async (uid) => { try { await groups.demote(id, uid); load(); } catch (e) { alert(e.response?.data?.detail || e.message); } };
  const doMute = async (uid) => {
    const mins = parseInt(muteMins[uid] || "30", 10);
    try { await groups.mute(id, uid, mins); load(); } catch (e) { alert(e.response?.data?.detail || e.message); }
  };
  const doShare = async () => {
    try { await groups.share(id, shareForm); setShareForm({ payload_type: "finding", payload_id: "", note: "" }); load(); }
    catch (e) { alert(e.response?.data?.detail || e.message); }
  };

  if (!detail) return <p className="p-6 text-xs text-slate-500">Loading group…</p>;

  return (
    <div className="p-6 space-y-4 overflow-y-auto h-full">
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2"><Users size={20} className="text-cyan-400" /> {detail.name}</h2>
        <p className="text-xs text-slate-400 mt-1">Lead: <span className="text-cyan-300 font-semibold">{detail.lead_name || "—"}</span> · {detail.stats?.hosts || 0} hosts · {detail.stats?.findings || 0} findings · {detail.stats?.fixes || 0} fixes</p>
      </div>

      <div className="flex gap-2 border-b border-slate-800 pb-2 text-xs">
        {["activity", "chat", "shares", "members"].map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`px-3 py-1.5 rounded-lg border capitalize ${tab === t ? "bg-cyan-500/10 text-cyan-300 border-cyan-500/30" : "text-slate-400 border-transparent hover:bg-slate-900"}`}>{t}</button>
        ))}
      </div>

      {tab === "activity" && <GroupActivityFeed groupId={id} />}
      {tab === "chat" && <GroupChat groupId={id} />}

      {tab === "shares" && (
        <div className="space-y-3">
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-3 space-y-2">
            <p className="text-xs text-slate-300 flex items-center gap-1"><Share2 size={13} /> Share work to lead</p>
            <div className="flex flex-wrap gap-2">
              <select value={shareForm.payload_type} onChange={(e) => setShareForm({ ...shareForm, payload_type: e.target.value })} className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs text-white">
                <option value="finding">finding</option><option value="fix">fix</option><option value="log">log</option>
              </select>
              <input value={shareForm.payload_id} onChange={(e) => setShareForm({ ...shareForm, payload_id: e.target.value })} placeholder="finding/fix/log id" className="flex-1 min-w-[160px] bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs text-white" />
              <input value={shareForm.note} onChange={(e) => setShareForm({ ...shareForm, note: e.target.value })} placeholder="note: nmap found 3 ports" className="flex-1 min-w-[160px] bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs text-white" />
              <button onClick={doShare} className="px-3 py-1.5 rounded bg-cyan-600 text-white text-xs">Share</button>
            </div>
          </div>
          {shares.map((s) => (
            <div key={s.id} className="rounded-lg border border-slate-800 bg-slate-900/40 p-2.5 text-xs">
              <p className="text-slate-200"><span className="font-semibold">{s.sender}</span> shared {s.payload_type} <span className="font-mono text-cyan-300">{s.payload_id.slice(0, 8)}</span> <span className="text-slate-500">· {s.status}</span></p>
              {s.note && <p className="text-slate-400 mt-1">{s.note}</p>}
              {(isLead || isCoLead) && s.status === "pending" && <button onClick={() => groups.markSeen(id, s.id).then(load)} className="mt-1 text-[11px] text-cyan-400 hover:underline">Mark seen</button>}
            </div>
          ))}
          {shares.length === 0 && <p className="text-xs text-slate-600 text-center py-6">No shares yet.</p>}
        </div>
      )}

      {tab === "members" && (
        <div className="space-y-3">
          {(isLead || isCoLead) && (
            <div className="flex gap-2">
              <input value={addUser} onChange={(e) => setAddUser(e.target.value)} placeholder="username or email" className="flex-1 bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white" />
              <button onClick={doAdd} className="px-3 py-2 rounded bg-cyan-600 text-white text-xs">Add analyst</button>
            </div>
          )}
          {detail.members.map((m) => (
            <div key={m.user_id} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/40 p-3 text-xs">
              <div>
                <p className="text-slate-200 font-semibold flex items-center gap-1.5">{m.full_name || m.username} {m.role === "lead" && <Crown size={12} className="text-amber-400" />} {m.is_founder && <span className="text-[9px] bg-violet-950 border border-violet-800 text-violet-300 px-1 rounded">Founder</span>}</p>
                <p className="text-slate-500 font-mono text-[11px]">{m.username} {m.email ? `· ${m.email}` : ""} · {m.role} {m.muted_until && `· muted until ${m.muted_until.slice(0, 16)}`}</p>
              </div>
              {isLead && m.role !== "lead" && (
                <div className="flex items-center gap-1.5">
                  {m.role === "analyst" ? <button onClick={() => doPromote(m.user_id)} className="px-2 py-1 rounded bg-amber-600/20 border border-amber-600/40 text-amber-300 text-[11px]">Co-lead</button>
                    : <button onClick={() => doDemote(m.user_id)} className="px-2 py-1 rounded bg-slate-800 border border-slate-700 text-slate-300 text-[11px]">Demote</button>}
                  <input value={muteMins[m.user_id] || "30"} onChange={(e) => setMuteMins({ ...muteMins, [m.user_id]: e.target.value })} placeholder="mins" className="w-14 bg-slate-950 border border-slate-800 rounded px-1 py-1 text-[11px] text-white" title="custom minutes" />
                  <button onClick={() => doMute(m.user_id)} className="px-2 py-1 rounded bg-slate-800 border border-slate-700 text-slate-300 text-[11px] flex items-center gap-1"><VolumeX size={11} /> Mute</button>
                </div>
              )}
              {(isCoLead && !isLead) && <span className="text-[11px] text-slate-500 flex items-center gap-1"><Volume2 size={11} /> co-lead view</span>}
            </div>
          ))}
          <p className="text-[11px] text-slate-600">Register stays lead|analyst only. Co-lead promoted here (max 2). Muted analyst messages stay visible but trigger no popup/notify.</p>
        </div>
      )}
    </div>
  );
}
