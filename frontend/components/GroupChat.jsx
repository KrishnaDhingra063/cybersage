import React, { useState, useEffect, useRef } from "react";
import { Send, VolumeX } from "lucide-react";
import { groups } from "../api/client";
import { useAuth } from "../auth";

export default function GroupChat({ groupId }) {
  const { user } = useAuth();
  const [msgs, setMsgs] = useState([]);
  const [input, setInput] = useState("");
  const bottomRef = useRef(null);

  const load = async () => {
    if (!groupId) return;
    try {
      const r = await groups.messages(groupId, 50);
      setMsgs(r.data || []);
    } catch {}
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, [groupId]); // eslint-disable-line

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [msgs]);

  const send = async () => {
    const m = input.trim();
    if (!m) return;
    setInput("");
    try {
      const r = await groups.sendMessage(groupId, m);
      // muted send returns notify:false, still visible
      await load();
      if (r.data?.muted) {
        // no popup per spec, just silent
      }
    } catch (e) {
      alert(e.response?.data?.detail || e.message);
    }
  };

  return (
    <div className="flex flex-col h-[500px] border border-slate-800 rounded-xl overflow-hidden bg-slate-950/40">
      <div className="flex-1 overflow-y-auto p-3 space-y-2">
        {msgs.map((m) => {
          const mine = m.sender === user?.username;
          return (
            <div key={m.id} className={`flex ${mine ? "justify-end" : "justify-start"}`}>
              <div className={`max-w-[75%] rounded-xl px-3 py-2 text-xs ${mine ? "bg-cyan-950/60 border border-cyan-800/40 text-slate-200" : "bg-slate-900 border border-slate-800 text-slate-300"} ${m.muted ? "opacity-60" : ""}`}>
                <p className="text-[10px] text-slate-500">{m.full_name || m.sender} {m.muted && <span className="inline-flex items-center gap-0.5 text-slate-600"><VolumeX size={10} /> muted — no notify</span>}</p>
                <p className="mt-0.5">{m.message}</p>
              </div>
            </div>
          );
        })}
        <div ref={bottomRef} />
        {msgs.length === 0 && <p className="text-xs text-slate-600 text-center py-8">No messages. Ask: “did you run nmap? send output”.</p>}
      </div>
      <div className="p-2 border-t border-slate-800 flex gap-2">
        <input value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === "Enter" && send()} placeholder="Ask did you perform that task? send output..." className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500" />
        <button onClick={send} className="px-3 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs flex items-center gap-1"><Send size={13} /> Send</button>
      </div>
    </div>
  );
}
