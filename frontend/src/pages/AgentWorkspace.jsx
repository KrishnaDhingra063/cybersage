import React, { useState, useEffect, useRef } from "react";
import {
  Send,
  Plus,
  User as UserIcon,
  Bot,
  Zap,
  Terminal,
  Cpu,
  Layers,
  Activity,
  FileCode,
  Shield,
  Check,
  Copy,
  Edit2,
  ChevronRight,
  ExternalLink,
  Play,
  Square,
  AlertTriangle,
  History,
  Trash2,
  Search,
  X,
} from "lucide-react";
import { engagements, agent, findings } from "../api/client";
import { useAuth } from "../auth";
import ToolCard from "../components/ToolCard";
import AttackGraph from "../components/AttackGraph";
import DashboardCards from "../components/DashboardCards";
import EngagementWizard from "../components/EngagementWizard";
import PricingModal from "../components/PricingModal";

// Strict Indian Standard Time (Asia/Kolkata, UTC+5:30) Formatter
const formatIST = (isoString, type = "time") => {
  if (!isoString) return "";
  const date = new Date(isoString);
  if (isNaN(date.getTime())) return "";

  if (type === "time") {
    return date.toLocaleTimeString("en-IN", {
      timeZone: "Asia/Kolkata",
      hour: "2-digit",
      minute: "2-digit",
      hour12: true,
    });
  }

  return date.toLocaleString("en-IN", {
    timeZone: "Asia/Kolkata",
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    hour12: true,
  });
};

function getGreeting(user, engCount = 0) {
  const now = new Date();
  const hour = now.getHours();
  const day = now.getDay();
  const isWeekend = day === 0 || day === 6;
  const rawName = user?.displayName || user?.full_name || user?.username || "there";
  const name = rawName.charAt(0).toUpperCase() + rawName.slice(1);
  let period = "";
  let emoji = "";
  let quote = "";
  if (hour >= 5 && hour < 12) {
    period = "Good morning";
    emoji = "☀️";
    quote = "Early bird catches the misconfig — perfect time for recon.";
  } else if (hour >= 12 && hour < 17) {
    period = "Good afternoon";
    emoji = "🌤️";
    quote = "Half-day sweep — let's triage what we found.";
  } else if (hour >= 17 && hour < 21) {
    period = "Good evening";
    emoji = "🌙";
    quote = "Evening recon — lock down the criticals before nightfall.";
  } else {
    period = "Burning the midnight oil";
    emoji = "🦉";
    quote = "Night owl mode — stealth scans recommended.";
  }
  if (isWeekend) {
    period = `Weekend ${period.toLowerCase()}`;
    quote = "Weekend watch — light scans, sharp eyes. " + quote;
  }
  if (engCount > 5) {
    quote += ` You’ve got ${engCount} active engagements — heavy workload, pace yourself.`;
  } else if (engCount > 2) {
    quote += ` ${engCount} engagements in flight — steady flow.`;
  } else if (engCount > 0) {
    quote += ` ${engCount} engagement active — good time for deep dives.`;
  } else {
    quote += " No active engagements — ready to spin up a new scope?";
  }
  if (isWeekend && engCount > 0) {
    quote += " Weekend effort counts — but take breaks.";
  }
  return { title: `${period}, ${name} ${emoji}`, subtitle: quote, isWeekend };
}

const chatKey = (engId) => `pentestai_chat_${engId}`;
const activeKey = "pentestai_active_engagement";
const providerKey = "pentestai_provider";

function loadLocalChat(engId) {
  if (!engId) return [];
  try {
    const raw = localStorage.getItem(chatKey(engId));
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((m) => m && !m.thinking) : [];
  } catch {
    return [];
  }
}

function saveLocalChat(engId, msgs) {
  if (!engId) return;
  try {
    const clean = (msgs || []).filter((m) => m && !m.thinking).slice(-100);
    localStorage.setItem(chatKey(engId), JSON.stringify(clean));
  } catch {}
}

function groupByDay(msgs) {
  const groups = {};
  msgs.forEach((m, idx) => {
    let label = "Older";
    try {
      const d = m.timestamp ? new Date(m.timestamp) : null;
      if (d && !isNaN(d)) {
        const today = new Date();
        const yesterday = new Date();
        yesterday.setDate(today.getDate() - 1);
        if (d.toDateString() === today.toDateString()) label = "Today";
        else if (d.toDateString() === yesterday.toDateString()) label = "Yesterday";
        else label = d.toLocaleDateString();
      } else if (idx < 4) label = "Today";
    } catch {}
    if (!groups[label]) groups[label] = [];
    groups[label].push({ ...m, _idx: idx });
  });
  return groups;
}

export default function AgentWorkspace() {
  const { user, isLead } = useAuth();
  const [engList, setEngList] = useState([]);
  const [engagementId, setEngagementId] = useState(() => {
    try {
      return localStorage.getItem(activeKey) || "";
    } catch {
      return "";
    }
  });
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [activeTab, setActiveTab] = useState("chat");
  const abortControllerRef = useRef(null);
  const [copiedIndex, setCopiedIndex] = useState(null);
  const [showPricing, setShowPricing] = useState(false);

  // Persistent default set to Gemini Flash
  const [provider, setProvider] = useState(() => {
    try {
      return localStorage.getItem(providerKey) || "gemini";
    } catch {
      return "gemini";
    }
  });

  const [autonomy, setAutonomy] = useState("human_gated");
  const [expandedTool, setExpandedTool] = useState(null);
  const [showHistory, setShowHistory] = useState(false);
  const [historySearch, setHistorySearch] = useState("");
  const [historyLoading, setHistoryLoading] = useState(false);
  const [showWizard, setShowWizard] = useState(false);

  const [chatPrefs, setChatPrefs] = useState(() => {
    try {
      return {
        cute: localStorage.getItem("pentestai_cute") === "1",
        emoji: localStorage.getItem("pentestai_emoji") || "💜",
        accent: localStorage.getItem("pentestai_accent") || "violet",
        showGreeting: localStorage.getItem("pentestai_show_greeting") !== "0",
        showCards: localStorage.getItem("pentestai_show_cards") !== "0",
      };
    } catch {
      return { cute: false, emoji: "💜", accent: "violet", showGreeting: true, showCards: true };
    }
  });
  const [showCuteMenu, setShowCuteMenu] = useState(false);

  const saveChatPrefs = (p) => {
    setChatPrefs(p);
    try {
      localStorage.setItem("pentestai_cute", p.cute ? "1" : "0");
      localStorage.setItem("pentestai_emoji", p.emoji);
      localStorage.setItem("pentestai_accent", p.accent);
      localStorage.setItem("pentestai_show_greeting", p.showGreeting ? "1" : "0");
      localStorage.setItem("pentestai_show_cards", p.showCards ? "1" : "0");
    } catch {}
  };
  const greeting = getGreeting(user, engList.length);

  const bottomRef = useRef(null);
  const inputRef = useRef(null);
  const turnRef = useRef(0);

  // Action Handlers: Copy, Edit, Stop
  const handleCopyCommand = (text, index) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 1500);
  };

  const handleEditCommand = (text) => {
    setInput(text);
    if (inputRef && inputRef.current) {
      inputRef.current.focus();
    }
  };

  const handleStopExecution = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setBusy(false);
    setMessages((prev) => {
      const copy = [...prev];
      const last = copy[copy.length - 1];
      if (last && last.role === "assistant" && last.thinking) {
        last.thinking = false;
        last.text = "⚠️ Execution stopped by user.";
      }
      return copy;
    });
  };

  useEffect(() => {
    engagements
      .list()
      .then((r) => {
        if (r?.data && r.data.length > 0) {
          setEngList(r.data);
          let saved = "";
          try {
            saved = localStorage.getItem(activeKey) || "";
          } catch {}
          if (saved && r.data.some((e) => e.id === saved)) {
            setEngagementId(saved);
          } else {
            setEngagementId(r.data[0].id);
            try {
              localStorage.setItem(activeKey, r.data[0].id);
            } catch {}
          }
        }
      })
      .catch((err) => console.warn("Failed to fetch engagements:", err));
  }, []);

  useEffect(() => {
    if (!engagementId) {
      setMessages([]);
      return;
    }
    try {
      localStorage.setItem(activeKey, engagementId);
    } catch {}
    const local = loadLocalChat(engagementId);
    setMessages(local);
    setExpandedTool(null);
    setHistoryLoading(true);
    agent
      .history(engagementId, 100)
      .then((r) => {
        const server = (r.data?.messages || [])
          .map((m) => ({
            role: m.role,
            text: m.text,
            timestamp: m.timestamp,
            tools: [],
          }))
          .filter((m) => m.text);
        if (server.length === 0) return;
        const toolByText = {};
        local.forEach((m) => {
          if (m.tools?.length && m.text) toolByText[m.text.slice(0, 80)] = m.tools;
        });
        const merged = server.map((m) => ({
          ...m,
          tools: toolByText[m.text?.slice(0, 80)] || [],
        }));
        setMessages(merged);
        saveLocalChat(engagementId, merged);
      })
      .catch(() => {})
      .finally(() => setHistoryLoading(false));
  }, [engagementId]);

  useEffect(() => {
    if (engagementId && messages.length > 0) {
      saveLocalChat(engagementId, messages);
    }
  }, [messages, engagementId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, busy]);

  const selectEngagement = (id) => {
    if (id === engagementId) return;
    setEngagementId(id);
    try {
      localStorage.setItem(activeKey, id);
    } catch {}
    setExpandedTool(null);
  };

  const handleProviderChange = (newVal) => {
    setProvider(newVal);
    try {
      localStorage.setItem(providerKey, newVal);
    } catch {}
  };

  const send = async () => {
    const msg = input.trim();
    if (!msg || busy) return;
    const controller = new AbortController();
    abortControllerRef.current = controller;

    let targetEng = engagementId;
    if (!targetEng || targetEng === "default" || targetEng === "demo-target" || targetEng === "UNBOUND") {
      targetEng = engList[0]?.id || "default";
    }

    setInput("");
    const turnId = ++turnRef.current;
    const nowIso = new Date().toISOString();
    setMessages((prev) => [...prev, { role: "user", text: msg, timestamp: nowIso, tools: [] }]);
    setMessages((prev) => [
      ...prev,
      { role: "assistant", text: "", tools: [], thinking: true, timestamp: nowIso },
    ]);
    setBusy(true);

    try {
      const res = await agent.turn(targetEng || "default", msg, "", provider, {
        signal: abortControllerRef.current?.signal,
      });
      const effectiveEng = res.data?.engagement_id || targetEng;
      if (res.data?.engagement_id && res.data.engagement_id !== targetEng) {
        setEngagementId(res.data.engagement_id);
        try {
          localStorage.setItem(activeKey, res.data.engagement_id);
        } catch {}
        engagements
          .list()
          .then((r) => {
            if (r?.data) setEngList(r.data);
          })
          .catch(() => {});
        targetEng = res.data.engagement_id;
      }
      const replyIso = new Date().toISOString();
      setMessages((prev) => {
        const next = prev.map((m, i) =>
          i === prev.length - 1 && turnId === turnRef.current
            ? {
                role: "assistant",
                text: res.data?.assistant || res.data?.message || "Execution completed.",
                tools: res.data?.tools || [],
                thinking: false,
                timestamp: replyIso,
              }
            : m
        );
        saveLocalChat(effectiveEng, next.filter((m) => !m.thinking));
        return next;
      });
    } catch (e) {
      if (e.name === "AbortError" || e.name === "CanceledError") {
        return;
      }
      setMessages((prev) =>
        prev.map((m, i) =>
          i === prev.length - 1
            ? {
                role: "assistant",
                text:
                  "Error: " +
                  (e.response?.data?.detail || e.message || "Failed to communicate with agent."),
                tools: [],
                thinking: false,
                timestamp: new Date().toISOString(),
              }
            : m
        )
      );
    } finally {
      setBusy(false);
      abortControllerRef.current = null;
    }
  };

  const clearChat = async () => {
    if (!engagementId) return;
    if (!window.confirm("Clear chat history for this engagement? This removes the timeline from server + this browser."))
      return;
    try {
      await agent.clearHistory(engagementId);
    } catch {}
    setMessages([]);
    try {
      localStorage.removeItem(chatKey(engagementId));
    } catch {}
  };

  const filteredHistory = historySearch.trim()
    ? messages.filter((m) => (m.text || "").toLowerCase().includes(historySearch.toLowerCase()))
    : messages;

  return (
    <div className="flex h-[calc(100vh-3.5rem)] w-full bg-slate-950 font-sans text-slate-100 antialiased overflow-hidden">
      {/* 1. LEFT SIDEBAR */}
      <aside className="w-64 shrink-0 bg-slate-900/60 border-r border-slate-800 flex flex-col justify-between">
        <div>
          <div className="p-3 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-cyan-400" />
              <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                Engagements
              </span>
            </div>
            <button
              onClick={() => setShowWizard(true)}
              className="p-1 rounded text-slate-400 hover:text-cyan-300 hover:bg-slate-800"
              title="New engagement wizard"
            >
              <Plus size={16} />
            </button>
          </div>

          <div className="p-2 space-y-1 overflow-y-auto max-h-[50vh]">
            {engList.length === 0 ? (
              <div className="p-3 text-center">
                <p className="text-xs text-slate-500">No active targets found.</p>
                <button
                  onClick={async () => {
                    try {
                      const r = await engagements.create({
                        name: "Localhost Sandbox",
                        client_name: "Local",
                        test_type: "web_only",
                      });
                      try {
                        await engagements.createScope(r.data.id, {
                          allowed_targets: ["localhost", "127.0.0.1", "scanme.nmap.org"],
                          excluded_targets: [],
                          allowed_window_start: new Date().toISOString(),
                          allowed_window_end: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString(),
                          rules_of_engagement: "Sandbox",
                          signed_by: "auto",
                        });
                      } catch {}
                      setEngList((prev) => [...prev, r.data]);
                      setEngagementId(r.data.id);
                    } catch (e) {
                      setEngagementId("demo-target");
                    }
                  }}
                  className="mt-2 text-[11px] text-cyan-400 hover:underline"
                >
                  Use Localhost Sandbox
                </button>
              </div>
            ) : (
              engList.map((e) => (
                <button
                  key={e.id}
                  onClick={() => selectEngagement(e.id)}
                  className={`w-full text-left px-3 py-2.5 rounded-lg text-xs transition-all border ${
                    engagementId === e.id
                      ? "bg-cyan-950/40 text-cyan-300 border-cyan-500/40 shadow-sm"
                      : "border-transparent text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
                  }`}
                >
                  <div className="font-semibold truncate">{e.name || "Target Host"}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    {e.status || "IDLE"} · {e.autonomy_level || "human_gated"}
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Engine Config Footer */}
        <div className="p-3 border-t border-slate-800 bg-slate-900/30 text-[11px] space-y-2">
          {/* Business Model Trigger Button */}
          <button
            type="button"
            onClick={() => setShowPricing(true)}
            className="w-full mb-2 py-1.5 px-2 bg-gradient-to-r from-cyan-950 to-violet-950 border border-cyan-700/40 hover:border-cyan-400 text-cyan-300 text-xs font-semibold rounded-lg flex items-center justify-center gap-1.5 transition-all shadow-sm cursor-pointer"
          >
            <Shield size={13} /> View Business Plans
          </button>

          <div className="flex justify-between items-center text-slate-400">
            <span>Model Router</span>
            <select
              value={provider}
              onChange={(e) => handleProviderChange(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-1.5 py-0.5 text-slate-200"
            >
              <option value="gemini">Gemini Flash</option>
              <option value="anthropic">Claude 3.7</option>
              <option value="openai">GPT-4o</option>
              <option value="ollama">Ollama (Local)</option>
            </select>
          </div>
          <div className="flex justify-between items-center text-slate-400">
            <span>HITL Gate</span>
            <select
              value={autonomy}
              onChange={async (e) => {
                const v = e.target.value;
                setAutonomy(v);
                if (engagementId) {
                  try {
                    await engagements.setAutonomy(engagementId, v);
                  } catch (err) {
                    console.warn("setAutonomy failed", err.response?.data?.detail || err.message);
                  }
                }
              }}
              className="bg-slate-950 border border-slate-800 rounded px-1.5 py-0.5 text-slate-200"
            >
              <option value="human_gated">Gated</option>
              <option value="autonomous">Auto</option>
            </select>
          </div>
          <p className="text-[10px] leading-snug text-slate-600">
            {autonomy === "autonomous"
              ? "Auto: in-scope recon runs free, high-risk still gated."
              : "Gated: risky tools wait in Approval Queue."}
          </p>
        </div>
      </aside>

      {/* 2. CENTER PANEL */}
      <main className="flex-1 flex flex-col bg-slate-950 min-w-0">
        <div className="h-11 border-b border-slate-800 flex items-center justify-between px-4 bg-slate-900/40">
          <div className="flex gap-2 text-xs font-medium">
            <button
              onClick={() => setActiveTab("chat")}
              className={`flex items-center gap-1.5 px-3 py-1 rounded transition-all ${
                activeTab === "chat"
                  ? "bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Terminal size={14} /> Agent Console
            </button>
            <button
              onClick={() => setActiveTab("graph")}
              className={`flex items-center gap-1.5 px-3 py-1 rounded transition-all ${
                activeTab === "graph"
                  ? "bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Cpu size={14} /> Attack Graph
            </button>
            <button
              onClick={() => setShowHistory((v) => !v)}
              className={`flex items-center gap-1.5 px-3 py-1 rounded transition-all ${
                showHistory
                  ? "bg-violet-500/20 text-violet-300 font-semibold border border-violet-500/30"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <History size={14} /> History{" "}
              {messages.filter((m) => !m.thinking).length > 0 &&
                `(${messages.filter((m) => !m.thinking).length})`}
            </button>
          </div>

          <div className="flex items-center gap-2 font-mono text-[11px] text-slate-400">
            {historyLoading && <span className="text-cyan-400">restoring…</span>}
            <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
            TARGET: {engagementId || "UNBOUND"}
          </div>
        </div>

        {/* Center Content View */}
        <div className="flex-1 overflow-hidden relative flex">
          {showHistory && activeTab === "chat" && (
            <aside className="w-64 shrink-0 border-r border-slate-800 bg-slate-900/60 flex flex-col">
              <div className="p-3 border-b border-slate-800">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                    <History size={13} className="text-violet-400" /> Timeline
                  </span>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={clearChat}
                      title="Clear history"
                      className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-slate-800"
                    >
                      <Trash2 size={13} />
                    </button>
                    <button
                      onClick={() => setShowHistory(false)}
                      className="p-1 rounded text-slate-500 hover:text-white hover:bg-slate-800"
                    >
                      <X size={13} />
                    </button>
                  </div>
                </div>
                <div className="mt-2 flex items-center gap-1 bg-slate-950 border border-slate-800 rounded px-2">
                  <Search size={12} className="text-slate-500" />
                  <input
                    value={historySearch}
                    onChange={(e) => setHistorySearch(e.target.value)}
                    placeholder="Search conversation…"
                    className="flex-1 bg-transparent text-xs text-slate-200 py-1.5 focus:outline-none"
                  />
                </div>
              </div>
              <div className="flex-1 overflow-y-auto p-2 space-y-3">
                {Object.entries(groupByDay(filteredHistory.filter((m) => !m.thinking))).map(
                  ([day, items]) => (
                    <div key={day}>
                      <p className="text-[10px] uppercase tracking-wider text-slate-500 font-bold px-1 mb-1">
                        {day} · {items.length}
                      </p>
                      <div className="space-y-1 relative">
                        <div className="absolute left-2 top-1 bottom-1 w-px bg-slate-800" />
                        {items.map((m) => (
                          <button
                            key={`${m._idx}-${m.timestamp || m.text?.slice(0, 10)}`}
                            onClick={() => {
                              const el = document.getElementById(`chat-msg-${m._idx}`);
                              el?.scrollIntoView({ behavior: "smooth", block: "center" });
                            }}
                            className="relative w-full text-left pl-5 pr-2 py-1.5 rounded-lg hover:bg-slate-800/60 group"
                          >
                            <span
                              className={`absolute left-1 top-2.5 h-2 w-2 rounded-full ${
                                m.role === "user" ? "bg-cyan-500" : "bg-violet-500"
                              }`}
                            />
                            <p className="text-[11px] text-slate-300 truncate">
                              {m.role === "user" ? "You: " : ""}
                              {m.text?.slice(0, 60) || "(empty)"}
                            </p>
                            <p className="text-[10px] text-slate-600 font-mono">
                              {m.timestamp ? formatIST(m.timestamp, "time") : ""}{" "}
                              · {m.tools?.length ? `${m.tools.length} tool(s)` : m.role}
                            </p>
                          </button>
                        ))}
                      </div>
                    </div>
                  )
                )}
              </div>
            </aside>
          )}

          {activeTab === "chat" && (
            <div className="flex-1 h-full flex flex-col justify-between min-w-0">
              {chatPrefs.showGreeting && (
                <div className="px-4 pt-4">
                  <div
                    className={`rounded-xl border p-3 flex items-start gap-3 ${
                      greeting.isWeekend
                        ? "bg-violet-950/30 border-violet-800/40"
                        : "bg-slate-900/60 border-slate-800"
                    }`}
                  >
                    <div className="w-8 h-8 rounded-full flex items-center justify-center shrink-0 bg-cyan-600">
                      <Bot size={16} className="text-white" />
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-slate-100">{greeting.title}</p>
                      <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                        {greeting.subtitle}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {chatPrefs.showCards && (
                <div className="px-4 pt-3">
                  <DashboardCards engagementId={engagementId} />
                </div>
              )}

              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {messages.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-center p-6">
                    <Bot size={44} className="text-cyan-500 mb-3" />
                    <h3 className="text-lg font-bold text-slate-200">{greeting.title}</h3>
                    <p className="text-xs text-slate-400 max-w-md mt-2 leading-relaxed">
                      {greeting.subtitle}
                    </p>
                  </div>
                ) : (
                  messages.map((m, i) => (
                    <div
                      key={m.timestamp ? `${m.timestamp}-${i}` : i}
                      id={`chat-msg-${i}`}
                      className={`flex gap-3 ${m.role === "user" ? "flex-row-reverse" : ""} scroll-mt-4`}
                    >
                      <div className="shrink-0">
                        {m.role === "user" ? (
                          <div className="w-7 h-7 rounded-full bg-cyan-600 flex items-center justify-center">
                            <UserIcon size={14} className="text-white" />
                          </div>
                        ) : (
                          <div className="w-7 h-7 rounded-full flex items-center justify-center bg-violet-600">
                            <Bot size={14} className="text-white" />
                          </div>
                        )}
                      </div>

                      {/* Message Bubble + Action Buttons */}
                      <div className={`relative max-w-[80%] group flex flex-col ${m.role === "user" ? "items-end" : "items-start"}`}>
                        {/* Action toolbar visible on hover */}
                        {m.role === "user" && (
                          <div className="opacity-0 group-hover:opacity-100 transition-opacity mb-1 flex items-center gap-1.5 bg-slate-900 border border-slate-700/60 rounded px-2 py-0.5 text-[11px] text-slate-400 shadow-sm">
                            <button
                              type="button"
                              onClick={() => handleEditCommand(m.text)}
                              className="flex items-center gap-1 hover:text-cyan-300 transition-colors"
                              title="Edit directive"
                            >
                              <Edit2 size={11} /> Edit
                            </button>
                            <span className="text-slate-600">|</span>
                            <button
                              type="button"
                              onClick={() => handleCopyCommand(m.text, i)}
                              className="flex items-center gap-1 hover:text-cyan-300 transition-colors"
                              title="Copy directive"
                            >
                              {copiedIndex === i ? (
                                <>
                                  <Check size={11} className="text-emerald-400" />
                                  <span className="text-emerald-400">Copied</span>
                                </>
                              ) : (
                                <>
                                  <Copy size={11} /> Copy
                                </>
                              )}
                            </button>
                          </div>
                        )}

                        <div
                          className={`rounded-xl px-4 py-2.5 text-xs w-full ${
                            m.role === "user"
                              ? "bg-cyan-950/60 border border-cyan-800/40 text-slate-200"
                              : "bg-slate-900 border border-slate-800 text-slate-300"
                          }`}
                        >
                          {m.thinking ? (
                            <div className="flex items-center gap-2 text-cyan-400">
                              <Zap size={14} className="animate-spin" />
                              <span>Reasoning over AST & dispatching security adapters...</span>
                            </div>
                          ) : (
                            <>
                              <p className="whitespace-pre-wrap leading-relaxed">{m.text}</p>
                              {m.timestamp && (
                                <p className="text-[10px] text-slate-600 font-mono mt-1">
                                  {formatIST(m.timestamp, "full")} IST
                                </p>
                              )}
                            </>
                          )}
                          {m.tools?.map((tool, ti) => (
                            <div key={ti} className="mt-2">
                              <ToolCard
                                tool={tool}
                                expanded={expandedTool === ti}
                                onToggle={() =>
                                  setExpandedTool(expandedTool === ti ? null : ti)
                                }
                              />
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))
                )}
                <div ref={bottomRef} />
              </div>

              {/* Input Area */}
              <div className="p-3 border-t border-slate-800 bg-slate-900/40">
                <div className="flex gap-2 relative">
                  <textarea
                    ref={inputRef}
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && !e.shiftKey) {
                        e.preventDefault();
                        send();
                      }
                    }}
                    placeholder="Enter security target directive or ask agent to run recon..."
                    rows={2}
                    className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/80 resize-none z-10"
                  />
                  {busy ? (
                    <button
                      type="button"
                      onClick={handleStopExecution}
                      className="px-4 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all z-10 shadow-lg shadow-red-950/50 cursor-pointer"
                    >
                      <span className="w-2 h-2 rounded-xs bg-white animate-pulse" />
                      Stop
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={send}
                      disabled={!input.trim()}
                      className="px-4 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all z-10 cursor-pointer"
                    >
                      <Send size={14} />
                      Execute
                    </button>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeTab === "graph" && (
            <div className="flex-1 h-full w-full p-2 min-w-0">
              <AttackGraph engagementId={engagementId} />
            </div>
          )}
        </div>
      </main>

      {/* Modals */}
      {showWizard && (
        <EngagementWizard
          onClose={() => setShowWizard(false)}
          onCreated={(eng) => {
            setEngList((prev) => [...prev, eng]);
            setEngagementId(eng.id);
            try {
              localStorage.setItem(activeKey, eng.id);
            } catch {}
            setShowWizard(false);
          }}
        />
      )}

      <PricingModal
        isOpen={showPricing}
        onClose={() => setShowPricing(false)}
      />
    </div>
  );
}
