import React, { useState, useEffect, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Shield,
  Terminal,
  Play,
  Square,
  CheckCircle2,
  AlertTriangle,
  Cpu,
  Layers,
  Activity,
  FileCode,
  Lock,
  Wrench,
  Check,
  Globe,
} from "lucide-react";
import {
  engagements as engagementApi,
  findings as findingsApi,
  reasoning as reasoningApi,
  scans as scanApi,
} from "../api/client";
import { useAuth } from "../auth";
import AttackGraph from "../components/AttackGraph";
import ReasoningTimeline from "../components/ReasoningTimeline";
import ApprovalQueue from "../components/ApprovalQueue";
import FindingsTable from "../components/FindingsTable";
import HostInventory from "../components/HostInventory";

export default function EngagementDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user, isLead } = useAuth();

  const [engagement, setEngagement] = useState(null);
  const [activeTab, setActiveTab] = useState("graph");
  const [findingsList, setFindingsList] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scopes, setScopes] = useState([]);
  const [validateInput, setValidateInput] = useState("");
  const [validateRes, setValidateRes] = useState(null);

  const loadEngagementData = useCallback(async () => {
    if (!id) return;
    try {
      const [engRes, findRes, scopeRes] = await Promise.all([
        engagementApi.get(id),
        findingsApi.list(id),
        engagementApi.listScopes(id).catch(() => ({ data: [] })),
      ]);
      setEngagement(engRes?.data);
      setScopes(scopeRes?.data || []);
      const findings = findRes?.data || [];
      setFindingsList(findings);
      if (findings.length > 0 && !selectedFinding) {
        setSelectedFinding(findings[0]);
      }
    } catch (err) {
      console.error("Failed to load engagement telemetry:", err);
    }
  }, [id, selectedFinding]);

  useEffect(() => {
    loadEngagementData();
  }, [loadEngagementData]);

  const toggleScan = async () => {
    try {
      if (!isScanning) {
        // Use reasoning cycle or manual scan shim (now mapped correctly in client.js)
        try {
          await reasoningApi.triggerCycle(id);
        } catch {
          await scanApi.start({ engagement_id: id, scan_type: "full" });
        }
        setIsScanning(true);
      } else {
        await scanApi.stop(id);
        setIsScanning(false);
      }
    } catch (err) {
      console.error("Failed to toggle scan job:", err);
      // Keep UI responsive even if backend queue is busy
      setIsScanning((prev) => !prev);
    }
  };

  const handleValidate = async () => {
    if (!validateInput.trim()) return;
    try {
      const r = await scanApi.validate(id, validateInput.trim());
      setValidateRes(r.data);
    } catch (e) {
      setValidateRes({ allowed: false, reason: e.response?.data?.detail || e.message });
    }
  };

  const peakCvss = findingsList.reduce(
    (max, f) => Math.max(max, f.cvss_score || 0),
    0
  );
  const criticalCount = findingsList.filter(
    (f) => (f.severity || "").toLowerCase() === "critical"
  ).length;

  return (
    <div className="flex flex-col h-[calc(100vh-3.5rem)] w-full bg-slate-950 font-sans text-slate-100 overflow-hidden">
      {/* 1. TOP HEADER BAR */}
      <header className="flex h-14 shrink-0 items-center justify-between border-b border-slate-800 bg-slate-900/60 px-6 backdrop-blur">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 rounded-md border border-emerald-500/30 bg-emerald-950/40 px-3 py-1 text-xs text-emerald-400">
            <Lock className="h-3.5 w-3.5" />
            <span className="font-semibold uppercase">Scope:</span>
            <span className="font-mono text-slate-200">
              {engagement?.target_scope || id}
            </span>
            <span className="rounded bg-emerald-800/60 px-1 text-[10px] font-bold">
              AUTHORIZED
            </span>
          </div>
          <span className="text-xs text-slate-400 font-mono hidden md:inline">
            {engagement?.name}
          </span>
        </div>

        <div className="flex items-center gap-3">
          {isLead && (
            <button
              onClick={toggleScan}
              className={`flex items-center gap-1.5 rounded-lg px-4 py-1.5 text-xs font-semibold shadow transition-all ${
                isScanning
                  ? "bg-rose-600 text-white hover:bg-rose-500"
                  : "bg-cyan-600 text-white hover:bg-cyan-500"
              }`}
            >
              {isScanning ? (
                <>
                  <Square className="h-3.5 w-3.5 fill-current" /> Stop Probing
                </>
              ) : (
                <>
                  <Play className="h-3.5 w-3.5 fill-current" /> Launch Autonomous Probe
                </>
              )}
            </button>
          )}
        </div>
      </header>

      {/* Scope chips + dry-run validate (feature 7) */}
      <div className="flex flex-wrap items-center gap-2 px-6 py-2 bg-slate-900/30 border-b border-slate-800 text-xs">
        <span className="text-slate-400 flex items-center gap-1"><Globe size={12} /> Allowed:</span>
        {scopes.length === 0 ? (
          <span className="text-slate-500">No approved scope — scans will be blocked</span>
        ) : (
          scopes.flatMap((s) => s.allowed_targets || []).slice(0, 6).map((t, i) => (
            <span key={i} className="px-2 py-0.5 rounded-full bg-emerald-950/40 border border-emerald-800 text-emerald-300 font-mono text-[11px]">{t}</span>
          ))
        )}
        {scopes.flatMap((s) => s.allowed_targets || []).length > 6 && <span className="text-slate-500">+{scopes.flatMap((s) => s.allowed_targets || []).length - 6} more</span>}
        <div className="ml-auto flex items-center gap-2">
          <input value={validateInput} onChange={(e) => setValidateInput(e.target.value)} placeholder="Test target (e.g. api.example.com)" className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs text-slate-200 w-56" />
          <button onClick={handleValidate} className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs">Validate</button>
          {validateRes && <span className={`text-xs font-mono ${validateRes.allowed ? "text-emerald-400" : "text-rose-400"}`}>{validateRes.allowed ? "✓ Allowed" : `✗ ${validateRes.reason || "Blocked"}`}</span>}
        </div>
      </div>

      {/* 2. LIVE TELEMETRY METRICS */}
      <section className="grid grid-cols-2 md:grid-cols-4 gap-3 border-b border-slate-800 bg-slate-900/30 p-4 shrink-0">
        <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/60 p-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <div className="text-[10px] uppercase font-bold text-slate-400">Peak Risk (CVSS)</div>
            <div className="flex items-baseline gap-1.5">
              <span className="text-lg font-bold text-rose-400">
                {peakCvss > 0 ? peakCvss.toFixed(1) : "0.0"}
              </span>
              <span className="text-[10px] text-rose-500 font-semibold uppercase">
                {criticalCount > 0 ? `${criticalCount} Critical` : "Informational"}
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/60 p-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Layers className="h-5 w-5" />
          </div>
          <div>
            <div className="text-[10px] uppercase font-bold text-slate-400">Total Findings</div>
            <div className="flex items-baseline gap-1.5">
              <span className="text-lg font-bold text-slate-200">{findingsList.length}</span>
              <span className="text-[10px] text-cyan-400 font-semibold">Deduplicated</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/60 p-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 className="h-5 w-5" />
          </div>
          <div>
            <div className="text-[10px] uppercase font-bold text-slate-400">Autonomy Mode</div>
            <div className="flex items-baseline gap-1.5">
              <span className="text-lg font-bold text-emerald-400 capitalize">
                {engagement?.autonomy_mode || "Hybrid HITL"}
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/60 p-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-violet-500/10 text-violet-400 border border-violet-500/20">
            <Cpu className="h-5 w-5" />
          </div>
          <div>
            <div className="text-[10px] uppercase font-bold text-slate-400">Agent Status</div>
            <div className="flex items-baseline gap-1.5">
              <span className="text-lg font-bold text-violet-300">
                {isScanning ? "Active Probing" : "Idle / Standby"}
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* 3. WORKSPACE VIEW SWITCHER */}
      <div className="flex items-center border-b border-slate-800 bg-slate-900/40 px-6">
        <div className="flex gap-6 text-xs font-medium">
          <button
            onClick={() => setActiveTab("graph")}
            className={`py-3 border-b-2 flex items-center gap-2 transition-all ${
              activeTab === "graph"
                ? "border-cyan-400 text-cyan-300 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Cpu className="h-4 w-4" /> Interactive Attack Graph
          </button>
          <button
            onClick={() => setActiveTab("findings")}
            className={`py-3 border-b-2 flex items-center gap-2 transition-all ${
              activeTab === "findings"
                ? "border-cyan-400 text-cyan-300 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Layers className="h-4 w-4" /> Findings Matrix
          </button>
          <button
            onClick={() => setActiveTab("inventory")}
            className={`py-3 border-b-2 flex items-center gap-2 transition-all ${
              activeTab === "inventory"
                ? "border-cyan-400 text-cyan-300 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Globe className="h-4 w-4" /> Host Inventory
          </button>
          <button
            onClick={() => setActiveTab("reasoning")}
            className={`py-3 border-b-2 flex items-center gap-2 transition-all ${
              activeTab === "reasoning"
                ? "border-cyan-400 text-cyan-300 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Activity className="h-4 w-4" /> Chain-of-Thought Stream
          </button>
          <button
            onClick={() => setActiveTab("approvals")}
            className={`py-3 border-b-2 flex items-center gap-2 transition-all ${
              activeTab === "approvals"
                ? "border-cyan-400 text-cyan-300 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <AlertTriangle className="h-4 w-4 text-amber-400" /> High-Risk Approval Queue
          </button>
        </div>
      </div>

      {/* 4. MAIN VIEWPORT */}
      <main className="flex-1 overflow-y-auto p-5 bg-slate-950">
        {activeTab === "graph" && (
          <div className="h-full">
            <AttackGraph
              engagementId={id}
              onSelectFinding={(f) => {
                setSelectedFinding(f);
                setActiveTab("findings");
              }}
            />
          </div>
        )}

        {activeTab === "findings" && (
          <FindingsTable
            engagementId={id}
            onRequestFix={() => navigate("/remediation")}
          />
        )}

        {activeTab === "inventory" && (
          <div className="max-w-4xl mx-auto">
            <HostInventory engagementId={id} />
          </div>
        )}

        {activeTab === "reasoning" && (
          <div className="max-w-4xl mx-auto h-[600px]">
            <ReasoningTimeline engagementId={id} />
          </div>
        )}

        {activeTab === "approvals" && (
          <div className="max-w-3xl mx-auto">
            <ApprovalQueue engagementId={id} userRole={user?.role} />
          </div>
        )}
      </main>
    </div>
  );
}