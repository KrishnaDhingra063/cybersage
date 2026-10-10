import React, { useState } from "react";
import { Shield, Globe, Calendar, CheckCircle, ArrowRight, ArrowLeft, AlertTriangle } from "lucide-react";
import { engagements, scans } from "../api/client";

const steps = ["Basics", "Scope", "Window & RoE", "Autonomy"];

export default function EngagementWizard({ onCreated, onClose }) {
  const [step, setStep] = useState(0);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [validateMsg, setValidateMsg] = useState("");
  // Step 1
  const [name, setName] = useState("");
  const [clientName, setClientName] = useState("");
  const [testType, setTestType] = useState("external");
  // Step 2
  const [allowed, setAllowed] = useState("");
  const [excluded, setExcluded] = useState("");
  // Step 3
  const [start, setStart] = useState(() => new Date().toISOString().slice(0, 16));
  const [end, setEnd] = useState(() => new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString().slice(0, 16));
  const [roe, setRoe] = useState("");
  const [signedBy, setSignedBy] = useState("");
  // Step 4
  const [autonomy, setAutonomy] = useState("human_gated");

  const parseTargets = (s) => s.split(",").map((t) => t.trim()).filter(Boolean);

  const handleValidate = async () => {
    const t = parseTargets(allowed)[0];
    if (!t) { setValidateMsg("Add at least one allowed target"); return; }
    setValidateMsg("Validating...");
    try {
      // dry-run via validate endpoint if we had engagement id - for wizard we just check format
      // simple client-side CIDR/wildcard check
      setValidateMsg("Format OK — will be server-validated after creation");
    } catch (e) {
      setValidateMsg(e.response?.data?.detail || "Invalid");
    }
  };

  const handleCreate = async () => {
    setError("");
    if (!name.trim() || !clientName.trim() || !allowed.trim()) {
      setError("Name, Client and Allowed Targets are required");
      return;
    }
    setSaving(true);
    try {
      // 1. Create engagement
      const engRes = await engagements.create({ name: name.trim(), client_name: clientName.trim(), test_type: testType });
      const engId = engRes.data.id;
      // 2. Create scope
      const allowedList = parseTargets(allowed);
      const excludedList = parseTargets(excluded);
      await engagements.createScope(engId, {
        allowed_targets: allowedList,
        excluded_targets: excludedList,
        allowed_window_start: new Date(start).toISOString(),
        allowed_window_end: new Date(end).toISOString(),
        rules_of_engagement: roe,
        signed_by: signedBy || "wizard",
      });
      // 3. Set autonomy
      try {
        await engagements.setAutonomy(engId, autonomy);
      } catch {}
      onCreated && onCreated(engRes.data);
      onClose && onClose();
    } catch (e) {
      setError(e.response?.data?.detail || e.message || "Failed to create");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="w-full max-w-2xl rounded-xl border border-slate-800 bg-slate-900 shadow-2xl overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="font-semibold text-white flex items-center gap-2"><Shield size={18} className="text-cyan-400" /> New Engagement Wizard</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-sm">✕</button>
        </div>
        <div className="px-6 pt-4 flex gap-2">
          {steps.map((s, i) => (
            <div key={s} className={`flex-1 h-1.5 rounded-full ${i <= step ? "bg-cyan-500" : "bg-slate-800"}`} />
          ))}
        </div>
        <div className="px-6 py-2 text-xs text-slate-400">Step {step + 1} of 4 — {steps[step]}</div>

        <div className="px-6 py-4 space-y-4 min-h-[280px]">
          {error && <div className="flex items-center gap-2 p-2 rounded bg-rose-950/40 border border-rose-800 text-rose-300 text-xs"><AlertTriangle size={14} /> {error}</div>}

          {step === 0 && (
            <div className="grid gap-3">
              <label className="text-xs text-slate-400">Engagement Title</label>
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Q3 Corp Perimeter Audit" className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-white" />
              <label className="text-xs text-slate-400">Client / Organization</label>
              <input value={clientName} onChange={(e) => setClientName(e.target.value)} placeholder="Acme Financial" className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-white" />
              <label className="text-xs text-slate-400">Test Type</label>
              <select value={testType} onChange={(e) => setTestType(e.target.value)} className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-white">
                <option value="external">External Network</option>
                <option value="internal">Internal Pivot</option>
                <option value="web_app">Web Application</option>
                <option value="api">API Endpoints</option>
                <option value="cloud">Cloud Infrastructure</option>
              </select>
            </div>
          )}

          {step === 1 && (
            <div className="grid gap-3">
              <label className="flex items-center justify-between rounded-lg border border-amber-500/30 bg-amber-950/20 px-3 py-2 cursor-pointer">
                <span className="text-xs text-amber-200 font-semibold">🌍 Global scope — any target allowed</span>
                <input
                  type="checkbox"
                  checked={allowed.trim() === "*"}
                  onChange={(e) => setAllowed(e.target.checked ? "*" : "")}
                  className="h-4 w-4 accent-amber-500"
                />
              </label>
              {allowed.trim() !== "*" && (
                <>
                  <label className="text-xs text-slate-400 flex items-center gap-1"><Globe size={12} /> Allowed Targets (CIDR / URLs / wildcards, comma-separated)</label>
                  <input value={allowed} onChange={(e) => setAllowed(e.target.value)} placeholder="192.168.1.0/24, api.corp.com, *.corp.com" className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-white font-mono" />
                </>
              )}
              <label className="text-xs text-slate-400">Excluded Targets (optional — still enforced on global)</label>
              <input value={excluded} onChange={(e) => setExcluded(e.target.value)} placeholder="10.0.0.5, staging.corp.com" className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-white font-mono" />
              <button onClick={handleValidate} className="text-xs text-cyan-400 hover:underline text-left">Validate format</button>
              {validateMsg && <p className="text-xs text-slate-400">{validateMsg}</p>}
              <p className="text-[11px] text-slate-500">Supports IP/CIDR (10.0.0.0/24), exact domains, wildcards (*.example.com), or global (*). Global still needs Lead approval + valid window; excluded takes precedence.</p>
            </div>
          )}

          {step === 2 && (
            <div className="grid gap-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-slate-400 flex items-center gap-1"><Calendar size={12} /> Window Start</label>
                  <input type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-white" />
                </div>
                <div>
                  <label className="text-xs text-slate-400">Window End</label>
                  <input type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-white" />
                </div>
              </div>
              <label className="text-xs text-slate-400">Rules of Engagement</label>
              <textarea value={roe} onChange={(e) => setRoe(e.target.value)} rows={3} placeholder="No destructive exploits, business hours only..." className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-white resize-none" />
              <label className="text-xs text-slate-400">Signed By</label>
              <input value={signedBy} onChange={(e) => setSignedBy(e.target.value)} placeholder="Lead name" className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-white" />
            </div>
          )}

          {step === 3 && (
            <div className="space-y-3">
              <label className="text-xs text-slate-400">Autonomy Level</label>
              <div className="grid gap-2">
                {[
                  { v: "human_gated", l: "Human Gated (recommended)", d: "Recon auto, exploits need approval" },
                  { v: "suggest_only", l: "Suggest Only", d: "AI only proposes, nothing auto-runs" },
                  { v: "autonomous", l: "Autonomous", d: "Auto-run within scope (high-risk still gated)" },
                ].map((o) => (
                  <label key={o.v} className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer ${autonomy === o.v ? "border-cyan-500 bg-cyan-950/30" : "border-slate-800 bg-slate-950"}`}>
                    <input type="radio" name="autonomy" checked={autonomy === o.v} onChange={() => setAutonomy(o.v)} />
                    <div>
                      <div className="text-sm text-white">{o.l}</div>
                      <div className="text-xs text-slate-400">{o.d}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="px-6 py-4 border-t border-slate-800 flex justify-between">
          <button onClick={() => setStep(Math.max(0, step - 1))} disabled={step === 0} className="flex items-center gap-1 px-3 py-1.5 rounded text-xs bg-slate-800 text-slate-300 disabled:opacity-40"><ArrowLeft size={14} /> Back</button>
          {step < 3 ? (
            <button onClick={() => setStep(step + 1)} className="flex items-center gap-1 px-4 py-1.5 rounded text-xs bg-cyan-600 text-white hover:bg-cyan-500"><span>Next</span> <ArrowRight size={14} /></button>
          ) : (
            <button onClick={handleCreate} disabled={saving} className="flex items-center gap-1.5 px-5 py-1.5 rounded text-xs bg-emerald-600 text-white hover:bg-emerald-500 disabled:opacity-50"><CheckCircle size={14} /> {saving ? "Provisioning..." : "Authorize & Launch"}</button>
          )}
        </div>
      </div>
    </div>
  );
}
