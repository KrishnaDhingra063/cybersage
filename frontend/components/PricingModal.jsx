import React from "react";
import { X, Check, Zap, Shield, Building } from "lucide-react";

export default function PricingModal({ isOpen, onClose }) {
  if (!isOpen) return null;

  const tiers = [
    {
      name: "Community",
      badge: "BYO-AI",
      price: "₹0",
      period: "forever",
      desc: "Ideal for students, solo researchers, and local hardware testing.",
      icon: Zap,
      features: [
        "Local Ollama models (CPU / 3B)",
        "1 Concurrent Target Host",
        "Human-in-the-Loop Gating",
        "Raw Terminal Scans (Nmap/Nikto)",
        "Community Support",
      ],
      button: "Current Plan",
      current: true,
    },
    {
      name: "Security Pro",
      badge: "Most Popular",
      price: "₹2,499",
      period: "/ month",
      desc: "For freelance security auditors & penetration testers.",
      icon: Shield,
      features: [
        "Cloud LLM Routing (Gemini & Claude)",
        "Up to 5 Concurrent Target Scopes",
        "Automated PDF Executive Reports",
        "Automated Code Fix Suggestions",
        "Attack Graph Visualizer",
      ],
      button: "Upgrade to Pro",
      current: false,
    },
    {
      name: "Enterprise",
      badge: "Teams & CI/CD",
      price: "₹19,999",
      period: "/ month",
      desc: "For software teams needing continuous DevSecOps compliance.",
      icon: Building,
      features: [
        "Unlimited Targets & Autonomous Recon",
        "CI/CD Pipeline Webhook Integration",
        "Role-Based Access (Lead vs Analyst)",
        "Automated Remediation Pull Requests",
        "SOC 2 & OWASP Top 10 Audit Packs",
      ],
      button: "Contact Sales",
      current: false,
    },
  ];

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-4xl w-full p-6 shadow-2xl relative">
        <div className="flex justify-between items-center pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Shield className="text-cyan-400" size={20} /> Subscription Plans & Business Model
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Continuous AI-driven penetration testing at ~85% lower cost than manual audits.
            </p>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white cursor-pointer">
            <X size={18} />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
          {tiers.map((t) => {
            const Icon = t.icon;
            return (
              <div
                key={t.name}
                className={`rounded-xl p-5 border flex flex-col justify-between ${
                  t.badge === "Most Popular"
                    ? "bg-slate-950/80 border-cyan-500/50 shadow-lg shadow-cyan-950/40"
                    : "bg-slate-950/40 border-slate-800"
                }`}
              >
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs font-semibold px-2 py-0.5 rounded bg-slate-800 text-cyan-300">
                      {t.badge}
                    </span>
                    <Icon size={18} className="text-slate-400" />
                  </div>
                  <h3 className="text-base font-bold text-white">{t.name}</h3>
                  <div className="mt-2 mb-3">
                    <span className="text-2xl font-black text-white">{t.price}</span>
                    <span className="text-xs text-slate-500 ml-1">{t.period}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mb-4">{t.desc}</p>
                  <ul className="space-y-2 border-t border-slate-800/80 pt-3 text-[11px] text-slate-300">
                    {t.features.map((f) => (
                      <li key={f} className="flex items-center gap-2">
                        <Check size={12} className="text-cyan-400 shrink-0" />
                        <span>{f}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <button
                  type="button"
                  onClick={onClose}
                  className={`mt-6 w-full py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                    t.current
                      ? "bg-slate-800 text-slate-400 cursor-default"
                      : "bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-950/50"
                  }`}
                >
                  {t.button}
                </button>
              </div>
            );
          })}
        </div>

        <div className="mt-5 p-3 rounded-lg bg-slate-950 border border-slate-800/80 text-[11px] text-slate-400 flex justify-between items-center">
          <span><strong>Unit Economics:</strong> Local Ollama self-hosting provides ₹0 inference costs for entry-level tiers.</span>
          <span className="text-cyan-400 font-mono">Margin: ~80% Gross Profit</span>
        </div>
      </div>
    </div>
  );
}