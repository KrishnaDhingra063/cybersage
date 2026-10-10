import React, { useState, useEffect } from "react";
import axios from "axios";
import { Shield, Key, Users, Check, User as UserIcon, Mail, Phone, FileText, Lock, Save, AlertCircle, CheckCircle2, Sparkles, Sun, Moon, UserPlus } from "lucide-react";
import { useAuth } from "../auth";
import { auth as authApi } from "../api/client";

function getTheme() {
  try {
    return localStorage.getItem("pentestai_theme") || "dark";
  } catch {
    return "dark";
  }
}

function applyTheme(t) {
  try {
    localStorage.setItem("pentestai_theme", t);
  } catch {}
  try {
    if (t === "light") document.documentElement.classList.add("light");
    else document.documentElement.classList.remove("light");
  } catch {}
}

export default function Settings() {
  const { user, isLead, refreshProfile } = useAuth();
  const [activeTab, setActiveTab] = useState("account"); // account | security | system
  const [usersList, setUsersList] = useState([]);

  // Account form
  const [profile, setProfile] = useState({
    full_name: "",
    username: "",
    email: "",
    phone_number: "",
    bio: "",
  });
  const [profileMsg, setProfileMsg] = useState({ type: "", text: "" });
  const [savingProfile, setSavingProfile] = useState(false);

  // Security form
  const [pwd, setPwd] = useState({ current: "", next: "", confirm: "" });
  const [pwdMsg, setPwdMsg] = useState({ type: "", text: "" });
  const [savingPwd, setSavingPwd] = useState(false);

  // 2FA
  const [twofa, setTwofa] = useState({ enabled: false, secret: "", url: "", code: "", msg: { type: "", text: "" } });
  // Sessions + API tokens
  const [sessions, setSessions] = useState([]);
  const [tokens, setTokens] = useState([]);
  const [tokenForm, setTokenForm] = useState({ name: "ci", expires_days: 90 });
  const [secMsg, setSecMsg] = useState({ type: "", text: "" });

  // BYOK
  const [apiKey, setApiKey] = useState(localStorage.getItem("anthropic_api_key") || "");
  const [savedKey, setSavedKey] = useState(false);

  // Theme (dark/light, persisted)
  const [theme, setTheme] = useState(getTheme);

  // RootX team-create (lead creates account + picks role)
  const [teamForm, setTeamForm] = useState({ username: "", email: "", password: "", role: "analyst" });
  const [teamMsg, setTeamMsg] = useState({ type: "", text: "" });

  // Populate profile from user on mount / when user changes
  useEffect(() => {
    if (user) {
      setProfile({
        full_name: user.full_name || "",
        username: user.username || "",
        email: user.email || "",
        phone_number: user.phone_number || "",
        bio: user.bio || "",
      });
    }
  }, [user]);

  // Refresh full profile from server once (repairs stale role/is_founder after demote bug)
  useEffect(() => {
    if (refreshProfile) refreshProfile().then((m) => {
      if (m) setTwofa((t) => ({ ...t, enabled: !!m.totp_enabled }));
    }).catch(() => {});
    applyTheme(getTheme());
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const loadSecLists = async () => {
    try {
      const s = await authApi.sessions();
      setSessions(s.data || []);
    } catch {}
    try {
      const t = await authApi.listTokens();
      setTokens(t.data || []);
    } catch {}
  };

  useEffect(() => {
    if (activeTab === "security") loadSecLists();
  }, [activeTab]);

  useEffect(() => {
    if (isLead) {
      axios
        .get("/api/users", {
          headers: { Authorization: `Bearer ${localStorage.getItem("token")}` },
        })
        .then((res) => setUsersList(res.data))
        .catch(() => {});
    }
  }, [isLead]);

  const handleSaveProfile = async (e) => {
    e.preventDefault();
    setProfileMsg({ type: "", text: "" });
    setSavingProfile(true);
    try {
      const payload = {
        full_name: profile.full_name.trim(),
        username: profile.username.trim(),
        email: profile.email.trim(),
        phone_number: profile.phone_number.trim(),
        bio: profile.bio.trim(),
      };
      await authApi.updateMe(payload);
      await refreshProfile();
      setProfileMsg({ type: "success", text: "Profile updated. Chat greeting will now use your new name." });
    } catch (err) {
      setProfileMsg({ type: "error", text: err.response?.data?.detail || err.message || "Failed to update profile" });
    } finally {
      setSavingProfile(false);
      setTimeout(() => setProfileMsg({ type: "", text: "" }), 4000);
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setPwdMsg({ type: "", text: "" });
    if (pwd.next !== pwd.confirm) {
      setPwdMsg({ type: "error", text: "New passwords do not match" });
      return;
    }
    if (pwd.next.length < 6) {
      setPwdMsg({ type: "error", text: "New password must be at least 6 characters" });
      return;
    }
    setSavingPwd(true);
    try {
      await authApi.changePassword({ current_password: pwd.current, new_password: pwd.next });
      setPwdMsg({ type: "success", text: "Password changed successfully" });
      setPwd({ current: "", next: "", confirm: "" });
    } catch (err) {
      setPwdMsg({ type: "error", text: err.response?.data?.detail || "Failed to change password" });
    } finally {
      setSavingPwd(false);
    }
  };

  const handleSaveApiKey = () => {
    localStorage.setItem("anthropic_api_key", apiKey);
    setSavedKey(true);
    setTimeout(() => setSavedKey(false), 2000);
  };

  const apiBase = ""; // relative /api via proxy (fixes hardcoded localhost:8000 failures)

  const handlePromote = async (userId, targetRole) => {
    // Founder can never be demoted (backend 403 too). Never demote yourself.
    const target = usersList.find((u) => u.id === userId);
    if (target?.is_founder && targetRole !== "lead") {
      alert("Founder is always Lead and can't be demoted.");
      return;
    }
    if (target && user && (target.id === user.user_id) && targetRole !== "lead") {
      alert("You can't demote yourself.");
      return;
    }
    try {
      if (targetRole === "lead") {
        await axios.post(`${apiBase}/api/users/${userId}/promote`, {}, { headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } });
      } else {
        await axios.post(`${apiBase}/api/users/${userId}/demote`, {}, { headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } });
      }
      setUsersList((prev) => prev.map((u) => (u.id === userId ? { ...u, role: targetRole } : u)));
    } catch (err) {
      alert(err.response?.data?.detail || "Action unauthorized");
    }
  };

  const handleCreateTeam = async (e) => {
    e.preventDefault();
    setTeamMsg({ type: "", text: "" });
    try {
      const res = await axios.post(`${apiBase}/api/users/create`, teamForm, { headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } });
      setTeamMsg({ type: "success", text: `Created ${res.data.username} as ${res.data.role}. Share the login credentials with them.` });
      setTeamForm({ username: "", email: "", password: "", role: "analyst" });
      // refresh roster
      const r = await axios.get(`${apiBase}/api/users`, { headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } });
      setUsersList(r.data || []);
    } catch (err) {
      setTeamMsg({ type: "error", text: err.response?.data?.detail || "Failed to create account" });
    }
  };

  const handleTheme = (t) => {
    setTheme(t);
    applyTheme(t);
  };

  const tabs = [
    { id: "account", label: "Account", icon: UserIcon },
    { id: "security", label: "Security", icon: Lock },
    { id: "system", label: "System", icon: Shield },
  ];

  function AuditPanel() {
    const [rows, setRows] = React.useState([]);
    React.useEffect(() => {
      axios.get("/api/users/audit/list", { params: { limit: 50 }, headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } })
        .then((r) => setRows(r.data || [])).catch(() => {});
    }, []);
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
        <h2 className="text-sm font-semibold text-white mb-1">Audit trail — who did what, when</h2>
        <p className="text-[11px] text-slate-500 mb-3">Logins, 2FA, approvals, role changes, PRs, uploads, backups.</p>
        <div className="space-y-1.5 max-h-64 overflow-y-auto">
          {rows.map((a) => (
            <div key={a.id} className="flex items-center gap-2 text-xs rounded-lg border border-slate-800 bg-slate-950/60 px-2.5 py-1.5">
              <span className="font-mono text-cyan-300">{a.action}</span>
              <span className="text-slate-300">{a.actor || "?"}</span>
              <span className="text-slate-500 truncate">{a.detail?.slice(0, 80)}</span>
              <span className="ml-auto font-mono text-[10px] text-slate-600 shrink-0">{a.created_at?.slice(0, 16).replace("T", " ")}</span>
            </div>
          ))}
          {rows.length === 0 && <p className="text-xs text-slate-600">No audit events yet.</p>}
        </div>
      </div>
    );
  }

  function BackupPanel() {
    const [msg, setMsg] = React.useState("");
    const download = async () => {
      setMsg("Preparing encrypted backup…");
      try {
        const r = await axios.get("/api/admin/backup", { headers: { Authorization: `Bearer ${localStorage.getItem("token")}` }, responseType: "blob" });
        const url = window.URL.createObjectURL(new Blob([r.data]));
        const a = document.createElement("a");
        a.href = url;
        a.download = "pentestai-backup.enc";
        a.click();
        setMsg("Downloaded pentestai-backup.enc (Fernet-encrypted, key: BACKUP_KEY or JWT_SECRET).");
      } catch (e) {
        setMsg(e.response?.data?.detail || "Backup failed");
      }
    };
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
        <h2 className="text-sm font-semibold text-white">Encrypted backup (founder)</h2>
        <p className="text-[11px] text-slate-500 mt-1 mb-3">Users, engagements, hosts, findings snapshot encrypted with Fernet.</p>
        <button onClick={download} className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-white text-xs border border-slate-700">Download backup</button>
        {msg && <p className="text-xs text-slate-400 mt-2">{msg}</p>}
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto bg-slate-950 p-8 font-sans text-slate-100">
      <div className="mx-auto max-w-4xl space-y-6">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white">Settings</h1>
          <p className="text-xs text-slate-400 mt-1">
            Active Identity: <span className="font-semibold text-cyan-400">{user?.displayName || user?.full_name || user?.username}</span>
            <span className="mx-2 text-slate-600">|</span>
            Role: <span className="uppercase font-mono text-emerald-400 font-bold">{user?.role || "analyst"}</span>
            {user?.email && <span className="ml-2 font-mono text-slate-500">{user.email}</span>}
          </p>
        </div>

        {/* Tab bar */}
        <div className="flex gap-2 border-b border-slate-800 pb-2">
          {tabs.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${activeTab === id ? "bg-cyan-500/10 text-cyan-300 border-cyan-500/30" : "text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-900"}`}
            >
              <Icon size={14} /> {label}
            </button>
          ))}
          <div className="ml-auto flex items-center gap-1.5 text-[11px] text-slate-500">
            <Sparkles size={12} className="text-cyan-400" /> Chat shows personalized greeting
          </div>
        </div>

        {/* ACCOUNT TAB */}
        {activeTab === "account" && (
          <div className="space-y-6">
            <form onSubmit={handleSaveProfile} className="rounded-xl border border-slate-800 bg-slate-900/40 p-5 space-y-4">
              <div className="flex items-center gap-2">
                <UserIcon className="h-4 w-4 text-cyan-400" />
                <h2 className="text-sm font-semibold text-white">Profile — shown in chat greeting</h2>
                <span className="ml-auto text-[11px] text-slate-500">Weekend / time-of-day quotes use your name</span>
              </div>

              {profileMsg.text && (
                <div className={`flex items-center gap-2 p-2.5 rounded-lg text-xs border ${profileMsg.type === "success" ? "bg-emerald-950/40 border-emerald-800 text-emerald-300" : "bg-rose-950/40 border-rose-800 text-rose-300"}`}>
                  {profileMsg.type === "success" ? <CheckCircle2 size={14} /> : <AlertCircle size={14} />} {profileMsg.text}
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Display Name (shown as “Hello Depanshu”)</label>
                  <input value={profile.full_name} onChange={(e) => setProfile({ ...profile, full_name: e.target.value })} placeholder="Depanshu" className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-600 focus:border-cyan-500 focus:outline-none" />
                  <p className="text-[11px] text-slate-500 mt-1">Used for morning/evening/weekend greetings.</p>
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Username</label>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-600">@</span>
                    <input value={profile.username} onChange={(e) => setProfile({ ...profile, username: e.target.value })} className="flex-1 rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none" />
                  </div>
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1 flex items-center gap-1"><Mail size={12} /> Email</label>
                  <input type="email" value={profile.email} onChange={(e) => setProfile({ ...profile, email: e.target.value })} placeholder="you@example.com" className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-600 focus:border-cyan-500 focus:outline-none" />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1 flex items-center gap-1"><Phone size={12} /> Phone No.</label>
                  <input value={profile.phone_number} onChange={(e) => setProfile({ ...profile, phone_number: e.target.value })} placeholder="+91 9xxxxxxxxx" className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-600 focus:border-cyan-500 focus:outline-none" />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-xs text-slate-400 mb-1 flex items-center gap-1"><FileText size={12} /> About / Bio</label>
                  <textarea value={profile.bio} onChange={(e) => setProfile({ ...profile, bio: e.target.value })} rows={3} placeholder="Security analyst, weekend hunter, etc. This will be shown on your profile and can be used for future personalization." className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-600 focus:border-cyan-500 focus:outline-none resize-none" />
                  <p className="text-[11px] text-slate-500 mt-1">{profile.bio.length}/500</p>
                </div>
              </div>

              <div className="flex justify-between items-center pt-2">
                <p className="text-xs text-slate-500">Gmail logins auto-fill Display Name — you can edit it here.</p>
                <button type="submit" disabled={savingProfile} className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-5 py-2 text-sm font-semibold text-white hover:bg-cyan-500 disabled:opacity-50">
                  <Save size={14} /> {savingProfile ? "Saving..." : "Save Profile"}
                </button>
              </div>
            </form>

            {/* Extensible placeholder - user said "and also add some of thing whenever its come on my mind" */}
            <div className="rounded-xl border border-dashed border-slate-800 bg-slate-900/20 p-5">
              <h3 className="text-xs font-semibold text-slate-300 flex items-center gap-2"><Sparkles size={12} className="text-violet-400" /> Future preferences — placeholders</h3>
              <p className="text-xs text-slate-500 mt-2 leading-relaxed">
                This area is designed to be extensible. Next you can add: notification prefs, theme (dark/light), language, timezone for greeting, workload alerts, connected Slack/Discord, API webhook URLs. Tell me what’s on your mind and I’ll wire it here without touching the chat logic.
              </p>
              <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
                <span className="px-2 py-1 rounded bg-slate-800 text-slate-400">Timezone: Auto (browser)</span>
                <span className="px-2 py-1 rounded bg-slate-800 text-slate-400">Greeting style: Time + Weekend + Workload</span>
                <span className="px-2 py-1 rounded bg-slate-800 text-slate-400">Add more → just ask</span>
              </div>
            </div>
          </div>
        )}

        {/* SECURITY TAB */}
        {activeTab === "security" && (
          <div className="space-y-6">
            <form onSubmit={handleChangePassword} className="rounded-xl border border-slate-800 bg-slate-900/40 p-5 space-y-4">
              <div className="flex items-center gap-2">
                <Lock className="h-4 w-4 text-amber-400" />
                <h2 className="text-sm font-semibold text-white">Change Password</h2>
              </div>
              {pwdMsg.text && (
                <div className={`flex items-center gap-2 p-2.5 rounded-lg text-xs border ${pwdMsg.type === "success" ? "bg-emerald-950/40 border-emerald-800 text-emerald-300" : "bg-rose-950/40 border-rose-800 text-rose-300"}`}>
                  {pwdMsg.type === "success" ? <CheckCircle2 size={14} /> : <AlertCircle size={14} />} {pwdMsg.text}
                </div>
              )}
              <div className="grid gap-3 max-w-md">
                <input type="password" placeholder="Current password" value={pwd.current} onChange={(e) => setPwd({ ...pwd, current: e.target.value })} className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-600 focus:border-amber-500 focus:outline-none" required />
                <input type="password" placeholder="New password (min 6 chars)" value={pwd.next} onChange={(e) => setPwd({ ...pwd, next: e.target.value })} className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-600 focus:border-cyan-500 focus:outline-none" required />
                <input type="password" placeholder="Confirm new password" value={pwd.confirm} onChange={(e) => setPwd({ ...pwd, confirm: e.target.value })} className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-600 focus:border-cyan-500 focus:outline-none" required />
              </div>
              <button type="submit" disabled={savingPwd} className="rounded-lg bg-amber-600 px-5 py-2 text-sm font-semibold text-white hover:bg-amber-500 disabled:opacity-50">
                {savingPwd ? "Updating..." : "Update Password"}
              </button>
              <p className="text-xs text-slate-500">Gmail users without a password can set one here after OTP verification via Forgot Password flow.</p>
            </form>

            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5 space-y-3">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-emerald-400" />
                <h2 className="text-sm font-semibold text-white">Two-Factor Auth (TOTP)</h2>
                <span className={`ml-auto text-[11px] px-2 py-0.5 rounded-full border ${twofa.enabled ? "bg-emerald-950/40 border-emerald-800 text-emerald-300" : "bg-slate-800 border-slate-700 text-slate-400"}`}>{twofa.enabled ? "ON" : "OFF"}</span>
              </div>
              {twofa.msg.text && <p className={`text-xs ${twofa.msg.type === "success" ? "text-emerald-300" : "text-rose-300"}`}>{twofa.msg.text}</p>}
              {!twofa.enabled ? (
                <div className="space-y-2">
                  <button
                    onClick={async () => {
                      try {
                        const r = await authApi.setup2fa();
                        setTwofa((t) => ({ ...t, secret: r.data.secret, url: r.data.otpauth_url, msg: { type: "", text: "" } }));
                      } catch (e) { setTwofa((t) => ({ ...t, msg: { type: "error", text: e.response?.data?.detail || "Setup failed" } })); }
                    }}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-white text-xs border border-slate-700"
                  >
                    Generate secret
                  </button>
                  {twofa.secret && (
                    <div className="space-y-2 rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                      <p className="text-xs text-slate-400">1. Add to your authenticator app (Google/Microsoft Authy):</p>
                      <p className="text-xs font-mono text-cyan-300 break-all">{twofa.secret}</p>
                      <p className="text-[11px] text-slate-500 break-all">{twofa.url}</p>
                      <div className="flex gap-2">
                        <input value={twofa.code} onChange={(e) => setTwofa((t) => ({ ...t, code: e.target.value.replace(/\D/g, "") }))} placeholder="6-digit code" maxLength={6} className="w-32 rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs text-white font-mono text-center tracking-widest" />
                        <button
                          onClick={async () => {
                            try {
                              await authApi.enable2fa(twofa.code);
                              setTwofa((t) => ({ ...t, enabled: true, secret: "", url: "", code: "", msg: { type: "success", text: "2FA enabled. Login will now ask for a code." } }));
                              if (refreshProfile) refreshProfile().catch(() => {});
                            } catch (e) { setTwofa((t) => ({ ...t, msg: { type: "error", text: e.response?.data?.detail || "Invalid code" } })); }
                          }}
                          className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold"
                        >
                          Verify & Enable
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="flex gap-2 items-center">
                  <input value={twofa.code} onChange={(e) => setTwofa((t) => ({ ...t, code: e.target.value.replace(/\D/g, "") }))} placeholder="code to disable" maxLength={6} className="w-32 rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs text-white font-mono text-center tracking-widest" />
                  <button
                    onClick={async () => {
                      try {
                        await authApi.disable2fa(twofa.code);
                        setTwofa({ enabled: false, secret: "", url: "", code: "", msg: { type: "success", text: "2FA disabled." } });
                        if (refreshProfile) refreshProfile().catch(() => {});
                      } catch (e) { setTwofa((t) => ({ ...t, msg: { type: "error", text: e.response?.data?.detail || "Invalid code" } })); }
                    }}
                    className="px-3 py-1.5 rounded bg-rose-800 hover:bg-rose-700 text-white text-xs"
                  >
                    Disable 2FA
                  </button>
                </div>
              )}
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5 space-y-3">
              <h2 className="text-sm font-semibold text-white">Active sessions (this + other devices)</h2>
              <p className="text-[11px] text-slate-500">JWTs carry a session id — revoke any device here. Old tokens without id keep working until expiry.</p>
              {sessions.map((s) => (
                <div key={s.id} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs">
                  <div>
                    <p className="text-slate-200 truncate max-w-[280px]">{s.user_agent || "unknown device"}</p>
                    <p className="text-[11px] font-mono text-slate-500">{s.ip || "no ip"} · {s.created_at?.slice(0, 16).replace("T", " ")} {s.revoked && "· revoked"}</p>
                  </div>
                  {!s.revoked && <button onClick={async () => { try { await authApi.revokeSession(s.id); loadSecLists(); } catch {} }} className="px-2 py-1 rounded bg-slate-800 hover:bg-rose-800 text-slate-300 text-[11px] border border-slate-700">Revoke</button>}
                </div>
              ))}
              {sessions.length === 0 && <p className="text-xs text-slate-600">No sessions recorded yet — login again to register this device.</p>}
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5 space-y-3">
              <h2 className="text-sm font-semibold text-white">API tokens (CI) — <span className="font-mono">ptx_…</span> with expiry</h2>
              <p className="text-[11px] text-slate-500">Use as <span className="font-mono">Authorization: Bearer ptx_…</span>. Secret shown once, only the hash is stored.</p>
              <div className="flex gap-2">
                <input value={tokenForm.name} onChange={(e) => setTokenForm({ ...tokenForm, name: e.target.value })} placeholder="name (ci)" className="flex-1 rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs text-white" />
                <select value={tokenForm.expires_days} onChange={(e) => setTokenForm({ ...tokenForm, expires_days: parseInt(e.target.value, 10) })} className="rounded-lg border border-slate-800 bg-slate-950 px-2 py-1.5 text-xs text-white">
                  <option value={7}>7 days</option>
                  <option value={30}>30 days</option>
                  <option value={90}>90 days</option>
                </select>
                <button
                  onClick={async () => {
                    try {
                      const r = await authApi.createToken(tokenForm.name, tokenForm.expires_days);
                      setSecMsg({ type: "success", text: `Copy now (once): ${r.data.token}` });
                      loadSecLists();
                    } catch (e) { setSecMsg({ type: "error", text: e.response?.data?.detail || "Failed" }); }
                  }}
                  className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold"
                >
                  Create
                </button>
              </div>
              {secMsg.text && <p className={`text-xs break-all ${secMsg.type === "success" ? "text-emerald-300" : "text-rose-300"}`}>{secMsg.text}</p>}
              {tokens.map((t) => (
                <div key={t.id} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs">
                  <div>
                    <p className="text-slate-200">{t.name} <span className="font-mono text-slate-500">{t.prefix}…</span></p>
                    <p className="text-[11px] font-mono text-slate-500">exp {t.expires_at?.slice(0, 10)} {t.revoked && "· revoked"}</p>
                  </div>
                  {!t.revoked && <button onClick={async () => { try { await authApi.revokeToken(t.id); loadSecLists(); } catch {} }} className="px-2 py-1 rounded bg-slate-800 hover:bg-rose-800 text-slate-300 text-[11px] border border-slate-700">Revoke</button>}
                </div>
              ))}
            </div>

            <div className="rounded-xl border border-slate-800/60 bg-slate-900/20 p-4 flex items-start gap-3">
              <Shield className="h-5 w-5 text-slate-600 shrink-0" />
              <div className="text-xs text-slate-400 leading-relaxed">
                <span className="font-semibold text-slate-300">Account protection:</span> JWT (24h, HttpOnly cookie + header) with session revoke, TOTP 2FA, OTP email resets, scope-gated tools, rate-limited auth.
              </div>
            </div>
          </div>
        )}

        {/* SYSTEM TAB - Theme + BYOK + RootX team + roster */}
        {activeTab === "system" && (
          <div className="space-y-6">
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
              <div className="flex items-center gap-2 mb-3">
                {theme === "light" ? <Sun className="h-4 w-4 text-amber-400" /> : <Moon className="h-4 w-4 text-violet-400" />}
                <h2 className="text-sm font-semibold text-white">Appearance — Dark / Light</h2>
                <span className="ml-auto text-[11px] text-slate-500">Saved per browser, applied instantly</span>
              </div>
              <div className="flex gap-2">
                {(["dark", "light"]).map((t) => (
                  <button
                    key={t}
                    onClick={() => handleTheme(t)}
                    className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold border capitalize ${theme === t ? "bg-cyan-500/10 text-cyan-300 border-cyan-500/40" : "text-slate-400 border-slate-800 hover:bg-slate-900"}`}
                  >
                    {t === "dark" ? <Moon size={13} /> : <Sun size={13} />} {t}
                  </button>
                ))}
              </div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
              <div className="flex items-center gap-2 mb-3">
                <Key className="h-4 w-4 text-cyan-400" />
                <h2 className="text-sm font-semibold text-white">AI Engine Credentials (BYOK)</h2>
              </div>
              <p className="text-xs text-slate-400 mb-4 leading-relaxed">Standard scans run via Gemini Flash. To unlock deep reasoning models like Claude 3.7 Sonnet or GPT-4o, supply your personal API key. Keys stay in your browser session.</p>
              <div className="flex gap-3">
                <input type="password" placeholder="sk-ant-api03-..." value={apiKey} onChange={(e) => setApiKey(e.target.value)} className="flex-1 rounded-lg border border-slate-800 bg-slate-950 px-3.5 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:border-cyan-500 focus:outline-none" />
                <button onClick={handleSaveApiKey} className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-4 py-2 text-xs font-bold text-white hover:bg-cyan-500 transition-colors">
                  {savedKey ? <Check className="h-3.5 w-3.5 text-emerald-300" /> : null} {savedKey ? "Saved" : "Save Key"}
                </button>
              </div>
            </div>

            {isLead ? (
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <Users className="h-4 w-4 text-amber-400" />
                    <h2 className="text-sm font-semibold text-white">RootX Team — Create accounts + Roster</h2>
                  </div>
                  <span className="rounded bg-amber-950/60 border border-amber-800/40 px-2 py-0.5 text-[10px] font-bold text-amber-400 uppercase">Lead Clearance Only</span>
                </div>
                <form onSubmit={handleCreateTeam} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 mb-4 grid grid-cols-1 md:grid-cols-5 gap-2">
                  <input value={teamForm.username} onChange={(e) => setTeamForm({ ...teamForm, username: e.target.value })} placeholder="username (e.g. krishna)" className="rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs text-white" required minLength={3} />
                  <input value={teamForm.email} onChange={(e) => setTeamForm({ ...teamForm, email: e.target.value })} placeholder="email (optional)" className="rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs text-white" />
                  <input type="password" value={teamForm.password} onChange={(e) => setTeamForm({ ...teamForm, password: e.target.value })} placeholder="password (min 6)" className="rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs text-white" required minLength={6} />
                  <select value={teamForm.role} onChange={(e) => setTeamForm({ ...teamForm, role: e.target.value })} className="rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-xs text-white">
                    <option value="analyst">analyst</option>
                    <option value="lead">lead (founder only)</option>
                  </select>
                  <button type="submit" className="flex items-center justify-center gap-1 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-emerald-500"><UserPlus size={13} /> Create</button>
                  {teamMsg.text && <p className={`md:col-span-5 text-xs ${teamMsg.type === "success" ? "text-emerald-300" : "text-rose-300"}`}>{teamMsg.text}</p>}
                  <p className="md:col-span-5 text-[11px] text-slate-500">Example: create <span className="font-mono text-slate-300">krishna / analyst</span>, share credentials, they login at /login — no role select needed, role comes from your choice.</p>
                </form>
                <div className="divide-y divide-slate-800/80 border border-slate-800 rounded-lg overflow-hidden bg-slate-950/60">
                  {usersList.length === 0 ? (
                    <div className="p-4 text-xs text-slate-500 text-center">No other operators registered.</div>
                  ) : (
                    usersList.map((u) => (
                      <div key={u.id} className="flex items-center justify-between p-3.5 text-xs">
                        <div>
                          <div className="font-semibold text-slate-200 flex items-center gap-2">
                            {u.username}
                            {u.is_founder && <span className="rounded bg-violet-950 px-1.5 py-0.5 text-[9px] font-bold text-violet-400 border border-violet-800/40">Founder</span>}
                            {u.full_name && <span className="text-slate-400">({u.full_name})</span>}
                          </div>
                          <div className="text-[11px] font-mono text-slate-500">{u.email || "no email"} {u.phone_number ? `• ${u.phone_number}` : ""}</div>
                          {u.bio && <div className="text-[11px] text-slate-400 truncate max-w-[320px]">{u.bio}</div>}
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="rounded bg-slate-900 px-2 py-1 text-[10px] font-mono font-bold uppercase text-slate-300 border border-slate-800">{u.role}</span>
                          {u.is_founder ? (
                            <span className="text-[10px] text-violet-300 font-bold">Always Lead — can't demote</span>
                          ) : (user && u.id === user.user_id) ? (
                            <span className="text-[10px] text-slate-500">You — can't demote self</span>
                          ) : (
                            u.role === "analyst" ? (
                              <button onClick={() => handlePromote(u.id, "lead")} className="rounded bg-amber-600/20 border border-amber-600/40 px-2.5 py-1 text-[11px] font-bold text-amber-300 hover:bg-amber-600/40 transition-colors">Promote to Lead</button>
                            ) : (
                              <button onClick={() => handlePromote(u.id, "analyst")} className="rounded bg-rose-600/20 border border-rose-600/40 px-2.5 py-1 text-[11px] font-bold text-rose-300 hover:bg-rose-600/40 transition-colors">Demote to Analyst</button>
                            )
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-slate-800/60 bg-slate-900/20 p-4 flex items-center gap-3 text-xs text-slate-400">
                <Shield className="h-5 w-5 text-slate-600 shrink-0" />
                <div><span className="font-semibold text-slate-300">Standard Analyst Permissions Active:</span> You have discovery clearance. Exploit approvals and user management require Lead clearance.</div>
              </div>
            )}

            {isLead && <AuditPanel />}
            {user?.is_founder && <BackupPanel />}
          </div>
        )}
      </div>
    </div>
  );
}
