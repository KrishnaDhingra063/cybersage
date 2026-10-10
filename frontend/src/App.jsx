import React from 'react'
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom'
import { Shield, GitBranch, AlertTriangle, FileText, LogOut, Code2, Settings as SettingsIcon, Users } from 'lucide-react'
import { AuthProvider, useAuth } from './auth'
import LoginPage from './pages/LoginPage'
import Register from './pages/Register'
import Settings from './pages/Settings'
import EngagementList from './pages/EngagementList'
import EngagementDetail from './pages/EngagementDetail'
import FindingsTable from './components/FindingsTable'
import ApprovalQueue from './components/ApprovalQueue'
import ReportPreview from './pages/ReportPreview'
import FixesPage from './pages/FixesPage'
import AgentWorkspace from './pages/AgentWorkspace'
import GroupList from './pages/GroupList'
import GroupDetail from './pages/GroupDetail'

const navItems = [
  { path: '/', label: 'Agent', icon: Shield },
  { path: '/engagements', label: 'Engagements', icon: GitBranch },
  { path: '/groups', label: 'Groups', icon: Users },
  { path: '/alerts', label: 'Approval Queue', icon: AlertTriangle },
  { path: '/remediation', label: 'Remediation', icon: Code2 },
  { path: '/reports', label: 'Reports', icon: FileText },
  { path: '/settings', label: 'Settings', icon: SettingsIcon },
]

function Shell() {
  const { user, isLead, logout } = useAuth()

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100">
      <nav className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col">
        <div className="p-6 border-b border-slate-800">
          <h1 className="text-xl font-bold text-cyan-400 flex items-center gap-2">
            <Shield size={24} />
            PentestAI
          </h1>
          <p className="text-xs text-slate-400 mt-1">AI-Orchestrated Testing</p>
        </div>
        <div className="flex-1 p-4 space-y-1">
          {navItems.map(({ path, label, icon: Icon }) => (
            <NavLink
              key={path}
              to={path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800'
                }`
              }
            >
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </div>
        <div className="p-4 border-t border-slate-800">
          <div className="text-xs text-slate-400 mb-3">
            {user && (
              <>
                <p className="text-slate-200 font-medium">{user.username}</p>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                  isLead ? 'bg-purple-900/50 text-purple-300 border border-purple-800' : 'bg-slate-800 text-slate-300'
                }`}>
                  {isLead ? 'lead (approver)' : 'analyst (scanner)'}
                </span>
              </>
            )}
          </div>
          <button
            onClick={logout}
            className="flex items-center gap-2 text-xs text-slate-400 hover:text-rose-400 transition-colors"
          >
            <LogOut size={14} /> Sign out
          </button>
        </div>
      </nav>
      <main className="flex-1 overflow-hidden bg-slate-950">
        <Routes>
          <Route path="/" element={<AgentWorkspace />} />
          <Route path="/engagements" element={<EngagementList />} />
          <Route path="/engagement/:id" element={<EngagementDetail />} />
          <Route path="/engagement/:id/findings" element={<FindingsPage />} />
          <Route path="/engagement/:id/report" element={<ReportPreview />} />
          <Route path="/groups" element={<GroupList />} />
          <Route path="/groups/:id" element={<GroupDetail />} />
          <Route path="/alerts" element={<QueuePage />} />
          <Route path="/remediation" element={<FixesPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  )
}

export default function App() {
  React.useEffect(() => {
    try {
      const t = localStorage.getItem("pentestai_theme") || "dark";
      if (t === "light") document.documentElement.classList.add("light");
      else document.documentElement.classList.remove("light");
    } catch {}
  }, []);
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<GuestOnly><LoginPage /></GuestOnly>} />
          <Route path="/register" element={<GuestOnly><Register /></GuestOnly>} />
          <Route path="/*" element={<RequireAuth><Shell /></RequireAuth>} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}

function RequireAuth({ children }) {
  const { user } = useAuth()
  if (!user) return <Navigate to="/login" replace />
  return children
}

function GuestOnly({ children }) {
  const { user } = useAuth()
  if (user) return <Navigate to="/" replace />
  return children
}

function FindingsPage() {
  return (
    <div className="p-8">
      <h2 className="text-2xl font-bold mb-6">Findings</h2>
      <FindingsTable />
    </div>
  )
}

function QueuePage() {
  return (
    <div className="p-8">
      <h2 className="text-2xl font-bold mb-6">Approval Queue</h2>
      <ApprovalQueue />
    </div>
  )
}

function ReportsPage() {
  return (
    <div className="p-8">
      <h2 className="text-2xl font-bold mb-6">Reports</h2>
      <ReportPreview />
    </div>
  )
}