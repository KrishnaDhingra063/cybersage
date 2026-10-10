import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { engagements } from '../api/client'
import { useAuth } from '../auth'
import { Plus, Shield, Clock, CheckCircle, AlertTriangle, Globe } from 'lucide-react'
import EngagementWizard from '../components/EngagementWizard'

const statusColors = {
  draft: 'bg-gray-700 text-gray-300',
  authorized: 'bg-yellow-900/50 text-yellow-300 border border-yellow-700',
  active: 'bg-green-900/50 text-green-300 border border-green-700',
  completed: 'bg-blue-900/50 text-blue-300 border border-blue-700',
  archived: 'bg-gray-800 text-gray-500',
}

export default function EngagementList() {
  const { isLead } = useAuth()
  const [list, setList] = useState([])
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({
    name: '',
    client_name: '',
    test_type: 'external',
    target_scope: '',
  })
  const [creating, setCreating] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    engagements.list().then((r) => setList(r.data || []))
  }, [])

  const create = async () => {
    if (!form.name || !form.target_scope) return
    setCreating(true)
    try {
      const r = await engagements.create(form)
      setList([r.data, ...list])
      setShowCreate(false)
      setForm({ name: '', client_name: '', test_type: 'external', target_scope: '' })
    } catch (err) {
      console.error('Failed to create engagement:', err)
    } finally {
      setCreating(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white tracking-wide">Engagements</h2>
          <p className="text-gray-400 mt-1 text-sm">
            Manage target authorizations, rules of engagement, and active attack operations
          </p>
        </div>
        {isLead && (
          <button
            onClick={() => setShowCreate(true)}
            className="btn-primary flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white px-4 py-2 rounded-lg font-semibold text-xs shadow transition-colors"
          >
            <Plus size={16} /> New Engagement
          </button>
        )}
      </div>

      {/* Wizard replaces old drawer */}
      {showCreate && isLead && (
        <EngagementWizard
          onClose={() => setShowCreate(false)}
          onCreated={(eng) => {
            setList([eng, ...list]);
            setShowCreate(false);
          }}
        />
      )}

      {/* Engagement Cards List */}
      <div className="space-y-3">
        {list.map((eng) => (
          <div
            key={eng.id}
            onClick={() => navigate(`/engagement/${eng.id}`)}
            className="card bg-pentest-900 border border-pentest-700 hover:border-cyan-500/50 cursor-pointer transition-all rounded-xl p-4 shadow"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 bg-pentest-800 border border-pentest-700 rounded-lg flex items-center justify-center flex-shrink-0">
                  <Shield size={20} className="text-cyan-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-white text-base">{eng.name}</h3>
                  <div className="flex items-center gap-3 text-xs text-gray-400 mt-0.5">
                    <span>{eng.client_name || 'Internal Scope'}</span>
                    {eng.target_scope && (
                      <span className="font-mono text-[11px] text-cyan-300 flex items-center gap-1">
                        <Globe size={12} /> {eng.target_scope}
                      </span>
                    )}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-4">
                <span className="text-xs uppercase font-mono text-gray-400 bg-pentest-950 px-2.5 py-1 rounded border border-pentest-800">
                  {eng.test_type}
                </span>
                <span
                  className={`px-3 py-1 rounded-full text-xs font-mono font-semibold uppercase tracking-wider ${
                    statusColors[eng.status] || 'bg-gray-800 text-gray-400'
                  }`}
                >
                  {eng.status}
                </span>
              </div>
            </div>
          </div>
        ))}

        {list.length === 0 && (
          <div className="text-center py-16 text-gray-500 bg-pentest-900/40 border border-pentest-800 rounded-xl">
            <Shield size={48} className="mx-auto mb-3 opacity-30 text-gray-400" />
            <p className="text-sm font-medium">No active engagements found</p>
            <p className="text-xs text-gray-600 mt-1">
              {isLead ? 'Click "New Engagement" to define target scope.' : 'Awaiting Lead scope authorization.'}
            </p>
          </div>
        )}
      </div>
    </div>
  )
}