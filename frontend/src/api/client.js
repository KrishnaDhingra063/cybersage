import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true, // send HttpOnly auth cookie alongside Bearer header (dual support)
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (r) => r,
  (error) => {
    if (error.response?.status === 401 && localStorage.getItem('token')) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      if (!window.location.pathname.startsWith('/login')) {
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

export const auth = {
  register: (data) => api.post('/auth/register', data),
  login: (data) => api.post('/auth/login', data),
  logout: () => api.post('/auth/logout'),
  resetPassword: (data) => api.post('/auth/reset-password', data),
  requestOtp: (emailOrUsername) =>
    api.post('/auth/request-otp', { email_or_username: emailOrUsername }),
  verifyOtpReset: (data) =>
    api.post('/auth/verify-otp-reset', data),
  me: () => api.get('/auth/me'),
  updateMe: (data) => api.patch('/auth/me', data),
  changePassword: (data) => api.post('/auth/change-password', data),
  setup2fa: () => api.post('/auth/2fa/setup'),
  enable2fa: (code) => api.post('/auth/2fa/enable', { code }),
  disable2fa: (code) => api.post('/auth/2fa/disable', { code }),
  sessions: () => api.get('/auth/sessions'),
  revokeSession: (id) => api.post(`/auth/sessions/${id}/revoke`),
  createToken: (name, expires_days = 90) => api.post('/auth/tokens', { name, expires_days }),
  listTokens: () => api.get('/auth/tokens'),
  revokeToken: (id) => api.delete(`/auth/tokens/${id}`),
}

export const users = {
  me: () => api.get('/users/me'),
  updateMe: (data) => api.patch('/users/me', data),
  audit: (limit = 50) => api.get('/users/audit/list', { params: { limit } }),
}

export const admin = {
  backup: () => api.get('/admin/backup', { responseType: 'blob' }),
}

export const engagements = {
  list: (status) => api.get('/engagements/', { params: status ? { status } : {} }),
  get: (id) => api.get(`/engagements/${id}`),
  create: (data) => api.post('/engagements/', data),
  update: (id, data) => api.patch(`/engagements/${id}`, data),
  createScope: (engId, data) => api.post(`/engagements/${engId}/scope`, data),
  listScopes: (engId) => api.get(`/engagements/${engId}/scope`),
  approveScope: (engId, scopeId) => api.post(`/engagements/${engId}/scope/${scopeId}/approve`),
  setAutonomy: (engId, level) => api.post(`/engagements/${engId}/autonomy`, { level }),
  hosts: (engId) => api.get(`/engagements/${engId}/hosts`),
  services: (engId) => api.get(`/engagements/${engId}/services`),
  inventory: (engId) => api.get(`/engagements/${engId}/inventory`),
}

export const findings = {
  list: (engId, filters = {}) => api.get(`/findings/engagement/${engId}`, { params: filters }),
  get: (id) => api.get(`/findings/${id}`),
  update: (id, data) => api.patch(`/findings/${id}`, data),
  bulkUpdate: (ids, status) => api.post(`/findings/bulk-update`, { ids, status }),
  exportCsv: (engId) => api.get(`/findings/engagement/${engId}/export`, { params: { format: "csv" }, responseType: "blob" }),
  exportSarif: (engId) => api.get(`/findings/engagement/${engId}/export`, { params: { format: "sarif" } }),
  summary: (engId) => api.get(`/findings/engagement/${engId}/summary`),
  duplicates: (engId) => api.get(`/findings/engagement/${engId}/duplicates`),
}

export const reasoning = {
  trail: (engId) => api.get(`/reasoning/engagement/${engId}`),
  graph: (engId) => api.get(`/reasoning/engagement/${engId}/graph`),
  get: (id) => api.get(`/reasoning/${id}`),
  triggerCycle: (engId) => api.post(`/reasoning/engagement/${engId}/cycle`),
  startContinuous: (engId, maxCycles = 20) =>
    api.post(`/reasoning/engagement/${engId}/continuous`, null, { params: { max_cycles: maxCycles } }),
  approve: (logId, approved, notes = '') =>
    api.post(`/reasoning/${logId}/approve`, { approved, notes }),
  queue: (engId) => api.get(`/reasoning/engagement/${engId}/queue`),
  jobs: (engId) => api.get(`/reasoning/engagement/${engId}/jobs`),
  jobOutput: (jobId) => api.get(`/reasoning/jobs/${jobId}/output`),
}

export const fixes = {
  generate: (engagementId, findingId, styleRules) =>
    api.post('/fixes/generate', { engagement_id: engagementId, finding_id: findingId, style_rules: styleRules }),
  list: (engagementId) => api.get(`/fixes/engagement/${engagementId}`),
  get: (id) => api.get(`/fixes/${id}`),
  approve: (id) => api.post(`/fixes/${id}/approve`),
  reject: (id) => api.post(`/fixes/${id}/reject`),
  apply: (id) => api.post(`/fixes/${id}/apply`),
  verify: (id) => api.post(`/fixes/${id}/verify`),
  createPR: (id, data = {}) => api.post(`/fixes/${id}/create_pr`, data),
  saveStyle: (data) => api.post('/fixes/styles', data),
  listStyles: (engagementId) => api.get(`/fixes/engagement/${engagementId}/styles`),
}

export const reports = {
  generate: (engId, type = 'technical') =>
    api.post('/reports/generate', { engagement_id: engId, report_type: type }),
  preview: (engId, type = 'technical') =>
    api.get(`/reports/engagement/${engId}/preview`, { params: { report_type: type } }),
  downloadPdf: (engId, type = 'technical') =>
    api.get(`/reports/engagement/${engId}/pdf`, { params: { report_type: type }, responseType: 'blob' }),
}

export const scans = {
  quick: (target, engagementId, paths = []) =>
    api.post('/scans/quick', { target, engagement_id: engagementId, paths }),
  manual: (engagementId, target, tool, parameters = {}) =>
    api.post('/scans/manual', { engagement_id: engagementId, target, tool, parameters }),
  validate: (engagementId, target) =>
    api.post('/scans/validate', { engagement_id: engagementId, target }),
  // Backward-compat shims for EngagementDetail (originally expected start/stop)
  start: (data) => {
    // data: { engagement_id, scan_type } -> map to manual nmap scan on engagement's scope
    const engId = data?.engagement_id || data?.engagementId
    const target = data?.target || 'localhost'
    return api.post('/scans/manual', { engagement_id: engId, target, tool: 'nmap', parameters: { scan_type: data?.scan_type || 'full' } })
  },
  stop: (engagementId) => Promise.resolve({ data: { status: 'stopped', engagement_id: engagementId } }),
}

export const agent = {
  turn: (engagementId, message, history = '') =>
    api.post('/agent/turn', { engagement_id: engagementId, message, history }),
  history: (engagementId, limit = 100) =>
    api.get(`/agent/history/${engagementId}`, { params: { limit } }),
  clearHistory: (engagementId) =>
    api.delete(`/agent/history/${engagementId}`),
}

export const groups = {
  list: () => api.get('/groups/'),
  get: (id) => api.get(`/groups/${id}`),
  create: (engagementId, name) => api.post('/groups/', { engagement_id: engagementId, name }),
  addMember: (groupId, usernameOrEmail) => api.post(`/groups/${groupId}/members`, { username_or_email: usernameOrEmail }),
  promote: (groupId, userId) => api.post(`/groups/${groupId}/co-lead/${userId}`),
  demote: (groupId, userId) => api.post(`/groups/${groupId}/demote/${userId}`),
  mute: (groupId, userId, minutes = 30) => api.post(`/groups/${groupId}/mute/${userId}`, { minutes }),
  unmute: (groupId, userId) => api.post(`/groups/${groupId}/unmute/${userId}`),
  activity: (groupId, params = {}) => api.get(`/groups/${groupId}/activity`, { params }),
  logActivity: (groupId, data) => api.post(`/groups/${groupId}/activity`, data),
  messages: (groupId, limit = 50) => api.get(`/groups/${groupId}/messages`, { params: { limit } }),
  sendMessage: (groupId, message) => api.post(`/groups/${groupId}/messages`, { message }),
  share: (groupId, data) => api.post(`/groups/${groupId}/share`, data),
  shares: (groupId) => api.get(`/groups/${groupId}/shares`),
  markSeen: (groupId, shareId) => api.post(`/groups/${groupId}/shares/${shareId}/seen`),
}

export default api
