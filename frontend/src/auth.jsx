import React, { createContext, useContext, useState, useCallback, useEffect } from 'react'
import { auth } from './api/client'

const AuthContext = createContext(null)

function buildUserFromPayload(payload) {
  if (!payload) return null
  return {
    username: payload.username,
    role: payload.role,
    user_id: payload.user_id || payload.id,
    email: payload.email || null,
    full_name: payload.full_name || null,
    phone_number: payload.phone_number || null,
    bio: payload.bio || null,
    is_founder: payload.is_founder || false,
    // displayName fallback logic
    displayName: payload.full_name || payload.username || 'Operator',
  }
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('user')) || null
    } catch {
      return null
    }
  })
  const [token, setToken] = useState(() => localStorage.getItem('token') || null)

  const persistUser = useCallback((payload) => {
    const u = buildUserFromPayload(payload)
    if (u) {
      localStorage.setItem('user', JSON.stringify(u))
      setUser(u)
    }
    return u
  }, [])

  const login = useCallback(async (username, password, totp_code) => {
    const r = await auth.login({ username, password, totp_code: totp_code || undefined })
    localStorage.setItem('token', r.data.access_token)
    // Try to hydrate with full profile via /me after login
    try {
      const me = await auth.me()
      const merged = { ...r.data, ...me.data }
      persistUser(merged)
      setToken(r.data.access_token)
      return merged
    } catch {
      const u = buildUserFromPayload(r.data)
      localStorage.setItem('user', JSON.stringify(u))
      setToken(r.data.access_token)
      setUser(u)
      return r.data
    }
  }, [persistUser])

  const setAuthData = useCallback((data) => {
    localStorage.setItem('token', data.access_token)
    // If data already contains profile, persist it; otherwise fetch
    const u = buildUserFromPayload(data)
    localStorage.setItem('user', JSON.stringify(u))
    setToken(data.access_token)
    setUser(u)
    // Try to enrich from /me asynchronously
    auth.me().then((r) => {
      const merged = { ...data, ...r.data }
      persistUser(merged)
    }).catch(() => {})
  }, [persistUser])

  const refreshProfile = useCallback(async () => {
    try {
      const r = await auth.me()
      const current = JSON.parse(localStorage.getItem('user') || '{}')
      const merged = { ...current, ...r.data, displayName: r.data.full_name || r.data.username }
      localStorage.setItem('user', JSON.stringify(merged))
      setUser(merged)
      return merged
    } catch {
      return null
    }
  }, [])

  const updateProfile = useCallback(async (patch) => {
    const r = await auth.updateMe(patch)
    const merged = { ...(JSON.parse(localStorage.getItem('user') || '{}')), ...r.data, displayName: r.data.full_name || r.data.username }
    localStorage.setItem('user', JSON.stringify(merged))
    setUser(merged)
    return r.data
  }, [])

  const logout = useCallback(() => {
    // Best-effort server revoke (session jti + clear HttpOnly cookie); local clear always runs
    try {
      auth.logout().catch(() => {})
    } catch {}
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    setToken(null)
    setUser(null)
  }, [])

  // On mount, if token exists but user is stale, refresh profile once
  useEffect(() => {
    if (token && user) {
      // silent refresh to get full_name/bio without blocking
      auth.me().then((r) => {
        const merged = { ...user, ...r.data, displayName: r.data.full_name || r.data.username }
        localStorage.setItem('user', JSON.stringify(merged))
        setUser(merged)
      }).catch(() => {})
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <AuthContext.Provider value={{ user, token, login, logout, setAuthData, refreshProfile, updateProfile, isLead: user?.role === 'lead' }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}