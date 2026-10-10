import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, ArrowLeft, CheckCircle2, AlertCircle } from 'lucide-react'
import { useAuth } from '../auth'
import { auth as apiAuth } from '../api/client'
import GoogleLoginButton from '../components/GoogleLoginButton'

export default function LoginPage() {
  const { login, setAuthData } = useAuth()
  const navigate = useNavigate()

  // Modes: 'login' | 'register' | 'forgot_request' | 'forgot_verify'
  const [mode, setMode] = useState('login')
  const [form, setForm] = useState({
    username: '',
    password: '',
    email: '',
    role: 'analyst',
    otp: '',
    newPassword: '',
    totp: '',
  })
  const [showTotp, setShowTotp] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [loading, setLoading] = useState(false)

  const handleLoginSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)

    const trimmedUser = form.username.trim()

    try {
      if (mode === 'register') {
        await apiAuth.register({
          username: trimmedUser,
          password: form.password,
          email: form.email.trim(),
          role: 'analyst', // public register is analyst-only
        })
        await login(trimmedUser, form.password)
        navigate('/')
      } else {
        await login(trimmedUser, form.password, form.totp || undefined)
        navigate('/')
      }
    } catch (err) {
      const detail = err.response?.data?.detail
      if (detail === 'Username not found') {
        setError('Username does not exist. Please check your spelling or register.')
      } else if (detail === 'Incorrect password') {
        setError('Incorrect password. Please try again.')
      } else if (detail === '2FA code required' || detail === 'Invalid 2FA code') {
        setShowTotp(true)
        setError('This account has 2FA enabled — enter the 6-digit code from your authenticator app.')
      } else {
        setError(detail || err.message || 'Request failed')
      }
    } finally {
      setLoading(false)
    }
  }

  // Step 1: Send 6-digit OTP to user's registered Gmail
  const handleSendOTP = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)

    try {
      const target = form.username.trim()
      const res = await apiAuth.requestOtp(target)
      setSuccess(res.data?.message || 'Verification code sent to your registered Gmail.')
      setMode('forgot_verify')
    } catch (err) {
      // Show explicit error from FastAPI backend
      const detail = err.response?.data?.detail
      setError(detail || err.message || 'Failed to send verification code. Please check your network or server.')
    } finally {
      setLoading(false)
    }
  }

  // Step 2: Submit OTP and set the new password
  const handleVerifyOTP = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)

    try {
      const res = await apiAuth.verifyOtpReset({
        email_or_username: form.username.trim(),
        otp: form.otp.trim(),
        new_password: form.newPassword,
      })
      setSuccess(res.data?.message || 'Password successfully reset! Please sign in.')
      setMode('login')
      setForm({ username: form.username.trim(), password: '', email: '', role: 'analyst', otp: '', newPassword: '' })
    } catch (err) {
      const detail = err.response?.data?.detail
      setError(detail || err.message || 'Invalid or expired OTP.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-pentest-900 px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex w-16 h-16 bg-pentest-800 rounded-2xl items-center justify-center mb-4 border border-pentest-600">
            <Shield size={32} className="text-neon-green" />
          </div>
          <h1 className="text-2xl font-bold text-white">PentestAI</h1>
          <p className="text-gray-500 text-sm">Self-Hosted AI Penetration Testing Platform</p>
        </div>

        <div className="card space-y-4">
          <h2 className="text-lg font-semibold text-white">
            {mode === 'login' && 'Sign in'}
            {mode === 'register' && 'Create an account'}
            {mode === 'forgot_request' && 'Reset Password via Gmail'}
            {mode === 'forgot_verify' && 'Enter Verification Code'}
          </h2>

          {error && (
            <div className="flex items-center gap-2 p-3 text-xs rounded bg-red-950/60 border border-red-800 text-red-300">
              <AlertCircle size={15} className="shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="flex items-center gap-2 p-3 text-xs rounded bg-emerald-950/60 border border-emerald-800 text-emerald-300">
              <CheckCircle2 size={15} className="shrink-0" />
              <span>{success}</span>
            </div>
          )}

          {/* VIEW 1: SIGN IN / REGISTER */}
          {(mode === 'login' || mode === 'register') && (
            <form onSubmit={handleLoginSubmit} className="space-y-4">
              {mode === 'login' && (
                <>
                  <GoogleLoginButton
                    onSuccess={(data) => {
                      if (setAuthData) setAuthData(data)
                      navigate('/')
                    }}
                    onError={(err) => setError('Google login failed: ' + (err.response?.data?.detail || err.message))}
                  />
                  <div className="flex items-center my-4 text-xs text-gray-500">
                    <div className="flex-1 border-b border-pentest-700" />
                    <span className="px-2">OR</span>
                    <div className="flex-1 border-b border-pentest-700" />
                  </div>
                </>
              )}

              <div>
                <label className="block text-sm text-gray-400 mb-1">Username</label>
                <input
                  className="input-field w-full"
                  value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })}
                  placeholder="yourname"
                  required
                />
              </div>

              {mode === 'register' && (
                <>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Email (optional)</label>
                    <input
                      className="input-field w-full"
                      value={form.email}
                      onChange={(e) => setForm({ ...form, email: e.target.value })}
                      placeholder="you@example.com"
                    />
                  </div>

                  {/* 3rd Item: Account Role Selector */}
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Account Role</label>
                    <select
                      className="input-field w-full bg-pentest-800 text-white cursor-pointer"
                      value={form.role}
                      onChange={(e) => setForm({ ...form, role: e.target.value })}
                    >
                      <option value="analyst">Security Analyst (Standard Access)</option>
                      <option value="lead">Team Lead / Admin (Full Access)</option>
                    </select>
                  </div>
                </>
              )}

              <div>
                <label className="block text-sm text-gray-400 mb-1">Password</label>
                <input
                  type="password"
                  className="input-field w-full"
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  placeholder="••••••••"
                  required
                />

                {(showTotp || form.totp) && mode === 'login' && (
                  <div className="mt-3">
                    <label className="block text-sm text-gray-400 mb-1">2FA code (authenticator app)</label>
                    <input
                      type="text"
                      inputMode="numeric"
                      maxLength={6}
                      className="input-field w-full tracking-widest text-center font-mono"
                      value={form.totp}
                      onChange={(e) => setForm({ ...form, totp: e.target.value.replace(/\D/g, '') })}
                      placeholder="123456"
                    />
                  </div>
                )}

                {/* Placed Below Password Box */}
                {mode === 'login' && (
                  <div className="mt-2 text-left">
                    <button
                      type="button"
                      onClick={() => {
                        setMode('forgot_request')
                        setError('')
                        setSuccess('')
                      }}
                      className="text-xs text-cyan-400 hover:underline inline-block cursor-pointer"
                    >
                      Forgot password?
                    </button>
                  </div>
                )}
              </div>

              <button type="submit" disabled={loading} className="btn-primary w-full mt-2">
                {loading ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Register'}
              </button>

              <div className="w-full text-center text-sm text-gray-500 mt-4">
                {mode === 'login' ? 'No account? ' : 'Have an account? '}
                <button
                  type="button"
                  onClick={() => {
                    setMode(mode === 'login' ? 'register' : 'login')
                    setError('')
                    setSuccess('')
                  }}
                  className="text-cyan-400 hover:underline cursor-pointer"
                >
                  {mode === 'login' ? 'Register' : 'Sign in'}
                </button>
              </div>
            </form>
          )}

          {/* VIEW 2: REQUEST OTP VIA GMAIL */}
          {mode === 'forgot_request' && (
            <form onSubmit={handleSendOTP} className="space-y-4">
              <p className="text-xs text-gray-400 leading-relaxed">
                Enter your account username or registered Gmail address. We will send a 6-digit OTP code to verify your identity.
              </p>

              <div>
                <label className="block text-sm text-gray-400 mb-1">Username or Gmail</label>
                <input
                  type="text"
                  className="input-field w-full"
                  value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })}
                  placeholder="username or xyz@gmail.com"
                  required
                />
              </div>

              <button type="submit" disabled={loading} className="btn-primary w-full">
                {loading ? 'Sending code…' : 'Send Verification Code'}
              </button>

              <button
                type="button"
                onClick={() => {
                  setMode('login')
                  setError('')
                  setSuccess('')
                }}
                className="flex items-center justify-center gap-1 w-full text-center text-xs text-gray-400 hover:text-white pt-2 cursor-pointer"
              >
                <ArrowLeft size={13} /> Back to Sign in
              </button>
            </form>
          )}

          {/* VIEW 3: VERIFY OTP & ENTER NEW PASSWORD */}
          {mode === 'forgot_verify' && (
            <form onSubmit={handleVerifyOTP} className="space-y-4">
              <p className="text-xs text-gray-400">
                Check your Gmail inbox for the 6-digit code sent to your account.
              </p>

              <div>
                <label className="block text-sm text-gray-400 mb-1">6-Digit Code</label>
                <input
                  type="text"
                  maxLength={6}
                  className="input-field w-full tracking-widest text-center text-lg font-mono"
                  value={form.otp}
                  onChange={(e) => setForm({ ...form, otp: e.target.value })}
                  placeholder="123456"
                  required
                />
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-1">New Password</label>
                <input
                  type="password"
                  className="input-field w-full"
                  value={form.newPassword}
                  onChange={(e) => setForm({ ...form, newPassword: e.target.value })}
                  placeholder="••••••••"
                  required
                />
              </div>

              <button type="submit" disabled={loading} className="btn-primary w-full">
                {loading ? 'Verifying…' : 'Reset Password & Sign in'}
              </button>

              <div className="flex justify-between items-center text-xs pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setMode('forgot_request')
                    setError('')
                  }}
                  className="text-gray-400 hover:text-white cursor-pointer"
                >
                  Resend code
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setMode('login')
                    setError('')
                    setSuccess('')
                  }}
                  className="text-cyan-400 hover:underline cursor-pointer"
                >
                  Back to Sign in
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  )
}