import { useState } from 'react'
import axios from 'axios'

const API = 'http://localhost:8080'

export default function Login({ onLogin }) {
  const [tab, setTab] = useState('login')
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async () => {
    if (!email.trim() || !password.trim()) return
    if (tab === 'register' && !name.trim()) return
    setLoading(true)
    setError('')
    try {
      const endpoint = tab === 'login' ? '/auth/login' : '/auth/register'
      const payload  = tab === 'login' ? { email, password } : { email, name, password }
      const res = await axios.post(`${API}${endpoint}`, payload)
      localStorage.setItem('jichosec_token', res.data.access_token)
      localStorage.setItem('jichosec_user', JSON.stringify({ name: res.data.name, email: res.data.email }))
      onLogin(res.data)
    } catch (e) {
      setError(e.response?.data?.detail || 'Something went wrong. Please try again.')
    }
    setLoading(false)
  }

  const inputStyle = {
    width: '100%',
    padding: '10px 14px',
    border: '1px solid #E2EAF0',
    borderRadius: '8px',
    fontSize: '13px',
    outline: 'none',
    color: '#1B2B3A',
    background: '#F8FAFB',
    marginBottom: '12px',
    transition: 'border 0.15s'
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: '#F0F4F8',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    }}>
      <div style={{ width: '100%', maxWidth: '420px', padding: '0 16px' }}>

        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <div style={{
            width: '56px',
            height: '56px',
            background: '#1B2B3A',
            borderRadius: '16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 16px'
          }}>
            <img
                src="/j.png"
                alt="JichoSec Logo"
                style={{ width: '70px', height: '70px', objectFit: 'contain' }}
            />
          </div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: '#1B2B3A', letterSpacing: '-0.01em' }}>JichoSec</div>
          <div style={{ fontSize: '11px', color: '#000', letterSpacing: '0.2em', marginTop: '4px' }}>ATTACK SURFACE MANAGEMENT</div>
          <div style={{ fontSize: '13px', color: '#7A8FA6', marginTop: '8px' }}>
            {tab === 'login' ? 'Sign in to your account' : 'Create a new account'}
          </div>
        </div>

        <div style={{ background: '#fff', borderRadius: '16px', border: '1px solid #E2EAF0', overflow: 'hidden', boxShadow: '0 4px 24px rgba(0,0,0,0.06)' }}>
          <div style={{ display: 'flex', borderBottom: '1px solid #E2EAF0' }}>
            {['login', 'register'].map(t => (
              <div
                key={t}
                onClick={() => { setTab(t); setError('') }}
                style={{
                  flex: 1,
                  padding: '14px',
                  textAlign: 'center',
                  fontSize: '13px',
                  fontWeight: tab === t ? 600 : 400,
                  color: tab === t ? '#1B2B3A' : '#7A8FA6',
                  cursor: 'pointer',
                  borderBottom: tab === t ? '2px solid #2c3e50' : '2px solid transparent',
                  background: tab === t ? '#FAFBFC' : '#fff',
                  transition: 'all 0.15s'
                }}
              >
                {t === 'login' ? 'Sign In' : 'Create Account'}
              </div>
            ))}
          </div>

          <div style={{ padding: '24px' }}>
            {tab === 'register' && (
              <input
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="Full name"
                style={inputStyle}
              />
            )}
            <input
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="Email address"
              type="email"
              style={inputStyle}
            />
            <input
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="Password"
              type="password"
              onKeyDown={e => e.key === 'Enter' && handleSubmit()}
              style={{ ...inputStyle, marginBottom: '0' }}
            />

            {error && (
              <div style={{ fontSize: '12px', color: '#E05555', marginTop: '10px', padding: '8px 12px', background: '#FFF0F0', borderRadius: '6px', borderLeft: '3px solid #FF6B6B' }}>
                {error}
              </div>
            )}

            <button
              onClick={handleSubmit}
              disabled={loading}
              style={{
                width: '100%',
                padding: '11px',
                background: loading ? '#2c3e50' : '#2c3e50',
                color: '#00ffff',
                border: 'none',
                borderRadius: '8px',
                fontSize: '13px',
                fontWeight: 600,
                cursor: loading ? 'not-allowed' : 'pointer',
                marginTop: '16px',
                letterSpacing: '0.02em',
                transition: 'background 0.15s'
              }}
            >
              {loading ? 'Please wait...' : tab === 'login' ? 'Sign In' : 'Create Account'}
            </button>
          </div>
        </div>

        <div style={{ textAlign: 'center', marginTop: '20px', fontSize: '11px', color: '#7A8FA6' }}>
          By using JichoSec you agree to only scan systems you own or have permission to test.
        </div>
      </div>
    </div>
  )
}