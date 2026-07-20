import { useState } from 'react'
import axios from 'axios'

const API = 'http://localhost:8080'

const NavIcon = ({ d, viewBox = '0 0 24 24', points, circle, rect, polyline, path2, line1, line2 }) => (
  <svg width="16" height="16" viewBox={viewBox} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    {d && <path d={d} />}
    {points && <polygon points={points} />}
    {circle && <circle cx={circle.cx} cy={circle.cy} r={circle.r} />}
    {rect && <rect x={rect.x} y={rect.y} width={rect.w} height={rect.h} rx={rect.rx} />}
    {polyline && <polyline points={polyline} />}
    {path2 && <path d={path2} />}
    {line1 && <line x1={line1.x1} y1={line1.y1} x2={line1.x2} y2={line1.y2} />}
    {line2 && <line x1={line2.x1} y1={line2.y1} x2={line2.x2} y2={line2.y2} />}
  </svg>
)

export default function Sidebar({ activePage, setActivePage, user, onLogout }) {
  const [scanning, setScanning] = useState(false)
  const [domain, setDomain] = useState('')
  const [showInput, setShowInput] = useState(false)

  const startScan = async () => {
    if (!domain.trim()) return
    setScanning(true)
    try {
      await axios.post(`${API}/scans/`, { domain: domain.trim() }, {
        headers: { Authorization: `Bearer ${localStorage.getItem('jichosec_token')}` }
      })
      setDomain('')
      setShowInput(false)
      setActivePage('scans')
    } catch (e) {
      alert('Scan failed: ' + e.message)
    }
    setScanning(false)
  }

  const navItems = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="3" width="7" height="7" rx="1" />
          <rect x="14" y="3" width="7" height="7" rx="1" />
          <rect x="3" y="14" width="7" height="7" rx="1" />
          <rect x="14" y="14" width="7" height="7" rx="1" />
        </svg>
      )
    },
    {
      id: 'scans',
      label: 'Scans',
      icon: (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
      )
    },
    {
      id: 'assets',
      label: 'Assets',
      icon: (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
          <polygon points="12 2 2 7 12 12 22 7 12 2" />
          <polyline points="2 17 12 22 22 17" />
          <polyline points="2 12 12 17 22 12" />
        </svg>
      )
    },
    {
      id: 'findings',
      label: 'Security Issues',
      icon: (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      )
    },
  ]

  return (
    <div style={{
      width: '220px',
      background: '#1B2B3A',
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      flexShrink: 0,
    }}>
      <div style={{
        padding: '20px 16px 16px',
        borderBottom: '1px solid rgba(0,255,255,0.12)',
        display: 'flex',
        alignItems: 'center',
        gap: '10px'
      }}>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <img src="j.png" alt="JichoSec Logo" style={{ width: '80px', height: '80px', objectFit: 'contain' }} />
          <div style={{ fontSize: '15px', fontWeight: 600, color: '#F0F4F8', letterSpacing: '0.05em' }}>JichoSec</div>
          <div style={{ fontSize: '8px', color: '#00ffff', letterSpacing: '0.2em', marginTop: '2px' }}>ASM</div>
        </div>
      </div>

      <div style={{ fontSize: '9px', color: 'rgba(122,143,166,0.6)', letterSpacing: '0.2em', padding: '16px 16px 6px', textTransform: 'uppercase' }}>
        Take Charge
      </div>

      {navItems.map(item => (
        <div
          key={item.id}
          onClick={() => setActivePage(item.id)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            padding: '10px 16px',
            margin: '2px 8px',
            borderRadius: '8px',
            cursor: 'pointer',
            fontSize: '13px',
            color: activePage === item.id ? '#00ffff' : '#7A8FA6',
            fontWeight: activePage === item.id ? 500 : 400,
            background: activePage === item.id ? 'rgba(0,255,255,0.1)' : 'transparent',
            transition: 'all 0.15s'
          }}
        >
          <div style={{ width: '16px', height: '16px', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            {item.icon}
          </div>
          {item.label}
        </div>
      ))}

      <div style={{ margin: '16px 8px 8px', borderTop: '1px solid rgba(0,255,255,0.08)', paddingTop: '16px' }}>
        <div style={{ fontSize: '9px', color: 'rgba(122,143,166,0.6)', letterSpacing: '0.2em', padding: '0 8px 8px', textTransform: 'uppercase' }}>
          Actions
        </div>
        {showInput && (
          <input
            value={domain}
            onChange={e => setDomain(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && startScan()}
            placeholder="e.g. example.com"
            style={{
              background: 'rgba(255,255,255,0.06)',
              border: '1px solid rgba(0,255,255,0.3)',
              color: '#F0F4F8',
              padding: '8px 12px',
              fontSize: '12px',
              outline: 'none',
              width: '100%',
              borderRadius: '8px',
              marginBottom: '8px',
              letterSpacing: '0.03em'
            }}
          />
        )}
        <button
          onClick={() => showInput ? startScan() : setShowInput(true)}
          disabled={scanning}
          style={{
            background: '#00ffff',
            color: '#1B2B3A',
            border: 'none',
            padding: '10px 16px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            borderRadius: '8px',
            width: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '6px',
            letterSpacing: '0.02em'
          }}
        >
          
          {scanning ? 'Scanning...' : 'New Scan'}
        </button>
      </div>

      <div style={{ marginTop: 'auto', padding: '16px', borderTop: '1px solid rgba(0,255,255,0.1)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
          <div style={{
            width: '34px',
            height: '34px',
            background: 'linear-gradient(135deg, rgba(0,255,255,0.15), rgba(0,255,255,0.3))',
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '13px',
            fontWeight: 600,
            color: '#00ffff',
            flexShrink: 0,
            border: '1.5px solid rgba(0,255,255,0.3)'
          }}>{user?.name?.charAt(0).toUpperCase()}</div>
          <div>
            <div style={{ fontSize: '12px', fontWeight: 500, color: '#F0F4F8' }}>{user?.name}</div>
            <div style={{ fontSize: '10px', color: '#7A8FA6', marginTop: '1px' }}>{user?.email}</div>
          </div>
        </div>
        <button
          onClick={onLogout}
          style={{
            width: '100%',
            padding: '8px',
            background: 'rgba(255,107,107,0.1)',
            color: '#FF6B6B',
            border: '1px solid rgba(255,107,107,0.2)',
            borderRadius: '8px',
            fontSize: '11px',
            fontWeight: 500,
            cursor: 'pointer',
            letterSpacing: '0.02em'
          }}
        >Sign Out</button>
      </div>
    </div>
  )
}