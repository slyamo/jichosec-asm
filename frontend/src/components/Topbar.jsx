import { useState } from 'react'
import axios from 'axios'

const API = 'http://localhost:8080'

export default function Topbar({ activePage, setActivePage }) {
  const [scanning, setScanning] = useState(false)
  const [domain, setDomain] = useState('')
  const [showInput, setShowInput] = useState(false)

  const navItems = [
    { id: 'dashboard', label: 'OVERVIEW' },
    { id: 'scans',     label: 'SCANS' },
    { id: 'assets',    label: 'ASSETS' },
    { id: 'findings',  label: 'FINDINGS' },
  ]

  const startScan = async () => {
    if (!domain.trim()) return
    setScanning(true)
    try {
      await axios.post(`${API}/scans/`, { domain: domain.trim() })
      setDomain('')
      setShowInput(false)
      setActivePage('scans')
    } catch (e) {
      alert('Scan failed: ' + e.message)
    }
    setScanning(false)
  }

  return (
    <div style={{
      background: '#0A1628',
      height: '52px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 24px',
      borderBottom: '2px solid #C9A84C',
      position: 'sticky',
      top: 0,
      zIndex: 100
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
          <ellipse cx="16" cy="16" rx="14" ry="9" stroke="#C9A84C" strokeWidth="1.2"/>
          <circle cx="16" cy="16" r="5" stroke="#C9A84C" strokeWidth="1.2"/>
          <circle cx="16" cy="16" r="2" fill="#C9A84C"/>
          <line x1="16" y1="7" x2="16" y2="5" stroke="#C9A84C" strokeWidth="1"/>
          <line x1="16" y1="25" x2="16" y2="27" stroke="#C9A84C" strokeWidth="1"/>
        </svg>
        <div>
          <div style={{ fontSize: '15px', fontWeight: 500, color: '#F7F6F2', letterSpacing: '0.12em' }}>JichoSec</div>
          <div style={{ fontSize: '9px', color: '#C9A84C', letterSpacing: '0.25em' }}>ATTACK SURFACE MANAGEMENT</div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '2px' }}>
        {navItems.map(item => (
          <div
            key={item.id}
            onClick={() => setActivePage(item.id)}
            style={{
              padding: '6px 14px',
              fontSize: '11px',
              color: activePage === item.id ? '#C9A84C' : '#8899aa',
              cursor: 'pointer',
              letterSpacing: '0.08em',
              borderBottom: activePage === item.id ? '2px solid #C9A84C' : '2px solid transparent',
              marginBottom: '-2px'
            }}
          >{item.label}</div>
        ))}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        {showInput && (
          <input
            value={domain}
            onChange={e => setDomain(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && startScan()}
            placeholder="e.g. example.com"
            style={{
              background: 'rgba(255,255,255,0.08)',
              border: '1px solid #C9A84C',
              color: '#F7F6F2',
              padding: '5px 12px',
              fontSize: '11px',
              outline: 'none',
              width: '180px',
              letterSpacing: '0.05em'
            }}
          />
        )}
        <button
          onClick={() => showInput ? startScan() : setShowInput(true)}
          disabled={scanning}
          style={{
            background: '#C9A84C',
            color: '#0A1628',
            border: 'none',
            padding: '6px 16px',
            fontSize: '11px',
            fontWeight: 500,
            cursor: 'pointer',
            letterSpacing: '0.1em'
          }}
        >
          {scanning ? 'SCANNING...' : '+ NEW SCAN'}
        </button>
      </div>
    </div>
  )
}