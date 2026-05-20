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
      background: '#2c3e50',
      height: '90px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 24px',
      borderBottom: '2px solid #00ffff',
      position: 'sticky',
      top: 0,
      zIndex: 100
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
  <img
    src="/j.png"
    alt="JichoSec Logo"
    style={{ width: '70px', height: '70px', objectFit: 'contain' }}
  />

  <div>
    <div style={{ fontSize: '15px', fontWeight: 500, color: '#F7F6F2', letterSpacing: '0.12em' }}>
      JichoSec
    </div>

    <div style={{ fontSize: '9px', color: '#00ffff', letterSpacing: '0.25em' }}>
      ATTACK SURFACE MANAGEMENT
    </div>
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
              color: activePage === item.id ? '#00ffff' : '#8899aa',
              cursor: 'pointer',
              letterSpacing: '0.08em',
              borderBottom: activePage === item.id ? '2px solid #00ffff' : '2px solid transparent',
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
              border: '1px solid #00ffff',
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
            background: '#00ffff',
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