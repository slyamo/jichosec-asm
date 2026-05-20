import { useState } from 'react'
import Topbar from './components/Topbar'
import Dashboard from './pages/Dashboard'
import Scans from './pages/Scans'
import Assets from './pages/Assets'
import Findings from './pages/Findings'
import './index.css'

export default function App() {
  const [activePage, setActivePage] = useState('dashboard')
  const [scans, setScans] = useState([])

  const renderPage = () => {
  switch (activePage) {
    case 'dashboard': return <Dashboard scans={scans} setScans={setScans} />
    case 'scans':     return <Scans scans={scans} setScans={setScans} />
    case 'assets':    return <Assets />
    case 'findings':  return <Findings />
    default:          return <Dashboard scans={scans} setScans={setScans} />
  }
}

  return (
    <div style={{ minHeight: '100vh', background: '#F7F6F2' }}>
      <Topbar activePage={activePage} setActivePage={setActivePage} />
      <div style={{ display: 'flex' }}>
        <div style={{
          width: '14px',
          background: '#0A1628',
          minHeight: 'calc(100vh - 52px)',
          flexShrink: 0,
          position: 'relative',
          overflow: 'hidden'
        }}>
          <span style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%) rotate(-90deg)',
            fontSize: '8px',
            color: 'rgba(201,168,76,0.3)',
            letterSpacing: '0.3em',
            whiteSpace: 'nowrap'
          }}>JICHOSEC ASM</span>
        </div>
        <div style={{ flex: 1, padding: '20px' }}>
          {renderPage()}
        </div>
      </div>
    </div>
  )
}