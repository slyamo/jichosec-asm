import { useState, useEffect } from 'react'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import Scans from './pages/Scans'
import Assets from './pages/Assets'
import Findings from './pages/Findings'
import Login from './pages/Login'
import './index.css'

export default function App() {
  const [activePage, setActivePage] = useState('dashboard')
  const [scans, setScans] = useState([])
  const [user, setUser] = useState(null)

  useEffect(() => {
    const token = localStorage.getItem('jichosec_token')
    const stored = localStorage.getItem('jichosec_user')
    if (token && stored) {
      setUser(JSON.parse(stored))
    }
  }, [])

  const handleLogin = (data) => {
    setUser({ name: data.name, email: data.email })
  }

  const handleLogout = () => {
    localStorage.removeItem('jichosec_token')
    localStorage.removeItem('jichosec_user')
    setUser(null)
    setScans([])
    setActivePage('dashboard')
  }

  if (!user) return <Login onLogin={handleLogin} />

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
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: '#F0F4F8' }}>
      <Sidebar activePage={activePage} setActivePage={setActivePage} user={user} onLogout={handleLogout} />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'auto' }}>
        {renderPage()}
      </div>
    </div>
  )
}