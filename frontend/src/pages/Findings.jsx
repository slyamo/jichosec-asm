import { useEffect, useState } from 'react'
import axios from 'axios'

const API = 'http://localhost:8080'

export default function Findings() {
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [riskFilter, setRiskFilter] = useState('all')
  const [sourceFilter, setSourceFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [sortBy, setSortBy] = useState('score')

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const scansRes = await axios.get(`${API}/scans/`, { headers: { Authorization: `Bearer ${localStorage.getItem('jichosec_token')}` } })
        const scans = scansRes.data
        const allFindings = []
        for (const s of scans) {
          if (s.status !== 'completed') continue
          const r = await axios.get(`${API}/scans/${s.scan_id}`, { headers: { Authorization: `Bearer ${localStorage.getItem('jichosec_token')}` } })
          r.data.assets.forEach(a => {
            ;(a.findings || []).forEach(f => allFindings.push({
              ...f,
              subdomain: a.subdomain,
              domain: s.domain,
              scan_id: s.scan_id
            }))
          })
        }
        setFindings(allFindings)
      } catch (e) {
        console.error(e)
      }
      setLoading(false)
    }
    fetchAll()
  }, [])

  const riskColor = r => r === 'critical' ? '#C0392B' : r === 'high' ? '#9A7D0A' : r === 'medium' ? '#1A5276' : '#1A7A4A'
  const riskBg    = r => r === 'critical' ? '#FDEDEC' : r === 'high' ? '#FEF9E7' : r === 'medium' ? '#EAF2FF' : '#EAFAF1'
  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 }

  const sources = ['all', ...new Set(findings.map(f => f.source || 'scanner').filter(Boolean))]
  const count   = r => findings.filter(f => f.risk === r).length

  const filtered = findings
    .filter(f => riskFilter === 'all' || f.risk === riskFilter)
    .filter(f => sourceFilter === 'all' || (f.source || 'scanner') === sourceFilter)
    .filter(f => f.title.toLowerCase().includes(search.toLowerCase()) || f.description.toLowerCase().includes(search.toLowerCase()) || f.subdomain.toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => sortBy === 'score' ? b.risk_score - a.risk_score : riskOrder[a.risk] - riskOrder[b.risk])

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '20px', paddingBottom: '14px', borderBottom: '1px solid #E0DDD5' }}>
        <div>
          <div style={{ fontSize: '22px', fontWeight: 500, color: '#0A1628' }}>Security Findings</div>
          <div style={{ fontSize: '11px', color: '#8899aa', marginTop: '3px' }}>
            {loading ? 'Loading...' : `${filtered.length} findings across all scans`}
          </div>
        </div>
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search findings..."
          style={{ background: '#fff', border: '1px solid #E0DDD5', padding: '6px 12px', fontSize: '11px', outline: 'none', width: '220px' }}
        />
      </div>

      <div style={{ display: 'flex', gap: '16px', marginBottom: '16px', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', gap: '4px' }}>
          {['all', 'critical', 'high', 'medium', 'low'].map(r => (
            <button key={r} onClick={() => setRiskFilter(r)} style={{ padding: '5px 12px', fontSize: '10px', fontWeight: 500, letterSpacing: '0.08em', cursor: 'pointer', background: riskFilter === r ? '#2c3e50' : '#fff', color: riskFilter === r ? '#00FFFF' : '#8899aa', border: '1px solid #E0DDD5', borderLeft: riskFilter === r ? '2px solid #2c3e50' : '1px solid #E0DDD5' }}>
              {r.toUpperCase()} {r !== 'all' && `(${count(r)})`}
            </button>
          ))}
        </div>

        <div style={{ display: 'flex', gap: '4px' }}>
          {sources.map(s => (
            <button key={s} onClick={() => setSourceFilter(s)} style={{ padding: '5px 12px', fontSize: '10px', letterSpacing: '0.08em', cursor: 'pointer', background: sourceFilter === s ? '#2c3e50' : '#fff', color: sourceFilter === s ? '#00FFFF' : '#8899aa', border: '1px solid #E0DDD5' }}>
              {s.toUpperCase().replace('_', ' ')}
            </button>
          ))}
        </div>

        <div style={{ marginLeft: 'auto', display: 'flex', gap: '4px', alignItems: 'center' }}>
          <span style={{ fontSize: '10px', color: '#8899aa', letterSpacing: '0.08em' }}>SORT:</span>
          {['score', 'risk'].map(s => (
            <button key={s} onClick={() => setSortBy(s)} style={{ padding: '5px 10px', fontSize: '10px', cursor: 'pointer', background: sortBy === s ? '#2c3e50' : '#fff', color: sortBy === s ? '#00FFFF' : '#8899aa', border: '1px solid #E0DDD5' }}>
              {s.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '1px', background: '#FFF', border: '1px solid #000', marginBottom: '16px' }}>
        {['critical', 'high', 'medium', 'low'].map(r => (
          <div key={r} style={{ background: '#2c3e50', padding: '12px 16px', position: 'relative' }}>
            <div style={{ fontSize: '9px', color: '#8899aa', letterSpacing: '0.15em', marginBottom: '4px' }}>{r.toUpperCase()}</div>
            <div style={{ fontSize: '22px', fontWeight: 500, color: riskColor(r) }}>{count(r)}</div>
            <div style={{ position: 'absolute', bottom: 0, left: '16px', right: '16px', height: '2px', background: riskColor(r) }}></div>
          </div>
        ))}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {loading && (
          <div style={{ padding: '24px', fontSize: '11px', color: '#8899aa', textAlign: 'center', background: '#fff', border: '1px solid #E0DDD5' }}>Loading findings...</div>
        )}
        {!loading && filtered.length === 0 && (
          <div style={{ padding: '24px', fontSize: '11px', color: '#8899aa', textAlign: 'center', background: '#2c3e50', border: '1px solid #E0DDD5' }}>No findings found.</div>
        )}
        {filtered.map((f, i) => (
          <div key={i} style={{ background: '#FFF', border: '1px solid #000', borderLeft: `3px solid ${riskColor(f.risk)}`, padding: '14px 16px' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '12px' }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 500, color: '#0A1628' }}>{f.title}</span>
                  <span style={{ padding: '1px 6px', fontSize: '9px', background: riskBg(f.risk), color: riskColor(f.risk), fontWeight: 500, letterSpacing: '0.08em' }}>{f.risk.toUpperCase()}</span>
                </div>
                <div style={{ fontSize: '11px', color: '#8899aa', marginBottom: '8px', lineHeight: 1.6 }}>{f.description}</div>
                <div style={{ fontSize: '11px', color: '#0A1628', padding: '6px 10px', background: '#F7F6F2', marginBottom: '8px' }}>
                  Fix: {f.remediation}
                </div>
                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: '9px', background: '#F0EDE8', color: '#8899aa', padding: '1px 6px', letterSpacing: '0.06em' }}>{(f.source || 'scanner').toUpperCase().replace('_', ' ')}</span>
                  <span style={{ fontSize: '9px', background: '#F0EDE8', color: '#8899aa', padding: '1px 6px' }}>{f.subdomain}</span>
                  <span style={{ fontSize: '9px', background: '#F0EDE8', color: '#8899aa', padding: '1px 6px' }}>{f.domain}</span>
                  <span style={{ fontSize: '9px', background: '#F0EDE8', color: '#0A1628', padding: '1px 6px', fontWeight: 500 }}>SCORE: {f.risk_score}</span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}