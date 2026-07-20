import { useEffect, useState } from 'react'
import axios from 'axios'

const API = 'http://localhost:8080'

export default function Assets() {
  const [assets, setAssets] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')
  const [riskFilter, setRiskFilter] = useState('all')
  const [selected, setSelected] = useState(null)

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const scansRes = await axios.get(`${API}/scans/`, { headers: { Authorization: `Bearer ${localStorage.getItem('jichosec_token')}` } })
        const scans = scansRes.data
        const allAssets = []
        for (const s of scans) {
          if (s.status !== 'completed') continue
          const r = await axios.get(`${API}/scans/${s.scan_id}`, { headers: { Authorization: `Bearer ${localStorage.getItem('jichosec_token')}` } })
          r.data.assets.forEach(a => allAssets.push({
            ...a,
            domain: s.domain,
            scan_id: s.scan_id
          }))
        }
        setAssets(allAssets)
      } catch (e) {
        console.error(e)
      }
      setLoading(false)
    }
    fetchAll()
  }, [])

  const riskColor = r => r === 'critical' ? '#C0392B' : r === 'high' ? '#9A7D0A' : r === 'medium' ? '#1A5276' : '#1A7A4A'
  const riskBg    = r => r === 'critical' ? '#FDEDEC' : r === 'high' ? '#FEF9E7' : r === 'medium' ? '#EAF2FF' : '#EAFAF1'

  const topRisk = a => {
    const f = a.findings || []
    if (f.find(x => x.risk === 'critical')) return 'critical'
    if (f.find(x => x.risk === 'high'))     return 'high'
    if (f.find(x => x.risk === 'medium'))   return 'medium'
    return 'low'
  }

  const filtered = assets.filter(a => {
    const matchText = a.subdomain.includes(filter) || (a.ip_address || '').includes(filter) || a.domain.includes(filter)
    const matchRisk = riskFilter === 'all' || topRisk(a) === riskFilter
    return matchText && matchRisk
  })

  const count = r => assets.filter(a => topRisk(a) === r).length

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '20px', paddingBottom: '14px', borderBottom: '1px solid #E0DDD5' }}>
        <div>
          <div style={{ fontSize: '22px', fontWeight: 500, color: '#0A1628' }}>Discovered Assets</div>
          <div style={{ fontSize: '11px', color: '#8899aa', marginTop: '3px' }}>
            {loading ? 'Loading...' : `${filtered.length} assets across all scans`}
          </div>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <input
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Search domain, subdomain or IP..."
            style={{ background: '#fff', border: '1px solid #E0DDD5', padding: '6px 12px', fontSize: '11px', outline: 'none', width: '240px' }}
          />
        </div>
      </div>

      <div style={{ display: 'flex', gap: '4px', marginBottom: '16px' }}>
        {['all', 'critical', 'high', 'medium', 'low'].map(r => (
          <button key={r} onClick={() => setRiskFilter(r)} style={{ padding: '5px 12px', fontSize: '10px', fontWeight: 500, letterSpacing: '0.08em', cursor: 'pointer', background: riskFilter === r ? '#0A1628' : '#fff', color: riskFilter === r ? '#00ffff' : '#8899aa', border: '1px solid #E0DDD5' }}>
            {r.toUpperCase()} {r !== 'all' && `(${count(r)})`}
          </button>
        ))}
        <div style={{ marginLeft: 'auto', fontSize: '10px', color: '#8899aa', padding: '5px 0', letterSpacing: '0.08em' }}>
          TOTAL: {assets.length} ASSETS
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 1fr' : '1fr', gap: '16px' }}>
        <div style={{ background: '#fff', border: '1px solid #E0DDD5' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1.2fr 1fr 1fr 80px', padding: '10px 16px', borderBottom: '2px solid #0A1628', fontSize: '9px', color: '#8899aa', letterSpacing: '0.18em' }}>
            <span>SUBDOMAIN</span>
            <span>IP ADDRESS</span>
            <span>OPEN PORTS</span>
            <span>TECHNOLOGIES</span>
            <span>RISK</span>
          </div>
          {loading && (
            <div style={{ padding: '24px', fontSize: '11px', color: '#8899aa', textAlign: 'center' }}>Loading assets...</div>
          )}
          {!loading && filtered.length === 0 && (
            <div style={{ padding: '24px', fontSize: '11px', color: '#8899aa', textAlign: 'center' }}>No assets found. Run a scan first.</div>
          )}
          {filtered.map((a, i) => {
            const risk = topRisk(a)
            return (
              <div
                key={i}
                onClick={() => setSelected(selected === i ? null : i)}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '2fr 1.2fr 1fr 1fr 80px',
                  padding: '10px 16px',
                  borderBottom: '1px solid #000',
                  alignItems: 'center',
                  fontSize: '11px',
                  cursor: 'pointer',
                  background: selected === i ? '#EAF2FF' : '#fff',
                  borderLeft: selected === i ? '2px solid #00ffff' : '2px solid transparent'
                }}
              >
                <div>
                  <div style={{ fontWeight: 500, color: '#0A1628' }}>{a.subdomain}</div>
                  <div style={{ fontSize: '10px', color: '#8899aa', marginTop: '1px' }}>{a.domain}</div>
                </div>
                <div style={{ fontFamily: 'monospace', fontSize: '10px', color: '#8899aa' }}>{a.ip_address || 'N/A'}</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '2px' }}>
                  {(a.open_ports || []).slice(0, 3).map((p, j) => (
                    <span key={j} style={{ background: '#F0EDE8', color: '#0A1628', fontSize: '9px', padding: '1px 5px', fontFamily: 'monospace', borderLeft: '2px solid #EAF2FF' }}>:{p.port}</span>
                  ))}
                  {(a.open_ports || []).length > 3 && (
                    <span style={{ fontSize: '9px', color: '#8899aa' }}>+{(a.open_ports || []).length - 3}</span>
                  )}
                </div>
                <div style={{ fontSize: '10px', color: '#8899aa' }}>{(a.technologies || []).join(', ') || 'Unknown'}</div>
                <span style={{ padding: '2px 6px', fontSize: '9px', fontWeight: 500, background: riskBg(risk), color: riskColor(risk) }}>{risk.toUpperCase()}</span>
              </div>
            )
          })}
        </div>

        {selected !== null && filtered[selected] && (
          <div style={{ background: '#fff', border: '1px solid #E0DDD5', padding: '16px' }}>
            <div style={{ marginBottom: '14px', paddingBottom: '10px', borderBottom: '1px solid #000' }}>
              <div style={{ fontSize: '15px', fontWeight: 500, color: '#0A1628' }}>{filtered[selected].subdomain}</div>
              <div style={{ fontSize: '10px', color: '#8899aa', marginTop: '2px', fontFamily: 'monospace' }}>{filtered[selected].ip_address}</div>
            </div>

            <div style={{ fontSize: '9px', color: '#8899aa', letterSpacing: '0.15em', marginBottom: '8px' }}>OPEN PORTS</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginBottom: '14px' }}>
              {(filtered[selected].open_ports || []).map((p, j) => (
                <span key={j} style={{ background: '#EAF2FF', color: '#0A1628', fontSize: '10px', padding: '3px 8px', fontFamily: 'monospace' }}>:{p.port} {p.service}</span>
              ))}
            </div>

            <div style={{ fontSize: '9px', color: '#8899aa', letterSpacing: '0.15em', marginBottom: '8px' }}>TECHNOLOGIES</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginBottom: '14px' }}>
              {(filtered[selected].technologies || []).map((t, j) => (
                <span key={j} style={{ background: '#EAF2FF', color: '#0A1628', fontSize: '10px', padding: '3px 8px' }}>{t}</span>
              ))}
            </div>

            <div style={{ fontSize: '9px', color: '#8899aa', letterSpacing: '0.15em', marginBottom: '8px' }}>FINDINGS ({(filtered[selected].findings || []).length})</div>
            {(filtered[selected].findings || []).map((f, j) => (
              <div key={j} style={{ display: 'flex', gap: '8px', padding: '8px 0', borderBottom: '1px solid #000' }}>
                <div style={{ width: '2px', background: riskColor(f.risk), flexShrink: 0 }}></div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '11px', fontWeight: 500, color: '#0A1628' }}>{f.title}</div>
                  <div style={{ fontSize: '10px', color: '#8899aa', marginTop: '2px' }}>{f.description}</div>
                  <div style={{ fontSize: '10px', color: '#0A1628', marginTop: '4px', padding: '4px 8px', background: '#EAF2FF' }}>Fix: {f.remediation}</div>
                </div>
                <span style={{ padding: '1px 6px', fontSize: '9px', background: riskBg(f.risk), color: riskColor(f.risk),  flexShrink: 0, alignSelf: 'flex-start' }}>{f.risk.toUpperCase()}</span>
              </div>
            ))}

            <div style={{ fontSize: '9px', color: '#8899aa', letterSpacing: '0.15em', marginTop: '14px', marginBottom: '8px' }}>THREAT INTELLIGENCE</div>
            {(filtered[selected].threat_intel || []).map((t, j) => (
              <div key={j} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid #F0EDE8', fontSize: '10px' }}>
                <span style={{ color: '#8899aa', letterSpacing: '0.08em' }}>{t.source.toUpperCase()}</span>
                <span style={{ color: t.is_malicious ? '#C0392B' : '#1A7A4A', fontWeight: 500 }}>{t.is_malicious ? 'FLAGGED' : 'CLEAN'}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}