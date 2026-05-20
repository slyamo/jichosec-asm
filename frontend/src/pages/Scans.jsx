import { useEffect, useState } from 'react'
import axios from 'axios'

const API = 'http://localhost:8080'

export default function Scans({ scans, setScans }) {
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    axios.get(`${API}/scans/`).then(r => setScans(r.data))
  }, [])

  const viewScan = async (id) => {
    setSelected(id)
    setLoading(true)
    const r = await axios.get(`${API}/scans/${id}`)
    setDetail(r.data)
    setLoading(false)
  }

  const riskColor = r => r === 'critical' ? '#C0392B' : r === 'high' ? '#9A7D0A' : r === 'medium' ? '#1A5276' : '#1A7A4A'
  const riskBg = r => r === 'critical' ? '#FDEDEC' : r === 'high' ? '#FEF9E7' : r === 'medium' ? '#EAF2FF' : '#EAFAF1'

  return (
    <div>
      <div style={{ marginBottom: '20px', paddingBottom: '14px', borderBottom: '1px solid #E0DDD5' }}>
        <div style={{ fontSize: '22px', fontWeight: 500, color: '#0A1628' }}>Scan History</div>
        <div style={{ fontSize: '11px', color: '#8899aa', marginTop: '3px', letterSpacing: '0.05em' }}>{scans.length} scans total</div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 2fr' : '1fr', gap: '16px' }}>
        <div style={{ background: '#fff', border: '1px solid #E0DDD5' }}>
          <div style={{ padding: '12px 16px', borderBottom: '1px solid #E0DDD5', fontSize: '9px', color: '#8899aa', letterSpacing: '0.18em', display: 'grid', gridTemplateColumns: '1fr 1fr 80px' }}>
            <span>DOMAIN</span>
            <span>DATE</span>
            <span>STATUS</span>
          </div>
          {scans.length === 0 && (
            <div style={{ padding: '24px', fontSize: '11px', color: '#8899aa', textAlign: 'center' }}>No scans yet</div>
          )}
          {scans.map(s => (
            <div
              key={s.scan_id}
              onClick={() => viewScan(s.scan_id)}
              style={{
                padding: '12px 16px',
                borderBottom: '1px solid #F0EDE8',
                cursor: 'pointer',
                background: selected === s.scan_id ? '#F7F6F2' : '#fff',
                display: 'grid',
                gridTemplateColumns: '1fr 1fr 80px',
                alignItems: 'center',
                borderLeft: selected === s.scan_id ? '2px solid #C9A84C' : '2px solid transparent'
              }}
            >
              <div style={{ fontWeight: 500, fontSize: '12px', color: '#0A1628' }}>{s.domain}</div>
              <div style={{ fontSize: '10px', color: '#8899aa' }}>{new Date(s.created_at).toLocaleDateString()}</div>
              <span style={{
                padding: '2px 6px',
                fontSize: '9px',
                fontWeight: 500,
                background: riskBg(s.status === 'completed' ? 'low' : 'critical'),
                color: riskColor(s.status === 'completed' ? 'low' : 'critical'),
                borderLeft: `2px solid ${riskColor(s.status === 'completed' ? 'low' : 'critical')}`
              }}>{s.status.toUpperCase()}</span>
            </div>
          ))}
        </div>

        {selected && (
          <div style={{ background: '#fff', border: '1px solid #E0DDD5', padding: '16px' }}>
            {loading ? (
              <div style={{ fontSize: '11px', color: '#8899aa' }}>Loading...</div>
            ) : detail && (
              <div>
                <div style={{ marginBottom: '14px', paddingBottom: '10px', borderBottom: '1px solid #F0EDE8', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <div style={{ fontSize: '16px', fontWeight: 500, color: '#0A1628' }}>{detail.domain}</div>
                    <div style={{ fontSize: '10px', color: '#8899aa', marginTop: '2px', letterSpacing: '0.05em' }}>{detail.total_assets} assets discovered</div>
                  </div>
                  <a href={`${API}/reports/${detail.scan_id}/pdf`} target="_blank" rel="noreferrer" style={{ display: 'inline-block', padding: '6px 16px', background: '#0A1628', color: '#C9A84C', fontSize: '10px', fontWeight: 500, letterSpacing: '0.1em', textDecoration: 'none', borderLeft: '2px solid #C9A84C' }}>DOWNLOAD PDF REPORT</a>
                </div>

                {detail.assets && detail.assets.map((a, i) => (
                  <div key={i} style={{ marginBottom: '12px', padding: '12px', background: '#F7F6F2', border: '1px solid #E0DDD5', borderLeft: '2px solid #C9A84C' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                      <div style={{ fontWeight: 500, fontSize: '12px', color: '#0A1628' }}>{a.subdomain}</div>
                      <div style={{ fontFamily: 'monospace', fontSize: '10px', color: '#8899aa' }}>{a.ip_address}</div>
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px', marginBottom: '6px' }}>
                      {(a.open_ports || []).map((p, j) => (
                        <span key={j} style={{ background: '#F0EDE8', color: '#0A1628', fontSize: '9px', padding: '1px 5px', fontFamily: 'monospace', borderLeft: '2px solid #C9A84C' }}>:{p.port} {p.service}</span>
                      ))}
                    </div>
                    {(a.findings || []).map((f, j) => (
                      <div key={j} style={{ display: 'flex', gap: '8px', padding: '6px 0', borderTop: '1px solid #E0DDD5' }}>
                        <div style={{ width: '2px', background: riskColor(f.risk), flexShrink: 0 }}></div>
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: '11px', fontWeight: 500, color: '#0A1628' }}>{f.title}</div>
                          <div style={{ fontSize: '10px', color: '#8899aa', marginTop: '1px' }}>{f.remediation}</div>
                        </div>
                        <span style={{ padding: '1px 6px', fontSize: '9px', background: riskBg(f.risk), color: riskColor(f.risk), borderLeft: `2px solid ${riskColor(f.risk)}`, flexShrink: 0, alignSelf: 'flex-start' }}>{f.risk.toUpperCase()}</span>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}