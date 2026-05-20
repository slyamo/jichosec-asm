import { useEffect, useState } from 'react'
import axios from 'axios'
import { BarChart, Bar, XAxis, YAxis, Tooltip, PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'

const API = 'http://localhost:8080'

const card = {
  background: '#fff',
  border: '1px solid #E0DDD5',
  padding: '16px',
  marginBottom: '0'
}

const label = {
  fontSize: '9px',
  color: '#8899aa',
  letterSpacing: '0.18em',
  marginBottom: '8px'
}

export default function Dashboard({ scans, setScans }) {
  const [loading, setLoading] = useState(true)
  const [fullScans, setFullScans] = useState([])

  useEffect(() => {
    axios.get(`${API}/scans/`).then(async r => {
      setScans(r.data)
      const details = await Promise.all(
        r.data.map(s => axios.get(`${API}/scans/${s.scan_id}`).then(x => x.data))
      )
      setFullScans(details)
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  const allAssets = fullScans.flatMap(s => s.assets || [])
  const allFindings = allAssets.flatMap(a => a.findings || [])
  const allIntel = allAssets.flatMap(a => a.threat_intel || [])

  const countBy = (arr, key, val) => arr.filter(x => x[key] === val).length
  const critical = countBy(allFindings, 'risk', 'critical')
  const high     = countBy(allFindings, 'risk', 'high')
  const medium   = countBy(allFindings, 'risk', 'medium')
  const low      = countBy(allFindings, 'risk', 'low')

  const totalIntelHits = allIntel.filter(t => t.is_malicious).length

  const barData = [
    { name: 'Critical', count: critical, fill: '#C0392B' },
    { name: 'High',     count: high,     fill: '#C9A84C' },
    { name: 'Medium',   count: medium,   fill: '#1A5276' },
    { name: 'Low',      count: low,      fill: '#1A7A4A' },
  ]

  const pieData = barData.filter(d => d.count > 0)
  const latestScan = scans[0]

  const allOpenPorts = allAssets.flatMap(a => (a.open_ports || []).map(p => `${p.service}`))
  const uniqueServices = [...new Set(allOpenPorts)].slice(0, 8)

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: '20px', paddingBottom: '14px', borderBottom: '1px solid #E0DDD5' }}>
        <div>
          <div style={{ fontSize: '22px', fontWeight: 500, color: '#0A1628', letterSpacing: '-0.01em' }}>Intelligence Overview</div>
          <div style={{ fontSize: '11px', color: '#8899aa', marginTop: '3px', letterSpacing: '0.05em' }}>
            {latestScan ? `Last scan: ${latestScan.domain} · status: ${latestScan.status}` : 'No scans yet. Start a new scan above.'}
          </div>
        </div>
        <div style={{ fontSize: '10px', color: '#8899aa', textAlign: 'right', letterSpacing: '0.08em' }}>
          <div>{new Date().toDateString().toUpperCase()}</div>
          <div style={{ color: '#C9A84C', marginTop: '2px' }}>SESSION ACTIVE</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '1px', background: '#E0DDD5', border: '1px solid #E0DDD5', marginBottom: '20px' }}>
        {[
          { label: 'DOMAINS SCANNED',   value: scans.length,       color: '#0A1628', accent: '#0A1628', change: `${scans.length} total` },
          { label: 'ASSETS DISCOVERED', value: allAssets.length,   color: '#1A5276', accent: '#1A5276', change: 'subdomains found' },
          { label: 'ACTIVE FINDINGS',   value: allFindings.length, color: '#C0392B', accent: '#C0392B', change: `${critical} critical` },
          { label: 'THREAT INTEL HITS', value: totalIntelHits,     color: '#9A7D0A', accent: '#C9A84C', change: 'IPs flagged' },
        ].map((s, i) => (
          <div key={i} style={{ background: '#F7F6F2', padding: '16px', position: 'relative' }}>
            <div style={label}>{s.label}</div>
            <div style={{ fontSize: '26px', fontWeight: 500, color: s.color, lineHeight: 1 }}>{loading ? '...' : s.value}</div>
            <div style={{ fontSize: '10px', color: '#8899aa', marginTop: '5px' }}>{s.change}</div>
            <div style={{ position: 'absolute', bottom: 0, left: '16px', right: '16px', height: '2px', background: s.accent }}></div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '16px', marginBottom: '16px' }}>
        <div style={card}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', paddingBottom: '10px', borderBottom: '1px solid #F0EDE8' }}>
            <div style={{ fontSize: '10px', fontWeight: 500, color: '#0A1628', letterSpacing: '0.18em' }}>FINDINGS BY SEVERITY</div>
          </div>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={barData} layout="vertical" margin={{ left: 10, right: 20 }}>
              <XAxis type="number" tick={{ fontSize: 10, fill: '#8899aa' }} axisLine={false} tickLine={false}/>
              <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: '#8899aa', letterSpacing: '0.05em' }} axisLine={false} tickLine={false} width={55}/>
              <Tooltip contentStyle={{ fontSize: '11px', border: '1px solid #E0DDD5', background: '#fff' }}/>
              <Bar dataKey="count" radius={0}>
                {barData.map((entry, i) => <Cell key={i} fill={entry.fill}/>)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div style={{ borderTop: '1px solid #F0EDE8', marginTop: '12px', paddingTop: '12px' }}>
            <div style={{ fontSize: '10px', fontWeight: 500, color: '#0A1628', letterSpacing: '0.18em', marginBottom: '8px' }}>EXPOSED SERVICES</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
              {uniqueServices.length > 0 ? uniqueServices.map(p => (
                <span key={p} style={{ background: '#F0EDE8', color: '#0A1628', fontSize: '9px', padding: '2px 6px', fontFamily: 'monospace', borderLeft: '2px solid #C9A84C' }}>{p}</span>
              )) : [':80 HTTP', ':443 HTTPS', ':22 SSH', ':3306 MYSQL'].map(p => (
                <span key={p} style={{ background: '#F0EDE8', color: '#0A1628', fontSize: '9px', padding: '2px 6px', fontFamily: 'monospace', borderLeft: '2px solid #C9A84C' }}>{p}</span>
              ))}
            </div>
          </div>
        </div>

        <div style={card}>
          <div style={{ fontSize: '10px', fontWeight: 500, color: '#0A1628', letterSpacing: '0.18em', marginBottom: '14px', paddingBottom: '10px', borderBottom: '1px solid #F0EDE8' }}>RISK DISTRIBUTION</div>
          {allFindings.length > 0 ? (
            <ResponsiveContainer width="100%" height={140}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={40} outerRadius={65} dataKey="count">
                  {pieData.map((entry, i) => <Cell key={i} fill={entry.fill}/>)}
                </Pie>
                <Tooltip contentStyle={{ fontSize: '11px', border: '1px solid #E0DDD5' }}/>
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: '140px', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '11px', color: '#8899aa' }}>No findings yet</div>
          )}
          <div style={{ borderTop: '1px solid #F0EDE8', marginTop: '8px', paddingTop: '10px' }}>
            <div style={{ fontSize: '10px', fontWeight: 500, color: '#0A1628', letterSpacing: '0.18em', marginBottom: '8px' }}>THREAT INTELLIGENCE</div>
            {['shodan', 'virustotal', 'abuseipdb'].map(src => {
              const hits = allIntel.filter(t => t.source === src && t.is_malicious)
              return (
                <div key={src} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid #F0EDE8', fontSize: '10px' }}>
                  <span style={{ color: '#8899aa', letterSpacing: '0.1em' }}>{src.toUpperCase()}</span>
                  <span style={{ color: hits.length > 0 ? '#C0392B' : '#1A7A4A', fontWeight: 500 }}>
                    {hits.length > 0 ? `${hits.length} HIT${hits.length > 1 ? 'S' : ''}` : 'CLEAN'}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
        <div style={card}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '14px', paddingBottom: '10px', borderBottom: '1px solid #F0EDE8' }}>
            <div style={{ fontSize: '10px', fontWeight: 500, color: '#0A1628', letterSpacing: '0.18em' }}>RECENT SCANS</div>
          </div>
          {scans.length === 0 ? (
            <div style={{ fontSize: '11px', color: '#8899aa', padding: '20px 0', textAlign: 'center' }}>No scans yet. Start one above.</div>
          ) : scans.slice(0, 5).map(s => (
            <div key={s.scan_id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid #F0EDE8', fontSize: '11px' }}>
              <div>
                <div style={{ fontWeight: 500, color: '#0A1628' }}>{s.domain}</div>
                <div style={{ fontSize: '10px', color: '#8899aa', marginTop: '2px' }}>{new Date(s.created_at).toLocaleString()}</div>
              </div>
              <span style={{
                padding: '2px 8px',
                fontSize: '9px',
                fontWeight: 500,
                letterSpacing: '0.08em',
                background: s.status === 'completed' ? '#EAFAF1' : s.status === 'failed' ? '#FDEDEC' : '#FEF9E7',
                color: s.status === 'completed' ? '#1A7A4A' : s.status === 'failed' ? '#C0392B' : '#9A7D0A',
                borderLeft: `2px solid ${s.status === 'completed' ? '#1A7A4A' : s.status === 'failed' ? '#C0392B' : '#C9A84C'}`
              }}>{s.status.toUpperCase()}</span>
            </div>
          ))}
        </div>

        <div style={card}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '14px', paddingBottom: '10px', borderBottom: '1px solid #F0EDE8' }}>
            <div style={{ fontSize: '10px', fontWeight: 500, color: '#0A1628', letterSpacing: '0.18em' }}>LATEST FINDINGS</div>
          </div>
          {allFindings.length === 0 ? (
            <div style={{ fontSize: '11px', color: '#8899aa', padding: '20px 0', textAlign: 'center' }}>No findings yet.</div>
          ) : allFindings.slice(0, 4).map((f, i) => (
            <div key={i} style={{ display: 'flex', gap: '10px', padding: '9px 0', borderBottom: '1px solid #F0EDE8' }}>
              <div style={{ width: '2px', flexShrink: 0, background: f.risk === 'critical' ? '#C0392B' : f.risk === 'high' ? '#C9A84C' : '#1A5276', borderRadius: '1px' }}></div>
              <div>
                <div style={{ fontSize: '11px', fontWeight: 500, color: '#0A1628' }}>{f.title}</div>
                <div style={{ fontSize: '10px', color: '#8899aa', marginTop: '2px' }}>{f.description}</div>
                <div style={{ display: 'flex', gap: '6px', marginTop: '4px' }}>
                  <span style={{ fontSize: '9px', background: '#F0EDE8', color: '#8899aa', padding: '1px 6px', letterSpacing: '0.06em' }}>{f.source ? f.source.toUpperCase() : 'SCANNER'}</span>
                  <span style={{ fontSize: '9px', background: '#F0EDE8', color: '#0A1628', padding: '1px 6px', borderLeft: '2px solid #C9A84C' }}>{f.risk_score}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}