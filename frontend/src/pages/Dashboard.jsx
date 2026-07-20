import { useEffect, useState } from 'react'
import axios from 'axios'
import { BarChart, Bar, XAxis, YAxis, Tooltip, PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'

const API = 'http://localhost:8080'

const card = {
  background: '#fff',
  borderRadius: '12px',
  border: '1px solid #E2EAF0',
  padding: '16px',
}

export default function Dashboard({ scans, setScans }) {
  const [loading, setLoading] = useState(true)
  const [fullScans, setFullScans] = useState([])

  useEffect(() => {
    axios.get(`${API}/scans/`, { headers: { Authorization: `Bearer ${localStorage.getItem('jichosec_token')}` } }).then(async r => {
      setScans(r.data)
      const details = await Promise.all(
        r.data.map(s => axios.get(`${API}/scans/${s.scan_id}`).then(x => x.data))
      )
      setFullScans(details)
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  const allAssets   = fullScans.flatMap(s => s.assets || [])
  const allFindings = allAssets.flatMap(a => a.findings || [])
  const allIntel    = allAssets.flatMap(a => a.threat_intel || [])

  const count = r => allFindings.filter(f => f.risk === r).length
  const critical = count('critical')
  const high     = count('high')
  const medium   = count('medium')
  const low      = count('low')
  const total    = allFindings.length

  const intelHits = allIntel.filter(t => t.is_malicious).length

  const healthScore = total === 0 ? 100 : Math.max(0, Math.round(100 - (critical * 15 + high * 7 + medium * 3 + low * 1)))

  const healthColor  = healthScore >= 70 ? '#4ECDC4' : healthScore >= 40 ? '#FFD93D' : '#FF6B6B'
  const healthLabel  = healthScore >= 70 ? 'Good' : healthScore >= 40 ? 'Needs Attention' : 'At Risk'
  const healthBg     = healthScore >= 70 ? '#E8F8F5' : healthScore >= 40 ? '#FFF8E0' : '#FFF0F0'

  const gaugeOffset  = 188 - (188 * healthScore / 100)

  const latestScan   = scans[0]

  const urgentFindings = allFindings
    .filter(f => f.risk === 'critical' || f.risk === 'high')
    .slice(0, 4)

  const exposedDbs     = allFindings.filter(f => f.title && f.title.toLowerCase().includes('mysql') || (f.title && f.title.toLowerCase().includes('mongo')) || (f.title && f.title.toLowerCase().includes('redis')) || (f.title && f.title.toLowerCase().includes('postgres'))).length
  const weakSSL        = allFindings.filter(f => f.source === 'ssl_scanner').length
  const missingHeaders = allFindings.filter(f => f.source === 'headers_scanner').length
  const flaggedIPs     = allIntel.filter(t => t.is_malicious).length

  const intelSources = ['shodan', 'virustotal', 'abuseipdb']

  const riskColor = r => r === 'critical' ? '#FF6B6B' : r === 'high' ? '#FFD93D' : r === 'medium' ? '#00ffff' : '#4ECDC4'
  const riskBg    = r => r === 'critical' ? '#FFF0F0' : r === 'high' ? '#FFF8E0' : r === 'medium' ? '#E0FFFE' : '#E8F8F5'
  const riskText  = r => r === 'critical' ? '#E05555' : r === 'high' ? '#D4A017' : r === 'medium' ? '#009999' : '#2EAF9F'

  const plainTitle = f => {
    if (!f.title) return f.title
    const t = f.title.toLowerCase()
    if (t.includes('mysql') || t.includes('mongo') || t.includes('redis') || t.includes('postgres') || t.includes('3306') || t.includes('27017') || t.includes('6379') || t.includes('5432')) return 'Your database is publicly accessible'
    if (t.includes('ssh') || t.includes('rdp') || t.includes('3389') || t.includes('port 22')) return 'Remote access port is exposed'
    if (t.includes('smb') || t.includes('445')) return 'File sharing port is dangerously exposed'
    if (t.includes('ssl') && t.includes('expir')) return 'SSL certificate is expiring soon'
    if (t.includes('self-signed')) return 'Website is using an untrusted certificate'
    if (t.includes('strict-transport')) return 'Website can be accessed over insecure connection'
    if (t.includes('content-security')) return 'Website lacks cross-site scripting protection'
    if (t.includes('x-frame')) return 'Website is vulnerable to clickjacking'
    if (t.includes('spf')) return 'Emails from your domain can be faked'
    if (t.includes('dmarc')) return 'Email phishing protection is not configured'
    if (t.includes('http') && t.includes('80')) return 'Website accessible over unencrypted connection'
    return f.title
  }

  const plainDesc = f => {
    if (!f.description) return ''
    const t = f.title ? f.title.toLowerCase() : ''
    if (t.includes('mysql') || t.includes('database') || t.includes('3306')) return 'Attackers can directly access and steal your database'
    if (t.includes('ssh') || t.includes('rdp')) return 'Anyone can attempt to log into your server remotely'
    if (t.includes('ssl') && t.includes('expir')) return 'Visitors will see security warnings on your website'
    if (t.includes('spf') || t.includes('dmarc')) return 'Attackers can send emails pretending to be your organization'
    if (t.includes('header')) return 'Standard browser security protections are not enabled'
    return f.description
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ background: '#fff', padding: '0 24px', height: '60px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #E2EAF0', flexShrink: 0 }}>
        <div>
          <div style={{ fontSize: '18px', fontWeight: 600, color: '#1B2B3A' }}>Overview</div>
          <div style={{ fontSize: '11px', color: '#7A8FA6', marginTop: '2px' }}>
            {latestScan ? `Last scan: ${latestScan.domain}` : 'No scans yet. Start a new scan.'}
          </div>
        </div>
        <div style={{ fontSize: '10px', color: '#7A8FA6', textAlign: 'right' }}>
          <div>{new Date().toDateString().toUpperCase()}</div>
          <div style={{ color: '#037009', marginTop: '2px', fontSize: '10px', letterSpacing: '0.1em' }}>SESSION ACTIVE</div>
        </div>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '14px', marginBottom: '16px' }}>
          {[
            { label: 'Websites Monitored', value: scans.length, color: '#00BFBF', accent: '#00ffff', sub: `${scans.length} total`, subColor: '#00BFBF' },
            { label: 'Online Assets Found', value: allAssets.length, color: '#2EAF9F', accent: '#4ECDC4', sub: 'subdomains found', subColor: '#2EAF9F' },
            { label: 'Security Issues Found', value: total, color: '#E05555', accent: '#FF6B6B', sub: `${critical} need urgent attention`, subColor: '#E05555' },
            { label: 'Flagged Threats', value: intelHits, color: '#D4A017', accent: '#FFD93D', sub: 'IPs flagged malicious', subColor: '#D4A017' },
          ].map((s, i) => (
            <div key={i} style={{ background: '#fff', borderRadius: '12px', border: '1px solid #E2EAF0', padding: '16px', position: 'relative', overflow: 'hidden' }}>
              <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: '3px', borderRadius: '12px 12px 0 0', background: s.accent }}></div>
              <div style={{ fontSize: '11px', color: '#7A8FA6', marginBottom: '8px', fontWeight: 500 }}>{s.label}</div>
              <div style={{ fontSize: '28px', fontWeight: 700, color: s.color, lineHeight: 1 }}>{loading ? '...' : s.value}</div>
              <div style={{ fontSize: '11px', color: s.subColor, marginTop: '6px' }}>{s.sub}</div>
            </div>
          ))}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.2fr', gap: '14px', marginBottom: '16px' }}>
          <div style={card}>
            <div style={{ fontSize: '12px', fontWeight: 600, color: '#1B2B3A', marginBottom: '14px', display: 'flex', justifyContent: 'space-between' }}>
              Security Health Score
              <span style={{ fontSize: '10px', color: '#7A8FA6', fontWeight: 400 }}>Overall</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '8px 0' }}>
              <svg width="160" height="90" viewBox="0 0 160 90">
                <path d="M20 80 A60 60 0 0 1 140 80" fill="none" stroke="#F0F4F8" strokeWidth="14" strokeLinecap="round" />
                <path d="M20 80 A60 60 0 0 1 140 80" fill="none" stroke={healthColor} strokeWidth="14" strokeLinecap="round" strokeDasharray="188" strokeDashoffset={gaugeOffset} />
              </svg>
              <div style={{ fontSize: '42px', fontWeight: 700, color: '#1B2B3A', lineHeight: 1, marginTop: '-20px' }}>{loading ? '...' : healthScore}</div>
              <div style={{ fontSize: '11px', color: '#7A8FA6', marginTop: '4px' }}>out of 100</div>
              <div style={{ fontSize: '12px', fontWeight: 600, color: riskText(healthScore >= 70 ? 'low' : healthScore >= 40 ? 'medium' : 'critical'), marginTop: '8px', background: healthBg, padding: '3px 12px', borderRadius: '20px' }}>{healthLabel}</div>
            </div>
          </div>

          <div style={card}>
            <div style={{ fontSize: '12px', fontWeight: 600, color: '#1B2B3A', marginBottom: '14px' }}>Issues by Severity</div>
            {[
              { label: 'Critical', count: critical, color: '#FF6B6B', pct: total > 0 ? (critical / total) * 100 : 0 },
              { label: 'High',     count: high,     color: '#FFD93D', pct: total > 0 ? (high / total) * 100 : 0 },
              { label: 'Medium',   count: medium,   color: '#00ffff', pct: total > 0 ? (medium / total) * 100 : 0 },
              { label: 'Low',      count: low,      color: '#4ECDC4', pct: total > 0 ? (low / total) * 100 : 0 },
            ].map((s, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
                <div style={{ fontSize: '11px', color: '#1B2B3A', width: '55px', fontWeight: 500 }}>{s.label}</div>
                <div style={{ flex: 1, height: '7px', background: '#F0F4F8', borderRadius: '4px', overflow: 'hidden' }}>
                  <div style={{ height: '100%', borderRadius: '4px', background: s.color, width: `${s.pct}%`, transition: 'width 0.8s' }}></div>
                </div>
                <div style={{ fontSize: '11px', fontWeight: 600, color: '#1B2B3A', width: '20px', textAlign: 'right' }}>{s.count}</div>
              </div>
            ))}
            <div style={{ borderTop: '1px solid #000', marginTop: '12px', paddingTop: '12px' }}>
              <div style={{ fontSize: '12px', fontWeight: 600, color: '#1B2B3A', marginBottom: '8px' }}>What Was Found</div>
              {[
                { label: 'Exposed databases', count: exposedDbs, color: '#FF6B6B' },
                { label: 'Weak SSL certificates', count: weakSSL, color: '#FFD93D' },
                { label: 'Missing security settings', count: missingHeaders, color: '#00ffff' },
                { label: 'Flagged IP addresses', count: flaggedIPs, color: '#4ECDC4' },
              ].map((f, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid #F0F4F8', fontSize: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#1B2B3A', fontWeight: 500 }}>
                    <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: f.color, flexShrink: 0 }}></div>
                    {f.label}
                  </div>
                  <div style={{ fontWeight: 700, color: '#1B2B3A' }}>{f.count}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={card}>
            <div style={{ fontSize: '12px', fontWeight: 600, color: '#1B2B3A', marginBottom: '14px', display: 'flex', justifyContent: 'space-between' }}>
              Top Urgent Issues
              <span style={{ fontSize: '10px', color: '#7A8FA6', fontWeight: 400 }}>Act on these first</span>
            </div>
            {urgentFindings.length === 0 ? (
              <div style={{ fontSize: '12px', color: '#7A8FA6', padding: '20px 0', textAlign: 'center' }}>No urgent issues found</div>
            ) : urgentFindings.map((f, i) => (
              <div key={i} style={{ display: 'flex', gap: '10px', padding: '9px 0', borderBottom: '1px solid #000', alignItems: 'flex-start' }}>
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: riskColor(f.risk), flexShrink: 0, marginTop: '4px' }}></div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '12px', fontWeight: 500, color: '#1B2B3A' }}>{plainTitle(f)}</div>
                  <div style={{ fontSize: '10px', color: '#7A8FA6', marginTop: '2px' }}>{plainDesc(f)}</div>
                  <span style={{ fontSize: '9px', padding: '2px 8px', borderRadius: '20px', fontWeight: 600, marginTop: '4px', display: 'inline-block', background: riskBg(f.risk), color: riskText(f.risk) }}>
                    {f.risk === 'critical' ? 'Fix immediately' : 'Fix soon'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '14px' }}>
          <div style={card}>
            <div style={{ fontSize: '12px', fontWeight: 600, color: '#1B2B3A', marginBottom: '14px', display: 'flex', justifyContent: 'space-between' }}>
              Recent Scans
              
            </div>
            {scans.length === 0 ? (
              <div style={{ fontSize: '12px', color: '#7A8FA6', padding: '20px 0', textAlign: 'center' }}>No scans yet. Start one from the sidebar.</div>
            ) : scans.slice(0, 5).map(s => {
              const scanDetail = fullScans.find(x => x.scan_id === s.scan_id)
              const scanFindings = scanDetail ? (scanDetail.assets || []).flatMap(a => a.findings || []) : []
              const scanCritical = scanFindings.filter(f => f.risk === 'critical').length
              const scanTotal    = scanFindings.length
              const badgeColor   = scanCritical > 0 ? { bg: '#FFF0F0', text: '#E05555' } : scanTotal > 0 ? { bg: '#FFF8E0', text: '#D4A017' } : { bg: '#E8F8F5', text: '#2EAF9F' }
              const badgeLabel   = scanCritical > 0 ? `${scanCritical} critical issues` : scanTotal > 0 ? `${scanTotal} issues found` : 'All clear'
              return (
                <div key={s.scan_id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '9px 0', borderBottom: '1px solid #F0F4F8' }}>
                  <div>
                    <div style={{ fontSize: '12px', fontWeight: 500, color: '#1B2B3A' }}>{s.domain}</div>
                    <div style={{ fontSize: '10px', color: '#7A8FA6', marginTop: '1px' }}>{new Date(s.created_at).toLocaleString()}</div>
                  </div>
                  <span style={{ fontSize: '10px', padding: '3px 10px', borderRadius: '20px', fontWeight: 600, background: badgeColor.bg, color: badgeColor.text }}>{badgeLabel}</span>
                </div>
              )
            })}
          </div>

          <div style={card}>
            <div style={{ fontSize: '12px', fontWeight: 600, color: '#1B2B3A', marginBottom: '14px', display: 'flex', justifyContent: 'space-between' }}>
              Threat Intelligence
              <span style={{ fontSize: '10px', color: '#7A8FA6', fontWeight: 400 }}>External checks</span>
            </div>
            {[
              { label: 'Shodan', source: 'shodan' },
              { label: 'VirusTotal', source: 'virustotal' },
              { label: 'AbuseIPDB', source: 'abuseipdb' },
            ].map(t => {
              const hits = allIntel.filter(x => x.source === t.source && x.is_malicious).length
              return (
                <div key={t.source} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid #F0F4F8', fontSize: '12px' }}>
                  <span style={{ color: '#1B2B3A', fontWeight: 500 }}>{t.label}</span>
                  <span style={{ fontSize: '10px', padding: '3px 10px', borderRadius: '20px', fontWeight: 600, background: hits > 0 ? '#FFF0F0' : '#E8F8F5', color: hits > 0 ? '#E05555' : '#2EAF9F' }}>
                    {hits > 0 ? `${hits} flagged` : 'Clean'}
                  </span>
                </div>
              )
            })}
            <div style={{ borderTop: '1px solid #F0F4F8', marginTop: '8px', paddingTop: '12px' }}>
              <div style={{ fontSize: '12px', fontWeight: 600, color: '#1B2B3A', marginBottom: '8px', display: 'flex', justifyContent: 'space-between' }}>
                GitHub Repos
                <span style={{ fontSize: '10px', color: '#7A8FA6', fontWeight: 400 }}>Secret leaks</span>
              </div>
              {(() => {
                const secretFindings = allFindings.filter(f => f.source === 'secret_scanner')
                return (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px' }}>
                    <span style={{ color: '#1B2B3A', fontWeight: 500 }}>Public repositories</span>
                    <span style={{ fontSize: '10px', padding: '3px 10px', borderRadius: '20px', fontWeight: 600, background: secretFindings.length > 0 ? '#FFF0F0' : '#E8F8F5', color: secretFindings.length > 0 ? '#E05555' : '#2EAF9F' }}>
                      {secretFindings.length > 0 ? `${secretFindings.length} leaks found` : 'No leaks found'}
                    </span>
                  </div>
                )
              })()}
            </div>
          </div>
        </div>

      </div>
    </div>
  )
}