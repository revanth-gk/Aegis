export default function TriagePanel({ stats }) {
  if (!stats) return <div style={{ color: 'var(--text-dim)', padding: '20px', textAlign: 'center' }}>Loading triage data...</div>

  const tp = stats.breakdown?.TruePositive || 0
  const bp = stats.breakdown?.BenignPositive || 0
  const fp = stats.breakdown?.FalsePositive || 0
  const total = tp + bp + fp || 1

  // SVG donut chart
  const radius = 45
  const circumference = 2 * Math.PI * radius
  const tpPct = tp / total
  const bpPct = bp / total
  const fpPct = fp / total

  const tpDash = circumference * tpPct
  const bpDash = circumference * bpPct
  const fpDash = circumference * fpPct

  const tpOffset = 0
  const bpOffset = -(tpDash)
  const fpOffset = -(tpDash + bpDash)

  return (
    <div className="triage-chart">
      <div className="donut-container">
        <svg className="donut-svg" viewBox="0 0 120 120">
          {/* Background circle */}
          <circle cx="60" cy="60" r={radius} fill="none" stroke="rgba(100,116,139,0.1)" strokeWidth="10" />
          {/* FP slice */}
          <circle cx="60" cy="60" r={radius} fill="none" stroke="#22c55e" strokeWidth="10"
            strokeDasharray={`${fpDash} ${circumference - fpDash}`}
            strokeDashoffset={fpOffset}
            style={{ transition: 'all 0.5s ease' }}
          />
          {/* BP slice */}
          <circle cx="60" cy="60" r={radius} fill="none" stroke="#f59e0b" strokeWidth="10"
            strokeDasharray={`${bpDash} ${circumference - bpDash}`}
            strokeDashoffset={bpOffset}
            style={{ transition: 'all 0.5s ease' }}
          />
          {/* TP slice */}
          <circle cx="60" cy="60" r={radius} fill="none" stroke="#ef4444" strokeWidth="10"
            strokeDasharray={`${tpDash} ${circumference - tpDash}`}
            strokeDashoffset={tpOffset}
            style={{ transition: 'all 0.5s ease' }}
          />
        </svg>
        <div className="donut-center">
          <div className="donut-center-value">{total === 1 && tp + bp + fp === 0 ? 0 : tp + bp + fp}</div>
          <div className="donut-center-label">Triaged</div>
        </div>
      </div>
      <div className="triage-legend">
        <div className="legend-item">
          <div className="legend-color" style={{ background: '#ef4444' }}></div>
          <span className="legend-label">True Positive</span>
          <span className="legend-value">{tp}</span>
          <span className="legend-pct">{stats.percentages?.TruePositive || 0}%</span>
        </div>
        <div className="legend-item">
          <div className="legend-color" style={{ background: '#f59e0b' }}></div>
          <span className="legend-label">Benign Positive</span>
          <span className="legend-value">{bp}</span>
          <span className="legend-pct">{stats.percentages?.BenignPositive || 0}%</span>
        </div>
        <div className="legend-item">
          <div className="legend-color" style={{ background: '#22c55e' }}></div>
          <span className="legend-label">False Positive</span>
          <span className="legend-value">{fp}</span>
          <span className="legend-pct">{stats.percentages?.FalsePositive || 0}%</span>
        </div>
        {stats.avg_confidence > 0 && (
          <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace" }}>
            Avg confidence: {Math.round(stats.avg_confidence * 100)}%
          </div>
        )}
      </div>
    </div>
  )
}
