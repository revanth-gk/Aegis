export default function MetricsRow({ metrics }) {
  if (!metrics) {
    return (
      <div className="metrics-row">
        {[...Array(5)].map((_, i) => (
          <div className="metric-card cyan" key={i}>
            <div className="metric-icon">⏳</div>
            <div className="metric-value" style={{ opacity: 0.3 }}>—</div>
            <div className="metric-label">Loading...</div>
          </div>
        ))}
      </div>
    )
  }

  const cards = [
    {
      icon: '📡',
      value: metrics.events_total,
      label: 'Total Events',
      sub: `${metrics.events_per_second || 0} evt/s`,
      color: 'cyan',
    },
    {
      icon: '🔴',
      value: metrics.active_alerts || 0,
      label: 'Active Alerts',
      sub: 'Critical + High',
      color: 'red',
    },
    {
      icon: '⚡',
      value: metrics.severity_breakdown?.critical || 0,
      label: 'Critical Events',
      sub: `${metrics.severity_breakdown?.high || 0} high severity`,
      color: 'amber',
    },
    {
      icon: '🎯',
      value: metrics.triage_breakdown?.TruePositive || 0,
      label: 'True Positives',
      sub: `${metrics.triage_breakdown?.FalsePositive || 0} false positives`,
      color: 'green',
    },
    {
      icon: '🔄',
      value: Object.keys(metrics.events_by_type || {}).length,
      label: 'Event Types',
      sub: `${Math.round(metrics.uptime_seconds / 60)}m uptime`,
      color: 'purple',
    },
  ]

  return (
    <div className="metrics-row">
      {cards.map((card, idx) => (
        <div className={`metric-card ${card.color}`} key={idx}>
          <div className="metric-icon">{card.icon}</div>
          <div className="metric-value animate-count">{formatNumber(card.value)}</div>
          <div className="metric-label">{card.label}</div>
          <div className="metric-sub">{card.sub}</div>
        </div>
      ))}
    </div>
  )
}

function formatNumber(num) {
  if (num >= 1000) return (num / 1000).toFixed(1) + 'k'
  return String(num)
}
