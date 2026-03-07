export default function TimelineChart({ buckets }) {
  if (!buckets || buckets.length === 0) {
    return <div style={{ color: 'var(--text-dim)', padding: '40px', textAlign: 'center' }}>Collecting timeline data...</div>
  }

  const maxTotal = Math.max(...buckets.map(b => b.total || 0), 1)

  return (
    <div>
      <div className="timeline-chart">
        {buckets.map((bucket, idx) => {
          const height = Math.max(((bucket.total || 0) / maxTotal) * 100, 4)
          const hasCritical = (bucket.process_kprobe || 0) > 2

          return (
            <div
              key={idx}
              className={`timeline-bar ${hasCritical ? 'has-critical' : ''}`}
              style={{ height: `${height}%` }}
              title={`${formatBucketTime(bucket.timestamp)}\nexec: ${bucket.process_exec || 0}\nkprobe: ${bucket.process_kprobe || 0}\nexit: ${bucket.process_exit || 0}\ntotal: ${bucket.total || 0}`}
            />
          )
        })}
      </div>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        marginTop: '8px',
        fontSize: '10px',
        color: 'var(--text-dim)',
        fontFamily: "'JetBrains Mono', monospace",
      }}>
        <span>{formatBucketTime(buckets[0]?.timestamp)}</span>
        <span style={{ display: 'flex', gap: '12px' }}>
          <span><span style={{ color: 'var(--cyan)' }}>■</span> Normal</span>
          <span><span style={{ color: 'var(--red)' }}>■</span> High Activity</span>
        </span>
        <span>{formatBucketTime(buckets[buckets.length - 1]?.timestamp)}</span>
      </div>
    </div>
  )
}

function formatBucketTime(ts) {
  if (!ts) return '—'
  try {
    const d = new Date(ts)
    return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' })
  } catch {
    return '—'
  }
}
