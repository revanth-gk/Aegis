export default function EventDetail({ event, onClose }) {
  if (!event) return null

  const tel = event.telemetry || {}

  return (
    <div className="event-detail-overlay" onClick={onClose}>
      <div className="event-detail-modal" onClick={e => e.stopPropagation()}>
        <div className="event-detail-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className={`severity-badge ${event.severity || 'medium'}`}>
                {event.severity}
              </span>
              <span style={{ fontSize: '16px', fontWeight: 700 }}>
                {event.event_type?.replace('process_', '').toUpperCase()}
              </span>
              <span className={`triage-badge ${(event.triage?.grade || '').toLowerCase()}`}>
                {event.triage?.grade} {event.triage?.confidence ? `${Math.round(event.triage.confidence * 100)}%` : ''}
              </span>
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
              {event.description}
            </div>
          </div>
          <button className="event-detail-close" onClick={onClose}>✕</button>
        </div>
        <div className="event-detail-body">
          <div className="detail-section">
            <div className="detail-section-title">Event Metadata</div>
            <div className="detail-grid">
              <span className="detail-key">Event ID</span>
              <span className="detail-value">{event.event_id}</span>
              <span className="detail-key">Timestamp</span>
              <span className="detail-value">{event.timestamp}</span>
              <span className="detail-key">Source</span>
              <span className="detail-value">{event.source}</span>
              <span className="detail-key">Node</span>
              <span className="detail-value">{event.node_name}</span>
              <span className="detail-key">Event Type</span>
              <span className="detail-value">{event.event_type}</span>
            </div>
          </div>

          <div className="detail-section">
            <div className="detail-section-title">Process Telemetry</div>
            <div className="detail-grid">
              <span className="detail-key">Binary</span>
              <span className="detail-value" style={{ color: 'var(--cyan)' }}>{tel.binary}</span>
              <span className="detail-key">Arguments</span>
              <span className="detail-value">{(tel.args || []).join(' ') || '—'}</span>
              <span className="detail-key">PID</span>
              <span className="detail-value">{tel.pid}</span>
              <span className="detail-key">UID / User</span>
              <span className="detail-value">{tel.uid} ({tel.user})</span>
              <span className="detail-key">CWD</span>
              <span className="detail-value">{tel.cwd || '—'}</span>
              <span className="detail-key">Namespace</span>
              <span className="detail-value">{tel.namespace || '—'}</span>
              <span className="detail-key">Pod</span>
              <span className="detail-value" style={{ color: 'var(--purple)' }}>{tel.pod || '—'}</span>
              <span className="detail-key">Container ID</span>
              <span className="detail-value">{tel.container_id || '—'}</span>
              <span className="detail-key">Parent Binary</span>
              <span className="detail-value">{tel.parent_binary || '—'}</span>
              <span className="detail-key">Parent PID</span>
              <span className="detail-value">{tel.parent_pid || '—'}</span>
            </div>
          </div>

          {tel.kprobe && (
            <div className="detail-section">
              <div className="detail-section-title">KProbe Data</div>
              <div className="detail-grid">
                <span className="detail-key">Function</span>
                <span className="detail-value" style={{ color: 'var(--amber)' }}>{tel.kprobe.function}</span>
                <span className="detail-key">Policy</span>
                <span className="detail-value">{tel.kprobe.policy}</span>
                <span className="detail-key">Action</span>
                <span className="detail-value">{tel.kprobe.action}</span>
              </div>
            </div>
          )}

          {event.triage && (
            <div className="detail-section">
              <div className="detail-section-title">ML Triage Result</div>
              <div className="detail-grid">
                <span className="detail-key">Grade</span>
                <span className="detail-value">
                  <span className={`triage-badge ${(event.triage.grade || '').toLowerCase()}`}>
                    {event.triage.grade}
                  </span>
                </span>
                <span className="detail-key">Confidence</span>
                <span className="detail-value">{Math.round((event.triage.confidence || 0) * 100)}%</span>
                <span className="detail-key">Status</span>
                <span className="detail-value">{event.triage.status}</span>
              </div>
            </div>
          )}

          {event.explanation && (
            <div className="detail-section">
              <div className="detail-section-title">Threat Intelligence</div>
              <div className="detail-grid">
                <span className="detail-key">MITRE ATT&CK</span>
                <span className="detail-value" style={{ color: 'var(--red)' }}>{event.explanation.mitre_id}</span>
                <span className="detail-key">Guidance</span>
                <span className="detail-value">{event.explanation.guidance}</span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
