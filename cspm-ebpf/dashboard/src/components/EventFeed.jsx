import { useRef, useEffect } from 'react'

export default function EventFeed({ events, newEventIds, onSelectEvent }) {
  const feedRef = useRef(null)

  return (
    <div className="event-feed" ref={feedRef}>
      {events.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-dim)' }}>
          <div style={{ fontSize: '32px', marginBottom: '12px' }}>📡</div>
          <div>Waiting for security events...</div>
        </div>
      ) : (
        events.map((event) => (
          <div
            key={event.event_id}
            className={`event-row ${newEventIds.has(event.event_id) ? 'new' : ''}`}
            onClick={() => onSelectEvent(event)}
          >
            <span className="event-time">
              {formatTime(event.timestamp)}
            </span>
            <span className={`severity-badge ${event.severity || 'medium'}`}>
              {event.severity || 'med'}
            </span>
            <span className="event-description" title={event.description}>
              {event.description}
            </span>
            <span className="event-binary" title={event.telemetry?.binary}>
              {event.telemetry?.binary}
            </span>
            <span className="event-pod" title={event.telemetry?.pod}>
              {event.telemetry?.pod || '—'}
            </span>
            <span className={`triage-badge ${(event.triage?.grade || '').toLowerCase()}`}>
              {event.triage?.grade || '—'} {event.triage?.confidence ? `${Math.round(event.triage.confidence * 100)}%` : ''}
            </span>
          </div>
        ))
      )}
    </div>
  )
}

function formatTime(ts) {
  if (!ts) return '—'
  try {
    const d = new Date(ts)
    return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch {
    return '—'
  }
}
