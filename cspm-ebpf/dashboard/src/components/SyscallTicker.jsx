/**
 * SyscallTicker.jsx — Bottom status strip
 *
 * Shows raw JSON eBPF events as a scrolling ticker.
 * Minimal, monospace, low visual weight — like a terminal log strip.
 */

import { useStore } from '../store'
import { useEffect, useState } from 'react'

export default function SyscallTicker() {
  const { events } = useStore()
  const [tickerEvents, setTickerEvents] = useState([])

  useEffect(() => {
    if (events.length > 0) setTickerEvents(events.slice(0, 6))
  }, [events])

  if (tickerEvents.length === 0) return (
    <div className="h-7 min-h-7 bg-[#080b14] border-t border-white/[0.04] flex items-center px-4">
      <span className="text-[9px] text-slate-700 font-mono">Awaiting eBPF telemetry...</span>
    </div>
  )

  return (
    <div className="h-7 min-h-7 bg-[#080b14] border-t border-white/[0.04] flex items-center overflow-hidden px-4 gap-3">
      {/* Label */}
      <span className="text-[9px] font-mono font-semibold text-slate-700 uppercase tracking-wider shrink-0">
        eBPF&nbsp;&nbsp;▶
      </span>

      {/* Scrolling events */}
      <div className="flex-1 overflow-hidden">
        <div className="flex items-center gap-4 animate-ticker">
          {tickerEvents.map(event => {
            const gradeColor = event.triage?.grade === 'TP' ? '#f87171' : event.triage?.grade === 'BP' ? '#60a5fa' : '#64748b'
            return (
              <span key={event.event_id} className="shrink-0 text-[9px] font-mono text-slate-700 whitespace-nowrap">
                <span className="text-slate-600">{'{'}</span>
                <span className="text-slate-600"> type:</span><span className="text-slate-500">"{event.event_type}"</span>
                <span className="text-slate-600">, bin:</span><span className="text-slate-500">"{event.telemetry?.binary?.split('/').pop()}"</span>
                <span className="text-slate-600">, pid:</span><span className="text-slate-500">{event.telemetry?.pid}</span>
                <span className="text-slate-600">, grade:</span>
                <span style={{ color: gradeColor }}>"{event.triage?.grade}"</span>
                <span className="text-slate-600"> {'}'}</span>
              </span>
            )
          })}
          {/* Duplicate for seamless loop */}
          {tickerEvents.map(event => {
            const gradeColor = event.triage?.grade === 'TP' ? '#f87171' : event.triage?.grade === 'BP' ? '#60a5fa' : '#64748b'
            return (
              <span key={`d-${event.event_id}`} className="shrink-0 text-[9px] font-mono text-slate-700 whitespace-nowrap" aria-hidden="true">
                <span className="text-slate-600">{'{'}</span>
                <span className="text-slate-600"> type:</span><span className="text-slate-500">"{event.event_type}"</span>
                <span className="text-slate-600">, bin:</span><span className="text-slate-500">"{event.telemetry?.binary?.split('/').pop()}"</span>
                <span className="text-slate-600">, pid:</span><span className="text-slate-500">{event.telemetry?.pid}</span>
                <span className="text-slate-600">, grade:</span>
                <span style={{ color: gradeColor }}>"{event.triage?.grade}"</span>
                <span className="text-slate-600"> {'}'}</span>
              </span>
            )
          })}
        </div>
      </div>
    </div>
  )
}
