/**
 * Header.jsx — Production Page Header
 *
 * Design: Minimal top bar. Page context + system state. No decorative elements.
 * Typography hierarchy: title 16px, badges 10px, clock 12px mono.
 */

import { useStore } from '../store'
import { Activity } from 'lucide-react'
import { useState, useEffect } from 'react'

const PAGE_TITLES = {
  command:   'Command Center',
  ledger:    'Incident Ledger',
  forensics: 'Forensics Deep-Dive',
}

export default function Header() {
  const { currentPage, health, wsConnected, enforcementMode } = useStore()
  const [clock, setClock] = useState('')

  useEffect(() => {
    const tick = () => {
      const now = new Date()
      const offset = -now.getTimezoneOffset()
      const sign = offset >= 0 ? '+' : '-'
      const h = String(Math.abs(Math.floor(offset / 60))).padStart(2, '0')
      const m = String(Math.abs(offset % 60)).padStart(2, '0')
      setClock(now.toLocaleTimeString('en-US', { hour12: false }) + ` UTC${sign}${h}:${m}`)
    }
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [])

  const mode = health?.components?.forwarder?.mode || 'demo'

  return (
    <header className="h-16 min-h-[4rem] flex flex-row items-center justify-between px-6 border-b border-border bg-background backdrop-blur-md sticky top-0 z-50">
      {/* Left: breadcrumb-style title */}
      <div className="flex items-center gap-3">
        <span className="text-sm font-medium text-muted-foreground mr-1">Sentinel-Core</span>
        <span className="text-sm text-muted-foreground mr-1">/</span>
        <span className="text-lg font-semibold text-foreground tracking-tight">{PAGE_TITLES[currentPage] || 'Dashboard'}</span>
        <div className={`flex items-center gap-1.5 ml-4 px-2.5 py-1 rounded-md border text-xs font-semibold uppercase tracking-wider shadow-sm transition-all
          ${enforcementMode === 'guardian' ? 'text-destructive border-destructive/30 bg-destructive/10' : 'text-primary border-primary/30 bg-primary/10 shadow-[0_0_15px_rgba(var(--primary),0.2)]'}`}>
          <span className={`w-2 h-2 rounded-full ${enforcementMode === 'guardian' ? 'bg-destructive animate-pulse' : 'bg-primary'}`} />
          {enforcementMode === 'guardian' ? 'Auto Block: ON' : 'Auto Block: OFF'}
        </div>
      </div>

      {/* Right: system status */}
      <div className="flex items-center gap-5">
        {!wsConnected && (
          <span className="text-sm text-destructive font-medium bg-destructive/10 px-3 py-1 rounded">WebSocket disconnected</span>
        )}
        <div className="flex items-center gap-2 text-sm text-emerald-500">
          <Activity className="w-4 h-4" />
          <span className="font-medium">Live</span>
        </div>
        <span className="text-sm text-muted-foreground font-mono bg-muted/50 px-2 py-0.5 rounded border border-border">{mode}</span>
        <span className="text-sm text-muted-foreground font-mono">{clock}</span>
      </div>
    </header>
  )
}
