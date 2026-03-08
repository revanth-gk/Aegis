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
      </div>

      {/* Right: system status */}
      <div className="flex items-center gap-5">
        <span className="text-sm text-muted-foreground font-mono">{clock}</span>
      </div>
    </header>
  )
}
