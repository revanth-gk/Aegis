/**
 * Sidebar.jsx — Production Nav
 *
 * Design principles:
 * - Narrow, functional navigation. No marketing elements.
 * - System stats shown as plain data rows, not decorative numbers.
 * - Connection status shown as text indicators with minimal dots.
 */

import { useStore } from '../store'
import { Shield, BookOpen, Crosshair, LayoutDashboard } from 'lucide-react'
import { Separator } from '@/components/ui/separator'

const NAV = [
  { id: 'command', label: 'Command Center', icon: LayoutDashboard },
  { id: 'ledger',  label: 'Incident Ledger', icon: BookOpen },
]

export default function Sidebar() {
  const { currentPage, navigate, metrics, wsConnected, health, enforcementMode, triageStats } = useStore()
  const alertCount = metrics?.active_alerts || 0

  return (
    <aside className="w-64 min-w-[16rem] flex flex-col bg-sidebar border-r border-sidebar-border">

      {/* Brand */}
      <div className="px-6 py-5 border-b border-sidebar-border">
        <div className="flex items-center gap-3">
          <div className="bg-primary/20 p-2 rounded-lg border border-primary/30">
            <Shield className="w-5 h-5 text-primary shrink-0" />
          </div>
          <div>
            <div className="text-base font-semibold text-sidebar-foreground tracking-tight">Sentinel-Core</div>
            <div className="text-xs text-muted-foreground mt-0.5 font-mono">eBPF · v2.0</div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-4 py-5 flex flex-col gap-1 overflow-y-auto">
        <div className="text-xs font-semibold text-sidebar-foreground/70 uppercase tracking-wider px-2 pb-3">
          Navigation
        </div>

        {NAV.map(item => {
          const Icon = item.icon
          const active = currentPage === item.id
          return (
            <button
              key={item.id}
              onClick={() => navigate(item.id)}
              className={`flex items-center gap-3 w-full px-3 py-2.5 rounded-lg text-sm font-medium text-left transition-all cursor-pointer group
                ${active
                  ? 'bg-primary/10 text-primary shadow-sm border border-primary/20'
                  : 'text-muted-foreground hover:text-foreground hover:bg-sidebar-accent border border-transparent'
                }`}
            >
              <Icon className={`w-4 h-4 shrink-0 transition-colors ${active ? 'text-primary' : 'text-muted-foreground group-hover:text-foreground'}`} />
              <span className="flex-1 truncate">{item.label}</span>
              {item.id === 'ledger' && alertCount > 0 && (
                <span className="text-xs font-bold font-mono text-destructive bg-destructive/10 border border-destructive/20 px-2 py-0.5 rounded-md shadow-sm">
                  {alertCount}
                </span>
              )}
            </button>
          )
        })}

        <Separator className="my-6 bg-border" />

        {/* System snapshot */}
        <div className="text-xs font-semibold text-sidebar-foreground/70 uppercase tracking-wider px-2 pb-3">
          System Overview
        </div>
        <div className="px-2 space-y-3">
          <SidebarStat label="Events"   value={`${metrics?.events_total || 0}`} sub={`${metrics?.events_per_second || 0}/s`} />
          <SidebarStat label="Threats"  value={`${triageStats?.breakdown?.TruePositive || 0}`} valueClass="text-destructive font-bold" />
          <SidebarStat label="Filtered" value={`${(triageStats?.breakdown?.FalsePositive || 0) + (triageStats?.breakdown?.BenignPositive || 0)}`} />
          <SidebarStat label="Auto Block" value={enforcementMode === 'guardian' ? 'ON' : 'OFF'} valueClass={enforcementMode === 'guardian' ? 'text-destructive font-bold' : 'text-primary font-bold'} />
        </div>
      </nav>

      {/* Connection indicators */}
      <div className="px-5 py-4 border-t border-sidebar-border space-y-2.5 bg-sidebar-accent/30">
        <ConnRow label="WebSocket API" ok={wsConnected} />
        <ConnRow label="REST Backend"  ok={true} />
        <ConnRow label="Tetragon Agent" ok={true} />
      </div>
    </aside>
  )
}

function SidebarStat({ label, value, sub, valueClass = 'text-sidebar-foreground' }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-sidebar-foreground/80 font-medium">{label}</span>
      <div className="text-right">
        <span className={`text-sm tracking-tight ${valueClass}`}>{value}</span>
        {sub && <span className="text-xs text-muted-foreground ml-1.5">{sub}</span>}
      </div>
    </div>
  )
}

function ConnRow({ label, ok }) {
  return (
    <div className="flex items-center gap-3 text-xs text-sidebar-foreground">
      <span className={`w-2 h-2 rounded-full shadow-sm ${ok ? 'bg-emerald-500 shadow-emerald-500/50' : 'bg-destructive animate-pulse shadow-destructive/50'}`} />
      <span className="font-medium tracking-tight">{label}</span>
    </div>
  )
}
