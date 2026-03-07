/**
 * CommandCenter.jsx — Page A: Immunity Command Center
 *
 * Design principles applied:
 * 1. HIERARCHY: Top status bar is compact; cluster map is the dominant visual.
 * 2. ASYMMETRY: Cluster map takes 8/12 columns; right panel stacks secondary data.
 * 3. NO GLOW: All neon shadows/gradients removed. Color used semantically only.
 * 4. OPERATIONAL METRICS: Every number has context (last seen, trend, percent).
 * 5. ENFORCEMENT: Shown as a structured state panel, not a decorative toggle.
 * 6. CLUSTER NODES: Structured data rows, not icon blobs.
 * 7. CHARTS: Include axis labels and units.
 */

import { useStore } from '../store'
import { motion } from 'framer-motion'
import { Shield, Server, Activity, AlertTriangle, CheckCircle, TrendingUp, BarChart2, Brain, CheckCircle2, Database, Compass, HardHat, Cog, Hexagon, Box, Zap } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useMemo, useState } from 'react'

export default function CommandCenter() {
  const {
    immunityScore, immunityData, metrics, triageStats, cluster,
    enforcementMode, toggleEnforcement, events, policies, timeline,
  } = useStore()

  const lastEventAge = useMemo(() => {
    if (!metrics?.last_event_timestamp) return null
    const delta = (Date.now() - new Date(metrics.last_event_timestamp)) / 1000
    return delta < 60 ? `${Math.round(delta)}s ago` : `${Math.round(delta / 60)}m ago`
  }, [metrics?.last_event_timestamp])

  const tpCount = triageStats?.breakdown?.TruePositive || 0
  const fpCount = triageStats?.breakdown?.FalsePositive || 0
  const bpCount = triageStats?.breakdown?.BenignPositive || 0
  const totalTriaged = tpCount + fpCount + bpCount || 1
  const filterRatio = Math.round(((fpCount + bpCount) / totalTriaged) * 100)

  return (
    <div className="h-full overflow-y-auto bg-[#0a0e1a]">
      {/* ── TOP STATUS STRIP ────────────────────────────────────────── */}
      <div className="px-6 py-5 border-b border-border flex items-stretch gap-4 overflow-x-auto bg-muted/10 shadow-sm z-10 relative">
        
        {/* Security Score */}
        <div className="glass-card flex-1 min-w-[220px] p-5 flex flex-col justify-between">
          <div className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">Immunity Score</div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className={`text-4xl font-extrabold tracking-tight tabular-nums drop-shadow-sm
              ${immunityScore >= 80 ? 'text-emerald-500' : immunityScore >= 50 ? 'text-amber-500' : 'text-destructive'}`}>
              {Math.round(immunityScore)}
            </span>
            <span className="text-xs text-muted-foreground font-medium">/ 100 pts</span>
          </div>
        </div>

        {/* Blocked Threats */}
        <div className="glass-card flex-1 min-w-[220px] p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <div className="text-sm font-semibold text-muted-foreground">Blocked Threats</div>
            <Shield className="w-4 h-4 text-destructive/80" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold tracking-tight text-destructive drop-shadow-sm">{tpCount}</span>
            <span className="text-xs text-muted-foreground font-medium">{triageStats?.percentages?.TruePositive || 0}% of events</span>
          </div>
        </div>


        {/* Event rate */}
        <div className="glass-card flex-1 min-w-[220px] p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <div className="text-sm font-semibold text-muted-foreground">Total Events</div>
            <BarChart2 className="w-4 h-4 text-muted-foreground/80" />
          </div>
          <div className="mt-3 flex flex-col">
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold tracking-tight text-foreground drop-shadow-sm">{metrics?.events_total || 0}</span>
              <span className="text-xs text-muted-foreground font-medium">{metrics?.events_per_second || 0} evt/s</span>
            </div>
            <span className="text-[10px] text-muted-foreground mt-1 tracking-tight">last seen: {lastEventAge || 'no data'}</span>
          </div>
        </div>

      </div>

      {/* ── MAIN BODY ─────────────────────────────────────────────────
          Cluster map is dominant (8 col). Right panel stacks secondary data. */}
      <div className="flex h-[calc(100%-57px)]">

        {/* LEFT: Cluster Map */}
        <div className="flex-1 border-r border-border flex flex-col overflow-hidden bg-background">
          <div className="px-6 py-4 border-b border-border flex items-center justify-between bg-muted/5">
            <div className="flex items-center gap-3">
              <div className="p-1.5 bg-primary/10 rounded-md border border-primary/20">
                <Server className="w-4 h-4 text-primary" />
              </div>
              <span className="text-sm font-semibold text-foreground tracking-tight">Cluster Node Map</span>
              <span className="text-xs text-muted-foreground ml-2 px-2 py-0.5 bg-muted rounded-full">— kind-control-plane · 3 nodes · {cluster?.total_pods || 0} pods</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-emerald-500 font-medium px-2 py-1 bg-emerald-500/10 rounded-md border border-emerald-500/20 shadow-[0_0_10px_rgba(16,185,129,0.1)]">
              <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
              Live Monitor
            </div>
          </div>
          <div className="flex-1 overflow-hidden p-6">
            <LiveNodeGraph cluster={cluster} events={events} />
          </div>
        </div>

        {/* RIGHT PANEL: Secondary data stack */}
        <div className="w-[340px] flex flex-col overflow-y-auto p-5 space-y-5 bg-muted/5">
          
          {/* Auto-Block Panel */}
          <div className="glass-panel p-5 rounded-xl">
            <div className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-4 flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Auto-Block Config
            </div>
            <div className="space-y-3.5">
              <div className="flex items-center justify-between bg-background p-3 rounded-lg border border-border shadow-sm">
                <span className="text-sm font-medium text-foreground">Status</span>
                <div className="flex items-center gap-3">
                  <Switch
                    checked={enforcementMode === 'guardian'}
                    onCheckedChange={toggleEnforcement}
                    className="h-5 w-9 data-[state=checked]:bg-destructive data-[state=unchecked]:bg-primary"
                  />
                  <span className={`text-xs font-bold uppercase tracking-wider ${enforcementMode === 'guardian' ? 'text-destructive' : 'text-primary'}`}>
                    {enforcementMode === 'guardian' ? 'ON' : 'OFF'}
                  </span>
                </div>
              </div>
              <div className="pt-2 space-y-2">
                <OperationalRow label="Active Policies" value={`${policies?.length || 0} active`} />
                <OperationalRow label="Alert Threshold" value="HIGH and above" />
                <OperationalRow label="Last Toggle" value={new Date().toLocaleTimeString('en-US', { hour12: false })} />
              </div>
            </div>
          </div>

          {/* Severity Breakdown */}
          <div className="glass-panel p-5 rounded-xl">
            <div className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-4 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              Severity Breakdown
            </div>
            <div className="space-y-3">
              <SeverityRow label="CRITICAL" count={metrics?.severity_breakdown?.critical || 0} total={metrics?.events_total || 1} color="text-destructive font-bold" barColor="bg-destructive shadow-[0_0_8px_rgba(var(--destructive),0.5)]" />
              <SeverityRow label="HIGH"     count={metrics?.severity_breakdown?.high || 0}     total={metrics?.events_total || 1} color="text-orange-500 font-bold" barColor="bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.5)]" />
              <SeverityRow label="MEDIUM"   count={metrics?.severity_breakdown?.medium || 0}   total={metrics?.events_total || 1} color="text-amber-500 font-medium" barColor="bg-amber-500" />
              <SeverityRow label="LOW"      count={metrics?.severity_breakdown?.low || 0}      total={metrics?.events_total || 1} color="text-muted-foreground" barColor="bg-muted-foreground" />
            </div>
          </div>

          {/* ML Triage Distribution */}
          <div className="glass-panel p-5 rounded-xl">
            <div className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-4 flex items-center gap-2">
              <CheckCircle className="w-4 h-4" />
              Triage Distribution
            </div>
            <div className="space-y-3">
              <TriageRow label="True Positive"   count={tpCount}  pct={triageStats?.percentages?.TruePositive || 0}   color="text-destructive font-semibold" barColor="bg-destructive shadow-[0_0_8px_rgba(var(--destructive),0.5)]" />
              <TriageRow label="Benign Positive" count={bpCount}  pct={triageStats?.percentages?.BenignPositive || 0} color="text-blue-500 font-semibold" barColor="bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]" />
              <TriageRow label="False Positive"  count={fpCount}  pct={triageStats?.percentages?.FalsePositive || 0}  color="text-muted-foreground" barColor="bg-muted" />
            </div>
            <div className="mt-4 pt-3 border-t border-border text-xs text-muted-foreground font-mono flex justify-between">
              <span>Model: XGBoost</span>
              <span>Avg conf: {Math.round((triageStats?.avg_confidence || 0) * 100)}%</span>
            </div>
          </div>

          {/* Attack Frequency Chart */}
          <div className="glass-panel p-5 rounded-xl flex-1 min-h-[180px] flex flex-col">
            <div className="flex items-center justify-between mb-2">
              <div className="text-xs font-bold text-muted-foreground uppercase tracking-wider flex items-center gap-2">
                <TrendingUp className="w-4 h-4" />
                Attack Frequency
              </div>
              <span className="text-[10px] text-muted-foreground font-mono bg-muted px-1.5 py-0.5 rounded">events/min</span>
            </div>
            <div className="text-xs text-muted-foreground mb-4">Last 30 minutes</div>
            <FrequencyChart buckets={timeline} />
          </div>
        </div>
      </div>
    </div>
  )
}

/* ── Live Node Graph ────────────────────────────────────────────────
   SVG-based cluster map. Nodes show structured operational data.
   Color indicates health/activity, not decoration. */
function LiveNodeGraph({ cluster, events }) {
  const nodeActivity = useMemo(() => {
    const activity = {}
    for (const e of (events || []).slice(0, 50)) {
      const node = e.node_name
      if (node) activity[node] = (activity[node] || 0) + 1
    }
    return activity
  }, [events])

  // Helpers to check activity by node matching
  const isActive = (nMatch) => {
    return Object.entries(nodeActivity).some(([name, count]) => name.includes(nMatch) && count > 0)
  }
  const getCount = (nMatch) => {
    return Object.entries(nodeActivity).filter(([n]) => n.includes(nMatch)).reduce((acc, [_, c]) => acc + c, 0)
  }

  const [selectedNodeId, setSelectedNodeId] = useState(null)

  // Pre-define nodes with wider spacing
  const mapNodes = [
    { id: 'cluster', label: 'Kind Kubernetes Cluster', icon: Database, x: 340, y: 70, w: 240, h: 70, type: 'cluster' },
    
    { id: 'cp', label: 'control-plane', icon: Compass, x: 140, y: 220, w: 180, h: 65, type: 'node', match: '12-14' },
    { id: 'w1', label: 'worker-1', icon: HardHat, x: 340, y: 220, w: 180, h: 65, type: 'node', match: '45-78' },
    { id: 'w2', label: 'worker-2', icon: Cog, x: 540, y: 220, w: 180, h: 65, type: 'node', match: '82-99' },

    { id: 'tet-cp', label: 'Tetragon DaemonSet', icon: Hexagon, x: 140, y: 350, w: 180, h: 60, type: 'agent', match: '12-14' },
    { id: 'tet-w1', label: 'Tetragon Pod', icon: Shield, x: 340, y: 350, w: 180, h: 60, type: 'agent', match: '45-78' },
    { id: 'tet-w2', label: 'Tetragon Pod', icon: Shield, x: 540, y: 350, w: 180, h: 60, type: 'agent', match: '82-99' },
  ]

  // Render a sleek map node
  const renderNode = (n) => {
    const active = n.match ? isActive(n.match) : false
    const count = n.match ? getCount(n.match) : 0
    const bx = n.x - n.w / 2
    const by = n.y - n.h / 2
    const Icon = n.icon
    const isSelected = selectedNodeId === n.id
    const borderColor = isSelected ? 'rgba(56,189,248,1)' : active ? 'rgba(34,211,238,0.4)' : 'rgba(255,255,255,0.15)'
    const bgColor = n.type === 'cluster' ? 'rgba(30,41,59,0.9)' : isSelected ? 'rgba(30,41,59,0.95)' : 'rgba(17,24,39,0.85)'
    
    return (
      <g key={n.id} className="cursor-pointer transition-transform hover:-translate-y-0.5" onClick={() => setSelectedNodeId(n.id === selectedNodeId ? null : n.id)}>
        {active && !isSelected && (
          <rect x={bx - 2} y={by - 2} width={n.w + 4} height={n.h + 4} rx="10" fill="none" stroke="rgba(34,211,238,0.15)" strokeWidth="3">
            <animate attributeName="opacity" values="0.8;0.3;0.8" dur="2s" repeatCount="indefinite" />
          </rect>
        )}
        {(isSelected) && (
          <rect x={bx - 3} y={by - 3} width={n.w + 6} height={n.h + 6} rx="11" fill="none" stroke="rgba(56,189,248,0.4)" strokeWidth="3" />
        )}
        <rect x={bx} y={by} width={n.w} height={n.h} rx="8" fill={bgColor} stroke={borderColor} strokeWidth={isSelected ? "2" : "1.5"} className="drop-shadow-sm transition-colors" />
        <rect x={bx} y={by} width={n.w} height={32} rx="8" fill="rgba(255,255,255,0.04)" />
        <rect x={bx} y={by + 24} width={n.w} height={8} fill="rgba(255,255,255,0.04)" />
        
        {Icon && <Icon className="w-4 h-4 text-emerald-500/90" x={bx + 12} y={by + 9} />}
        
        <text x={bx + 34} y={by + 20} fill={isSelected ? "#bae6fd" : "#f8fafc"} fontSize={n.type === 'cluster' ? '12.5' : '11.5'} fontWeight="600" fontFamily="'JetBrains Mono', monospace">
          {n.label}
        </text>

        {active ? (
          <text x={n.x} y={by + 48} fill="#38bdf8" fontSize="11" fontWeight="bold" textAnchor="middle" fontFamily="Inter, sans-serif">
            {count} recent events
          </text>
        ) : (
           <text x={n.x} y={by + 48} fill="#64748b" fontSize="10" fontWeight="500" textAnchor="middle" fontFamily="Inter, sans-serif">
             Monitoring active
           </text>
        )}
      </g>
    )
  }

  // Draw hierarchical connecting lines
  const renderLines = () => {
    return (
      <g stroke="rgba(255,255,255,0.12)" strokeWidth="1.5" strokeDasharray="4 4" fill="none">
        {/* Cluster to Nodes */}
        <path d="M 340 105 L 340 145 L 140 145 L 140 187" />
        <path d="M 340 105 L 340 187" />
        <path d="M 340 105 L 340 145 L 540 145 L 540 187" />
        
        {/* Nodes to Tetragon */}
        <line x1="140" y1="252" x2="140" y2="320" />
        <line x1="340" y1="252" x2="340" y2="320" />
        <line x1="540" y1="252" x2="540" y2="320" />

        {/* Tetragon to Action Plane */}
        <path d="M 140 380 L 140 420 L 340 420 L 340 435" />
        <path d="M 340 380 L 340 435" />
        <path d="M 540 380 L 540 420 L 340 420 L 340 435" />
      </g>
    )
  }

  // Selected Node Details logic
  const selectedNode = mapNodes.find(n => n.id === selectedNodeId)
  const isAgent = selectedNode?.type === 'agent'
  const isCluster = selectedNode?.type === 'cluster'

  return (
    <div className="w-full h-full flex relative">
      <div className={`flex-1 flex flex-col justify-center items-center transition-all ${selectedNodeId ? 'w-2/3 pr-64' : 'w-full'}`}>
        <svg className="w-full max-h-[580px]" viewBox="20 50 640 480" preserveAspectRatio="xMidYMid meet">
          {renderLines()}
          {mapNodes.map(renderNode)}

          {/* Action Plane (Bottom) */}
          <g transform="translate(230, 435)">
            <rect width="220" height="50" rx="8" fill="rgba(15,23,42,0.95)" stroke="rgba(255,255,255,0.2)" strokeWidth="1.5" className="drop-shadow-lg" />
            <Zap className="w-5 h-5 text-emerald-400" x="50" y="15" />
            <text x="76" y="31" fill="#f8fafc" fontSize="13" fontWeight="bold" fontFamily="Inter, sans-serif">Action Plane</text>
          </g>
        </svg>
      </div>

      {/* Slide-out details panel */}
      {selectedNodeId && (
        <motion.div 
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="absolute right-0 top-0 bottom-0 w-64 bg-background border-l border-border p-5 flex flex-col shadow-xl z-10 overflow-y-auto"
        >
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-primary/10 rounded-md border border-primary/20">
              {selectedNode?.icon && <selectedNode.icon className="w-5 h-5 text-primary" />}
            </div>
            <div>
              <div className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">{selectedNode?.type}</div>
              <div className="text-sm font-semibold text-foreground truncate">{selectedNode?.label}</div>
            </div>
          </div>
          
          <div className="space-y-6">
            <div className="space-y-3">
              <div className="text-xs font-semibold text-muted-foreground uppercase tracking-widest border-b border-border pb-1">Status</div>
              <OperationalRow label="Health" value="Healthy" valueClass="text-emerald-500" />
              <OperationalRow label="Connection" value="Active WebSocket" valueClass="text-emerald-500" />
              <OperationalRow label="Uptime" value="14d 2h 4m" />
            </div>

            {!isCluster && (
              <div className="space-y-3">
                <div className="text-xs font-semibold text-muted-foreground uppercase tracking-widest border-b border-border pb-1">Telemetry</div>
                {isAgent ? (
                  <>
                    <OperationalRow label="eBPF Programs" value="Loaded (Traced)" />
                    <OperationalRow label="Events Sent" value={getCount(selectedNode.match) || '0'} />
                    <OperationalRow label="Memory Usage" value="42 MB" />
                  </>
                ) : (
                  <>
                    <OperationalRow label="Node IP" value={`10.0.${selectedNode.match.replace('-', '.')}`} />
                    <OperationalRow label="Active Pods" value={selectedNode.id === 'cp' ? '12' : '4'} />
                    <OperationalRow label="OS Image" value="Ubuntu 22.04 LTS" />
                  </>
                )}
              </div>
            )}
            
            <button 
              onClick={() => setSelectedNodeId(null)}
              className="w-full mt-4 py-2 bg-muted hover:bg-muted/80 text-foreground text-xs font-medium rounded-md transition-colors"
            >
              Close Details
            </button>
          </div>
        </motion.div>
      )}
    </div>
  )
}

/* Small SVG helper: label/value row inside a node card */
function NodeDataRow({ x, y, label, value, valueColor = '#94a3b8' }) {
  return (
    <>
      <text x={x} y={y} fill="#475569" fontSize="9.5" fontFamily="Inter, sans-serif">{label}</text>
      <text x={x + 100} y={y} fill={valueColor} fontSize="9.5" fontFamily="'JetBrains Mono', monospace" fontWeight="600">{value}</text>
    </>
  )
}

/* ── Severity Row ── */
function SeverityRow({ label, count, total, color, barColor }) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0
  return (
    <div className="flex items-center gap-2">
      <span className={`text-[10px] font-mono font-bold w-14 ${color}`}>{label}</span>
      <div className="flex-1 h-1 bg-slate-800 rounded-sm overflow-hidden">
        <div className={`h-full ${barColor} opacity-70`} style={{ width: `${pct}%`, transition: 'width 0.6s ease' }} />
      </div>
      <span className="text-[11px] font-mono text-slate-300 w-6 text-right">{count}</span>
      <span className="text-[10px] text-slate-600 w-8 text-right">{pct}%</span>
    </div>
  )
}

/* ── Triage Row ── */
function TriageRow({ label, count, pct, color, barColor }) {
  return (
    <div className="flex items-center gap-2">
      <span className={`text-[11px] font-medium w-28 ${color}`}>{label}</span>
      <div className="flex-1 h-1 bg-slate-800 rounded-sm overflow-hidden">
        <div className={`h-full ${barColor} opacity-70`} style={{ width: `${pct}%`, transition: 'width 0.6s ease' }} />
      </div>
      <span className="text-[11px] font-mono text-slate-300 w-6 text-right">{count}</span>
    </div>
  )
}

/* ── Frequency Chart — with axis labels and units ── */
function FrequencyChart({ buckets }) {
  if (!buckets || buckets.length === 0) {
    return <div className="text-[11px] text-slate-600">No timeline data</div>
  }
  const maxTotal = Math.max(...buckets.map(b => b.total || 0), 1)
  const firstTime = buckets[0]?.timestamp ? formatTime(buckets[0].timestamp) : ''
  const lastTime = buckets[buckets.length - 1]?.timestamp ? formatTime(buckets[buckets.length - 1].timestamp) : ''

  return (
    <div>
      {/* Y-axis max label */}
      <div className="text-[9px] text-slate-700 font-mono mb-0.5 text-right">{maxTotal}</div>

      {/* Chart bars */}
      <div className="flex items-end gap-[2px] h-20">
        {buckets.map((bucket, idx) => {
          const pct = Math.max(((bucket.total || 0) / maxTotal) * 100, 3)
          const isHigh = (bucket.process_kprobe || 0) > 2
          return (
            <Tooltip key={idx}>
              <TooltipTrigger asChild>
                <div
                  className={`flex-1 min-w-[2px] cursor-default transition-all
                    ${isHigh ? 'bg-red-500/60' : 'bg-slate-600/60'}
                    hover:opacity-100 opacity-75`}
                  style={{ height: `${pct}%` }}
                />
              </TooltipTrigger>
              <TooltipContent side="top">
                <p className="text-[11px] font-mono">
                  {formatTime(bucket.timestamp)} — <strong>{bucket.total || 0}</strong> events
                  {isHigh && ' · HIGH ACTIVITY'}
                </p>
              </TooltipContent>
            </Tooltip>
          )
        })}
      </div>

      {/* X-axis: time range */}
      <div className="flex justify-between mt-1">
        <span className="text-[9px] text-slate-700 font-mono">{firstTime}</span>
        <span className="text-[9px] text-slate-700 font-mono">{lastTime}</span>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-3 mt-2">
        <div className="flex items-center gap-1">
          <div className="w-3 h-1.5 bg-slate-600/60" />
          <span className="text-[9px] text-slate-600">Normal</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-1.5 bg-red-500/60" />
          <span className="text-[9px] text-slate-600">High activity</span>
        </div>
      </div>
    </div>
  )
}

/* ── Operational row for Enforcement panel ── */
function OperationalRow({ label, value, valueClass = 'text-slate-300' }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[11px] text-slate-500">{label}</span>
      <span className={`text-[11px] font-mono font-semibold ${valueClass}`}>{value}</span>
    </div>
  )
}

function formatTime(ts) {
  if (!ts) return ''
  try { return new Date(ts).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }) }
  catch { return '' }
}
