/**
 * IncidentLedger.jsx — Page B: Incident Ledger
 *
 * Design principles applied:
 * 1. DENSITY: Table is compact and information-dense, like Datadog's log explorer.
 * 2. HIERARCHY: Sparkline is a narrow header strip, not a hero chart.
 * 3. FILTER BAR: Matches real SIEM/observability tool filter UX.
 * 4. PROCESSING TIME: Shown as compact inline monospace badges per row.
 * 5. CONTEXTUAL: Grade badges sized clearly; confidence % always shown.
 * 6. NO DECORATION: Stripe-free table, subtle hover state only.
 */

import { useStore } from '../store'
import { useState, useMemo } from 'react'
import { Search, Filter, Zap, Brain, SlidersHorizontal, X } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'

// Semantic color map — no decoration, only operational meaning
const GRADE_STYLE = {
  TP: { dot: 'bg-red-500', text: 'text-red-400', label: 'TP' },
  BP: { dot: 'bg-blue-500', text: 'text-blue-400', label: 'BP' },
  FP: { dot: 'bg-slate-600', text: 'text-slate-500', label: 'FP' },
}

const SEV_STYLE = {
  critical: { text: 'text-red-400',    dot: 'bg-red-500' },
  high:     { text: 'text-orange-400', dot: 'bg-orange-500' },
  medium:   { text: 'text-amber-400',  dot: 'bg-amber-500' },
  low:      { text: 'text-slate-500',  dot: 'bg-slate-600' },
}

export default function IncidentLedger() {
  const { events, newEventIds, openForensics, timeline } = useStore()
  const [searchQuery, setSearchQuery] = useState('')
  const [gradeFilter, setGradeFilter] = useState(null)
  const [severityFilter, setSeverityFilter] = useState(null)
  const [sortConfig, setSortConfig] = useState({ key: 'timestamp', direction: 'desc' })

  const handleSort = (key) => {
    setSortConfig(current => ({
      key,
      direction: current.key === key && current.direction === 'desc' ? 'asc' : 'desc'
    }))
  }

  const filtered = useMemo(() => {
    let r = [...events]
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      r = r.filter(e =>
        (e.description || '').toLowerCase().includes(q) ||
        (e.telemetry?.binary || '').toLowerCase().includes(q) ||
        (e.telemetry?.pod || '').toLowerCase().includes(q) ||
        (e.explanation?.mitre_id || '').toLowerCase().includes(q)
      )
    }
    if (gradeFilter) r = r.filter(e => e.triage?.grade === gradeFilter)
    if (severityFilter) r = r.filter(e => e.severity === severityFilter)

    r.sort((a, b) => {
      let aVal, bVal
      switch (sortConfig.key) {
        case 'timestamp':
          aVal = new Date(a.timestamp).getTime()
          bVal = new Date(b.timestamp).getTime()
          break
        case 'severity':
          const sevMap = { critical: 4, high: 3, medium: 2, low: 1 }
          aVal = sevMap[a.severity] || 0
          bVal = sevMap[b.severity] || 0
          break
        case 'grade':
          const gradeMap = { TP: 3, BP: 2, FP: 1, '—': 0 }
          aVal = gradeMap[a.triage?.grade || '—'] || 0
          bVal = gradeMap[b.triage?.grade || '—'] || 0
          break
        case 'description':
          aVal = a.description || ''
          bVal = b.description || ''
          break
        default:
          aVal = a[sortConfig.key]
          bVal = b[sortConfig.key]
      }
      if (aVal < bVal) return sortConfig.direction === 'asc' ? -1 : 1
      if (aVal > bVal) return sortConfig.direction === 'asc' ? 1 : -1
      return 0
    })

    return r
  }, [events, searchQuery, gradeFilter, severityFilter, sortConfig])

  const hasFilter = searchQuery || gradeFilter || severityFilter

  // Summary counts for context
  const tpCount = filtered.filter(e => e.triage?.grade === 'TP').length
  const critCount = filtered.filter(e => e.severity === 'critical').length

  return (
    <div className="h-full flex flex-col overflow-hidden bg-background">

      {/* ── SPARKLINE HEADER STRIP */}
      <div className="shrink-0 px-6 py-3 border-b border-border bg-muted/5">
        <div className="flex items-center gap-4">
          <div className="text-xs text-muted-foreground font-semibold uppercase tracking-wider whitespace-nowrap">
            Events / 30 min
          </div>
          <div className="flex-1">
            <SparklineStrip buckets={timeline} />
          </div>
          <div className="text-[10px] text-muted-foreground font-mono whitespace-nowrap">
            {timeline[0] ? formatTime(timeline[0].timestamp) : ''}
            {' – '}
            {timeline[timeline.length - 1] ? formatTime(timeline[timeline.length - 1]?.timestamp) : ''}
          </div>
        </div>
      </div>

      {/* ── FILTER BAR */}
      <div className="shrink-0 px-6 py-3 border-b border-border flex items-center gap-3 bg-background shadow-sm z-10 relative">
        {/* Search */}
        <div className="relative w-80">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Filter: description, binary, pod, MITRE..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="pl-9 h-9 text-sm font-mono bg-muted/30 border-border text-foreground placeholder:text-muted-foreground focus-visible:ring-1 focus-visible:ring-primary shadow-inner transition-all"
          />
        </div>

        <div className="h-6 w-px bg-border" />

        {/* Grade filters */}
        <div className="flex items-center gap-1.5">
          {['TP', 'BP', 'FP'].map(g => {
            const s = GRADE_STYLE[g]
            return (
              <button
                key={g}
                onClick={() => setGradeFilter(gradeFilter === g ? null : g)}
                className={`flex items-center gap-2 h-9 px-3 rounded-md text-xs font-mono font-bold transition-all border cursor-pointer
                  ${gradeFilter === g
                    ? 'bg-primary/10 border-primary/30 text-primary shadow-sm'
                    : 'bg-transparent border-transparent text-muted-foreground hover:bg-muted hover:text-foreground'
                  }`}
              >
                <span className={`w-2 h-2 rounded-full ${s.dot}`} />
                {g}
              </button>
            )
          })}
        </div>

        <div className="h-6 w-px bg-border" />

        {/* Severity filters */}
        <div className="flex items-center gap-1.5">
          {['critical', 'high', 'medium', 'low'].map(s => {
            const st = SEV_STYLE[s]
            return (
              <button
                key={s}
                onClick={() => setSeverityFilter(severityFilter === s ? null : s)}
                className={`flex items-center gap-2 h-9 px-3 rounded-md text-xs font-medium uppercase transition-all border cursor-pointer
                  ${severityFilter === s
                    ? 'bg-primary/10 border-primary/30 text-primary shadow-sm'
                    : 'bg-transparent border-transparent text-muted-foreground hover:bg-muted hover:text-foreground'
                  }`}
              >
                <span className={`w-2 h-2 rounded-full ${st.dot}`} />
                {s.slice(0, 4)}
              </button>
            )
          })}
        </div>

        {hasFilter && (
          <button
            onClick={() => { setGradeFilter(null); setSeverityFilter(null); setSearchQuery('') }}
            className="flex items-center gap-1.5 h-9 px-3 text-xs font-medium text-muted-foreground hover:text-foreground cursor-pointer transition-colors"
          >
            <X className="w-4 h-4" /> Clear
          </button>
        )}

        {/* Result count — right-aligned */}
        <div className="ml-auto flex items-center gap-4 text-xs text-muted-foreground font-mono">
          {tpCount > 0 && <span className="text-destructive font-bold">{tpCount} TP</span>}
          {critCount > 0 && <span className="text-orange-500 font-bold">{critCount} crit</span>}
          <span>{filtered.length} results</span>
        </div>
      </div>

      {/* ── INCIDENT TABLE */}
      <ScrollArea className="flex-1 bg-background relative">
        <Table>
          <TableHeader className="sticky top-0 z-10 bg-muted/20 backdrop-blur-md shadow-sm border-b border-border">
            <TableRow className="border-transparent hover:bg-transparent">
              <SortableHeader label="Time" sortKey="timestamp" width="pl-6" sortConfig={sortConfig} onSort={handleSort} />
              <SortableHeader label="Sev" sortKey="severity" width="w-20" sortConfig={sortConfig} onSort={handleSort} />
              <SortableHeader label="Grade" sortKey="grade" width="w-24" sortConfig={sortConfig} onSort={handleSort} />
              <SortableHeader label="Description" sortKey="description" width="" sortConfig={sortConfig} onSort={handleSort} />
              <TableHead className="text-xs text-muted-foreground font-semibold uppercase tracking-wider h-11 w-40">Binary</TableHead>
              <TableHead className="text-xs text-muted-foreground font-semibold uppercase tracking-wider h-11 w-32">Pod</TableHead>
              <TableHead className="text-xs text-muted-foreground font-semibold uppercase tracking-wider h-11 w-24">MITRE</TableHead>
              <TableHead className="text-xs text-muted-foreground font-semibold uppercase tracking-wider h-11 w-48 pr-6">eBPF / Triage / AI</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="text-center text-muted-foreground py-20 text-sm">
                  No events match current filters
                </TableCell>
              </TableRow>
            ) : (
              filtered.map(event => {
                const isNew = newEventIds.has(event.event_id)
                const grade = event.triage?.grade || '—'
                const gs = GRADE_STYLE[grade]
                const ss = SEV_STYLE[event.severity] || SEV_STYLE.medium
                const pt = event.processing_time || {}
                const isTP = grade === 'TP'

                return (
                  <TableRow
                    key={event.event_id}
                    onClick={() => openForensics(event)}
                    className={`border-border cursor-pointer text-sm h-11 transition-colors
                      ${isNew ? 'bg-primary/5' : ''}
                      ${isTP ? 'hover:bg-destructive/10' : 'hover:bg-muted/50'}`}
                  >
                    {/* Time */}
                    <TableCell className="font-mono text-xs text-muted-foreground pl-6 py-2">
                      {formatTimestamp(event.timestamp)}
                    </TableCell>

                    {/* Severity */}
                    <TableCell className="py-2">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${ss.dot}`} />
                        <span className={`text-xs font-bold uppercase tracking-wider ${ss.text}`}>
                          {(event.severity || 'med').slice(0, 4)}
                        </span>
                      </div>
                    </TableCell>

                    {/* Grade + confidence */}
                    <TableCell className="py-2">
                      {gs ? (
                        <div className="flex items-center gap-2">
                          <span className={`w-2 h-2 rounded-full ${gs.dot}`} />
                          <span className={`text-xs font-mono font-bold ${gs.text}`}>{grade}</span>
                          <span className="text-[10px] text-muted-foreground/70">
                            {event.triage?.confidence ? `${Math.round(event.triage.confidence * 100)}%` : ''}
                          </span>
                        </div>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>

                    {/* Description */}
                    <TableCell className="py-2 text-foreground/80 max-w-sm">
                      <span className="block truncate pr-4 font-medium" title={event.description}>
                        {event.description}
                      </span>
                    </TableCell>

                    {/* Binary */}
                    <TableCell className="py-2 font-mono text-xs text-primary/90 truncate max-w-[10rem]">
                      <span className="block truncate" title={event.telemetry?.binary}>
                        {shortPath(event.telemetry?.binary)}
                      </span>
                    </TableCell>

                    {/* Pod */}
                    <TableCell className="py-2 font-mono text-xs text-purple-400/90 truncate max-w-[8rem]">
                      <span className="block truncate" title={event.telemetry?.pod}>
                        {event.telemetry?.pod || '—'}
                      </span>
                    </TableCell>

                    {/* MITRE */}
                    <TableCell className="py-2">
                      <span className="text-xs font-mono text-muted-foreground bg-muted px-1.5 py-0.5 rounded">
                        {event.explanation?.mitre_id || '—'}
                      </span>
                    </TableCell>

                    {/* Processing time — compact inline badges */}
                    <TableCell className="py-0 pr-6">
                      <div className="flex items-center gap-1">
                        <Tooltip>
                          <TooltipTrigger>
                            <span className="text-[9px] font-mono text-emerald-500/60 bg-emerald-950/50 px-1 py-0.5 rounded">
                              {pt.ebpf_intercept_ms || 0.2}ms
                            </span>
                          </TooltipTrigger>
                          <TooltipContent><p className="text-xs">eBPF intercept</p></TooltipContent>
                        </Tooltip>
                        <Tooltip>
                          <TooltipTrigger>
                            <span className="text-[9px] font-mono text-amber-500/60 bg-amber-950/50 px-1 py-0.5 rounded">
                              {pt.guide_triage_ms || 45}ms
                            </span>
                          </TooltipTrigger>
                          <TooltipContent><p className="text-xs">GUIDE triage</p></TooltipContent>
                        </Tooltip>
                        <Tooltip>
                          <TooltipTrigger>
                            <span className="text-[9px] font-mono text-blue-500/60 bg-blue-950/50 px-1 py-0.5 rounded">
                              {((pt.ai_reasoning_ms || 1200) / 1000).toFixed(1)}s
                            </span>
                          </TooltipTrigger>
                          <TooltipContent><p className="text-xs">AI reasoning</p></TooltipContent>
                        </Tooltip>
                      </div>
                    </TableCell>
                  </TableRow>
                )
              })
            )}
          </TableBody>
        </Table>
      </ScrollArea>
    </div>
  )
}

/* ── Narrow sparkline strip — used as context header, not hero chart ── */
function SparklineStrip({ buckets }) {
  if (!buckets || buckets.length === 0) {
    return <div className="h-8 flex items-center text-[10px] text-slate-700">No data</div>
  }
  const maxTotal = Math.max(...buckets.map(b => b.total || 0), 1)
  return (
    <div className="flex items-end gap-[1px] h-8">
      {buckets.map((bucket, idx) => {
        const pct = Math.max(((bucket.total || 0) / maxTotal) * 100, 5)
        const isHigh = (bucket.process_kprobe || 0) > 2
        return (
          <div
            key={idx}
            title={`${formatTime(bucket.timestamp)}: ${bucket.total || 0} events`}
            className={`flex-1 min-w-[2px] cursor-default ${isHigh ? 'bg-red-500/50' : 'bg-slate-600/40'}`}
            style={{ height: `${pct}%` }}
          />
        )
      })}
    </div>
  )
}

function shortPath(p) {
  if (!p) return '—'
  const parts = p.split('/')
  return parts[parts.length - 1]
}

function formatTimestamp(ts) {
  if (!ts) return '—'
  try {
    return new Date(ts).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch { return '—' }
}

function formatTime(ts) {
  if (!ts) return ''
  try { return new Date(ts).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }) }
  catch { return '' }
}

function SortableHeader({ label, sortKey, width, sortConfig, onSort }) {
  const isSorted = sortConfig.key === sortKey
  return (
    <TableHead
      className={`text-xs text-muted-foreground font-semibold uppercase tracking-wider h-11 cursor-pointer hover:text-foreground transition-colors ${width}`}
      onClick={() => onSort(sortKey)}
    >
      <div className="flex items-center gap-1.5 min-w-max">
        {label}
        {isSorted ? (
          <span className="text-[10px] tabular-nums leading-none mt-0.5">
            {sortConfig.direction === 'asc' ? '▲' : '▼'}
          </span>
        ) : (
          <span className="text-[10px] text-transparent leading-none mt-0.5">▼</span>
        )}
      </div>
    </TableHead>
  )
}
