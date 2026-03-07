/**
 * ForensicsPanel.jsx — Page C: Forensics Deep-Dive
 *
 * Design principles:
 * - Left panel: structured event telemetry + MITRE grid (like Splunk/Datadog trace view)
 * - Right panel: AI reasoning + YAML diff remediation
 * - Neutralize button shown as a serious operation, disabled until AI completes
 * - No glow, no gradients — color only for semantic meaning
 * - Processing time shown in header bar as key operational metrics
 */

import { useStore } from '../store'
import { useState, useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import { ChevronLeft, Brain, Terminal, CheckCircle2, Loader2, Shield, Zap, Activity, SlidersHorizontal } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'

const GRADE_STYLE = {
  TP: { text: 'text-red-400',    dot: 'bg-red-500' },
  BP: { text: 'text-blue-400',   dot: 'bg-blue-500' },
  FP: { text: 'text-slate-500',  dot: 'bg-slate-600' },
}

export default function ForensicsPanel() {
  const { selectedEvent, forensicsData, forensicsLoading, closeForensics, neutralizeEvent, navigate } = useStore()
  const [isNeutralizing, setIsNeutralizing] = useState(false)
  const [neutralized, setNeutralized] = useState(false)
  const [streamedText, setStreamedText] = useState('')
  const [streamComplete, setStreamComplete] = useState(false)
  const streamRef = useRef(null)

  useEffect(() => {
    if (!forensicsData?.reasoning) return
    setStreamedText('')
    setStreamComplete(false)
    const text = forensicsData.reasoning
    let idx = 0
    streamRef.current = setInterval(() => {
      idx += 10
      if (idx >= text.length) {
        setStreamedText(text)
        setStreamComplete(true)
        clearInterval(streamRef.current)
      } else {
        setStreamedText(text.slice(0, idx))
      }
    }, 20)
    return () => { if (streamRef.current) clearInterval(streamRef.current) }
  }, [forensicsData?.reasoning])

  const handleNeutralize = async () => {
    if (!selectedEvent) return
    setIsNeutralizing(true)
    const result = await neutralizeEvent(selectedEvent.event_id)
    setIsNeutralizing(false)
    if (result) setNeutralized(true)
  }

  // Empty state
  if (!selectedEvent) {
    return (
      <div className="h-full flex flex-col items-center justify-center gap-4 bg-[#0a0e1a]">
        <Brain className="w-12 h-12 text-slate-700" />
        <p className="text-[14px] font-semibold text-slate-400">No incident selected</p>
        <p className="text-[12px] text-slate-600 max-w-sm text-center">
          Click a row in the Incident Ledger to open forensic analysis.
        </p>
        <Button variant="outline" size="sm" className="mt-2 text-[12px] border-white/[0.08] text-slate-400 hover:text-slate-200 cursor-pointer" onClick={() => navigate('ledger')}>
          <ChevronLeft className="w-3.5 h-3.5 mr-1" /> Go to Ledger
        </Button>
      </div>
    )
  }

  if (forensicsLoading) {
    return (
      <div className="h-full flex items-center justify-center gap-3 bg-[#0a0e1a]">
        <Loader2 className="w-5 h-5 text-slate-500 animate-spin" />
        <span className="text-[13px] text-slate-500">Running forensic analysis...</span>
      </div>
    )
  }

  const event = selectedEvent
  const data = forensicsData
  const grade = event.triage?.grade || '—'
  const gs = GRADE_STYLE[grade] || GRADE_STYLE.FP
  const pt = event.processing_time || {}

  return (
    <div className="h-full flex flex-col overflow-hidden bg-background">

      {/* ── CONTEXT BAR ── */}
      <div className="shrink-0 h-14 px-6 border-b border-border bg-muted/5 flex items-center gap-4">
        <button
          onClick={closeForensics}
          className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
        >
          <ChevronLeft className="w-4 h-4" /> Ledger
        </button>
        <span className="text-muted-foreground/30 text-lg font-light">/</span>

        {/* Severity */}
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${event.severity === 'critical' ? 'bg-destructive' : event.severity === 'high' ? 'bg-orange-500' : 'bg-amber-500'}`} />
          <span className={`text-xs font-bold uppercase tracking-wider ${event.severity === 'critical' ? 'text-destructive' : event.severity === 'high' ? 'text-orange-500' : 'text-amber-500'}`}>
            {event.severity}
          </span>
        </div>

        <span className="text-muted-foreground/30 text-lg font-light">&bull;</span>

        {/* Grade */}
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${gs.dot}`} />
          <span className={`text-xs font-mono font-bold ${gs.text}`}>{grade}</span>
          <span className="text-[10px] text-muted-foreground/70 font-medium">{event.triage?.confidence ? `${Math.round(event.triage.confidence * 100)}%` : ''}</span>
        </div>

        <span className="text-muted-foreground/30 text-lg font-light">&bull;</span>
        <span className="text-sm font-medium text-muted-foreground truncate flex-1">{event.description}</span>

        {/* Processing time badges */}
        <div className="flex items-center gap-2 shrink-0">
          <span className="text-[10px] font-mono font-medium text-emerald-500 bg-emerald-500/10 border border-emerald-500/20 px-2 py-1 rounded-md flex items-center gap-1">
            <Zap className="w-3 h-3" />{pt.ebpf_intercept_ms || 0.2}ms
          </span>
          <span className="text-[10px] font-mono font-medium text-amber-500 bg-amber-500/10 border border-amber-500/20 px-2 py-1 rounded-md flex items-center gap-1">
            <SlidersHorizontal className="w-3 h-3" />{pt.guide_triage_ms || 45}ms
          </span>
          <span className="text-[10px] font-mono font-medium text-blue-500 bg-blue-500/10 border border-blue-500/20 px-2 py-1 rounded-md flex items-center gap-1">
            <Brain className="w-3 h-3" />{((pt.ai_reasoning_ms || 1200) / 1000).toFixed(1)}s
          </span>
        </div>
      </div>

      {/* ── MAIN BODY: Left telemetry + Right analysis ── */}
      <div className="flex-1 flex overflow-hidden">

        {/* LEFT: Event telemetry + MITRE grid */}
        <div className="w-96 border-r border-border flex flex-col overflow-hidden bg-muted/5 z-0">
          <ScrollArea className="flex-1">
            <div className="p-6 space-y-6">

              {/* Event fields */}
              <div>
                <div className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-4 flex items-center gap-2">
                  Event Telemetry
                </div>
                <TelemetryGrid event={event} />
              </div>

              <Separator className="bg-border" />

              {/* MITRE ATT&CK grid */}
              {data?.mitre_tactics && (
                <div>
                  <div className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-4">
                    MITRE ATT&CK — {data.mitre_technique?.tactic || ''} ({data.mitre_technique?.tactic_id || ''})
                  </div>
                  <MitreGrid tactics={data.mitre_tactics} technique={data.mitre_technique} />
                  {data.mitre_technique && (
                    <div className="mt-4 p-4 rounded-lg bg-background border border-border shadow-sm">
                      <div className="text-sm font-mono font-bold text-destructive mb-2">
                        {data.mitre_technique.id}: {data.mitre_technique.name}
                      </div>
                      <div className="text-xs text-muted-foreground leading-relaxed">
                        {data.mitre_technique.description}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Citations */}
              {data?.citations && (
                <div>
                  <div className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-3">
                    Sources
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {data.citations.map((c, i) => (
                      <span key={i} className={`text-xs font-medium px-2 py-1 rounded-md border shadow-sm
                        ${c.type === 'framework' ? 'text-destructive border-destructive/20 bg-destructive/10' :
                          c.type === 'benchmark' ? 'text-blue-500 border-blue-500/20 bg-blue-500/10' :
                          c.type === 'dataset'   ? 'text-emerald-500 border-emerald-500/20 bg-emerald-500/10' :
                          'text-muted-foreground border-border bg-muted/50'
                        }`}>
                        {c.source}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </ScrollArea>
        </div>

        {/* RIGHT: AI reasoning + remediation */}
        <div className="flex-1 flex flex-col overflow-hidden">

          {/* Top Half: Analysis & Reasoning */}
          <div className="flex-1 flex flex-col overflow-hidden border-b border-border">
            <ScrollArea className="flex-1 bg-background relative z-0">
              
              {/* SHAP Analysis */}
              {data?.shap_values && (
                <div className="border-b border-border">
                  <div className="px-6 py-4 flex items-center justify-between bg-muted/5 border-b border-border">
                    <div className="flex items-center gap-3">
                      <Activity className="w-4 h-4 text-primary" />
                      <span className="text-sm font-semibold text-foreground tracking-tight">Analysis & Reasoning (XAI)</span>
                    </div>
                    <div className="text-[10px] uppercase tracking-wider font-bold text-amber-500 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded">
                      SHAP Analysis
                    </div>
                  </div>
                  <div className="px-6 pb-6 pt-5 space-y-5">
                    <p className="text-xs text-muted-foreground">Top factors contributing to this classification. Positive values push towards "True Positive", negative away.</p>
                    <div className="space-y-3">
                      {data.shap_values.map((shap, i) => (
                        <div key={i} className="flex items-center gap-4 text-sm font-mono">
                          <div className="w-40 truncate text-xs text-foreground/80">{shap.factor}</div>
                          <div className="flex-1 flex items-center">
                            <div className="flex-1 bg-muted/30 h-1.5 rounded-full relative">
                              {shap.score > 0 ? (
                                <div className="absolute left-1/2 h-full bg-destructive rounded-r-full" style={{ width: `${Math.min(shap.score * 100, 50)}%` }} />
                              ) : (
                                <div className="absolute right-1/2 h-full bg-emerald-500 rounded-l-full" style={{ width: `${Math.min(Math.abs(shap.score) * 100, 50)}%` }} />
                              )}
                              <div className="absolute left-1/2 top-0 bottom-0 w-px bg-border z-10" />
                            </div>
                          </div>
                          <div className={`w-16 text-right text-[11px] font-bold ${shap.score > 0 ? 'text-destructive' : 'text-emerald-500'}`}>
                            {shap.score > 0 ? '+' : ''}{shap.score.toFixed(3)}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* AI Reasoning */}
              <div className="px-6 py-4 flex items-center gap-3 bg-muted/5 border-b border-border">
                <Brain className="w-4 h-4 text-primary" />
                <span className="text-sm font-semibold text-foreground tracking-tight">AI Remediation Guide (RAG)</span>
                {!streamComplete
                  ? <span className="text-xs text-muted-foreground flex items-center gap-1.5 ml-2"><Loader2 className="w-3.5 h-3.5 animate-spin" /> generating...</span>
                  : <span className="text-xs text-emerald-500 flex items-center gap-1.5 ml-2"><CheckCircle2 className="w-3.5 h-3.5" /> complete</span>
                }
              </div>
              <div className="p-6 font-mono text-sm text-foreground/80 leading-relaxed whitespace-pre-wrap max-w-4xl">
                {streamedText}
                {!streamComplete && <span className="inline-block w-2 h-4 bg-muted-foreground animate-pulse ml-1 align-middle" />}
              </div>
            </ScrollArea>
          </div>

          {/* Remediation YAML */}
          <div className="h-80 flex flex-col overflow-hidden">
            <div className="shrink-0 px-6 py-4 border-b border-border flex items-center justify-between bg-muted/5 z-0">
              <div className="flex items-center gap-3">
                <Terminal className="w-4 h-4 text-muted-foreground" />
                <span className="text-sm font-semibold text-foreground tracking-tight">Remediation Policy (YAML)</span>
              </div>
              <Button
                size="sm"
                disabled={!streamComplete || isNeutralizing || neutralized}
                onClick={handleNeutralize}
                className={`h-9 px-4 text-xs font-bold tracking-wider cursor-pointer shadow-sm transition-all rounded-md
                  ${neutralized
                    ? 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 hover:bg-emerald-500/10'
                    : streamComplete
                      ? 'bg-destructive text-white hover:bg-destructive/90 shadow-[0_4px_10px_rgba(239,68,68,0.2)]'
                      : 'bg-muted text-muted-foreground cursor-not-allowed border border-border'
                  }`}
              >
                {neutralized ? <><CheckCircle2 className="w-4 h-4 mr-2" />Neutralized</>
                  : isNeutralizing ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Patching...</>
                  : <><Shield className="w-4 h-4 mr-2" />Neutralize & Patch</>}
              </Button>
            </div>
            {data?.remediation ? (
              <Tabs defaultValue="diff" className="flex-1 flex flex-col overflow-hidden">
                <TabsList className="shrink-0 h-10 bg-transparent border-b border-border rounded-none justify-start px-6 gap-3 pt-2 font-medium">
                  {['diff', 'insecure', 'secure'].map(tab => (
                    <TabsTrigger key={tab} value={tab}
                      className="h-8 px-4 text-xs font-semibold uppercase rounded-md data-[state=active]:bg-muted data-[state=active]:text-foreground text-muted-foreground cursor-pointer transition-colors border border-transparent data-[state=active]:border-border data-[state=active]:shadow-sm">
                      {tab}
                    </TabsTrigger>
                  ))}
                </TabsList>
                <TabsContent value="diff" className="flex-1 overflow-hidden m-0">
                  <div className="grid grid-cols-2 h-full bg-background z-0 relative">
                    <div className="border-r border-border overflow-auto p-5 bg-destructive/5 z-0">
                      <div className="text-[10px] text-destructive font-bold mb-3 uppercase tracking-widest flex items-center gap-2">
                        <span className="w-1.5 h-1.5 bg-destructive rounded-full" /> Insecure
                      </div>
                      <YamlCode code={data.remediation.insecure_yaml} variant="insecure" />
                    </div>
                    <div className="overflow-auto p-5 bg-emerald-500/5 z-0">
                      <div className="text-[10px] text-emerald-500 font-bold mb-3 uppercase tracking-widest flex items-center gap-2">
                        <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full" /> Secure
                      </div>
                      <YamlCode code={data.remediation.secure_yaml} variant="secure" />
                    </div>
                  </div>
                </TabsContent>
                <TabsContent value="insecure" className="flex-1 overflow-auto m-0 p-5 bg-destructive/5">
                  <YamlCode code={data.remediation.insecure_yaml} variant="insecure" />
                </TabsContent>
                <TabsContent value="secure" className="flex-1 overflow-auto m-0 p-5 bg-emerald-500/5">
                  <YamlCode code={data.remediation.secure_yaml} variant="secure" />
                </TabsContent>
              </Tabs>
            ) : (
              <div className="flex-1 flex items-center justify-center text-xs text-muted-foreground bg-background">Loading remediation...</div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

/* ── Compact telemetry key/value grid ── */
function TelemetryGrid({ event }) {
  const tel = event.telemetry || {}
  const rows = [
    ['Event ID',       event.event_id?.slice(0, 18) + '…', ''],
    ['Timestamp',      event.timestamp, ''],
    ['Event Type',     event.event_type, ''],
    ['Node',           event.node_name, ''],
    ['Binary',         tel.binary, 'text-primary/90 font-semibold'],
    ['Args',           (tel.args || []).join(' ') || '—', ''],
    ['PID / PPID',     `${tel.pid} / ${tel.parent_pid}`, ''],
    ['User (UID)',      `${tel.user} (${tel.uid})`, tel.uid === 0 ? 'text-destructive font-semibold' : ''],
    ['Namespace',      tel.namespace || '—', ''],
    ['Pod',            tel.pod || '—', 'text-purple-400/90 font-semibold'],
    ['Container',      tel.container_id || '—', ''],
    ['Parent Binary',  tel.parent_binary || '—', ''],
    ['MITRE ID',       event.explanation?.mitre_id || '—', 'text-destructive font-semibold bg-destructive/10 px-1 py-0.5 rounded'],
  ]

  return (
    <div className="space-y-1.5 bg-background p-4 rounded-xl shadow-sm border border-border">
      {rows.map(([key, val, cls]) => (
        <div key={key} className="grid grid-cols-[112px_1fr] gap-3 text-xs border-b border-border/50 pb-1.5 last:border-0 last:pb-0">
          <span className="text-muted-foreground font-medium">{key}</span>
          <span className={`font-mono break-all text-foreground ${cls || ''}`}>{val}</span>
        </div>
      ))}
    </div>
  )
}

/* ── Compact MITRE ATT&CK tactic grid ── */
function MitreGrid({ tactics, technique }) {
  return (
    <div className="flex flex-wrap gap-2">
      {tactics.map(tactic => {
        const isActive = tactic.id === technique?.tactic_id
        return (
          <div
            key={tactic.id}
            className={`px-2 py-1 rounded-md text-[10px] font-medium transition-all border shadow-sm
              ${isActive
                ? 'bg-destructive/10 border-destructive/30 text-destructive shadow-[0_0_8px_rgba(239,68,68,0.15)]'
                : 'bg-background border-border text-muted-foreground'
              }`}
          >
            {isActive && <span className="font-bold mr-1">{technique.id} ·</span>}
            {tactic.short || tactic.name}
          </div>
        )
      })}
    </div>
  )
}

function YamlCode({ code, variant }) {
  return (
    <pre className={`text-xs font-mono leading-relaxed whitespace-pre-wrap
      ${variant === 'insecure' ? 'text-destructive/80' : 'text-emerald-500/80'}`}>
      {code || 'No YAML available'}
    </pre>
  )
}
