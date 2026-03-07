import { create } from 'zustand'

const API_BASE = ''  // relative - proxied by Vite

export const useStore = create((set, get) => ({
  // ── Navigation ──
  currentPage: 'command',  // 'command' | 'ledger' | 'forensics'
  navigate: (page) => set({ currentPage: page }),

  // ── Enforcement Mode ──
  enforcementMode: 'shadow',
  toggleEnforcement: async () => {
    try {
      const res = await fetch(`${API_BASE}/api/enforcement/mode`, { method: 'POST' })
      const data = await res.json()
      set({ enforcementMode: data.mode })
      // Refresh immunity score after toggling
      get().fetchImmunityScore()
    } catch (err) {
      console.error('Failed to toggle enforcement:', err)
    }
  },

  // ── Immunity Score ──
  immunityScore: 85,
  immunityData: null,
  fetchImmunityScore: async () => {
    try {
      const res = await fetch(`${API_BASE}/api/immunity-score`)
      const data = await res.json()
      set({
        immunityScore: data.score,
        immunityData: data,
        enforcementMode: data.enforcement_mode,
      })
    } catch (err) {
      console.error('Failed to fetch immunity score:', err)
    }
  },

  // ── Events ──
  events: [],
  setEvents: (events) => set({ events: events.map(normalizeEvent) }),
  addEvent: (event) => set((state) => ({
    events: [normalizeEvent(event), ...state.events.slice(0, 299)],
  })),

  // ── Metrics ──
  metrics: null,
  setMetrics: (metrics) => set({ metrics }),
  updateMetricsFromEvent: (event) => set((state) => {
    if (!state.metrics) return {}
    const newTotal = state.metrics.events_total + 1
    const byType = { ...state.metrics.events_by_type }
    const evtType = event.detection?.event_type || event.event_type || 'unknown'
    byType[evtType] = (byType[evtType] || 0) + 1
    
    const severity = { ...state.metrics.severity_breakdown }
    const evtSev = event.severity || (event.triage?.grade === 'TP' ? 'high' : 'medium')
    severity[evtSev] = (severity[evtSev] || 0) + 1
    
    return {
      metrics: {
        ...state.metrics,
        events_total: newTotal,
        events_by_type: byType,
        severity_breakdown: severity,
        last_event_timestamp: event.timestamp || new Date().toISOString(),
        active_alerts: (evtSev === 'critical' || evtSev === 'high')
          ? state.metrics.active_alerts + 1 : state.metrics.active_alerts,
      },
    }
  }),

  // ── Triage Stats ──
  triageStats: null,
  setTriageStats: (stats) => set({ triageStats: stats }),
  updateTriageFromEvent: (event) => set((state) => {
    if (!state.triageStats) return {}
    const grade = event.triage?.grade || 'UNKNOWN'
    const breakdown = { ...state.triageStats.breakdown }
    breakdown[grade] = (breakdown[grade] || 0) + 1
    const total = Object.values(breakdown).reduce((a, b) => a + b, 0)
    const percentages = {}
    for (const [k, v] of Object.entries(breakdown)) {
      percentages[k] = Math.round(v / total * 1000) / 10
    }
    return {
      triageStats: {
        ...state.triageStats,
        breakdown,
        percentages,
        total_triaged: total,
      },
    }
  }),

  // ── Timeline ──
  timeline: [],
  setTimeline: (timeline) => set({ timeline }),

  // ── Cluster ──
  cluster: null,
  setCluster: (cluster) => set({ cluster }),

  // ── Policies ──
  policies: [],
  setPolicies: (policies) => set({ policies }),

  // ── Health ──
  health: null,
  setHealth: (health) => set({ health }),

  // ── WebSocket ──
  wsConnected: false,
  setWsConnected: (connected) => set({ wsConnected: connected }),

  // ── New Event IDs (for flash animation) ──
  newEventIds: new Set(),
  addNewEventId: (id) => set((state) => {
    const next = new Set(state.newEventIds)
    next.add(id)
    return { newEventIds: next }
  }),
  removeNewEventId: (id) => set((state) => {
    const next = new Set(state.newEventIds)
    next.delete(id)
    return { newEventIds: next }
  }),

  // ── Forensics Panel ──
  selectedEvent: null,
  forensicsData: null,
  forensicsLoading: false,
  setSelectedEvent: (event) => set({ selectedEvent: event }),
  openForensics: async (event) => {
    set({ selectedEvent: event, forensicsLoading: true, forensicsData: null, currentPage: 'forensics' })
    try {
      // Direct assignment since real Sentinel events contain all forensic data natively
      setTimeout(() => {
        set({
          forensicsData: {
            reasoning: event.reasoning?.guide_explanation || event.reasoning?.summary || 'AI reasoning unavailable.',
            remediation: {
              summary: event.remediation?.summary || '',
              insecure_yaml: event.remediation?.insecure_yaml || null,
              secure_yaml: event.remediation?.yaml_fix || event.remediation?.secure_yaml || '# No fix generated'
            },
            mitre_tactics: event.triage?.mitre_tactics || event.threat_intel?.mitre_techniques || [],
            mitre_technique: event.triage?.mitre_technique || (event.threat_intel?.mitre_techniques?.[0]) || null,
            shap_values: event.reasoning?.shap_values || []
          },
          forensicsLoading: false
        })
      }, 500) // slight delay to feel like processing
    } catch (err) {
      console.error('Failed to load forensics:', err)
      set({ forensicsLoading: false })
    }
  },
  closeForensics: () => set({ selectedEvent: null, forensicsData: null, currentPage: 'ledger' }),

  // ── Neutralize ──
  neutralizeEvent: async (eventId) => {
    try {
      const res = await fetch(`${API_BASE}/api/neutralize/${eventId}`, { method: 'POST' })
      const data = await res.json()
      set({ immunityScore: data.immunity_score })
      // Refresh immunity score
      get().fetchImmunityScore()
      return data
    } catch (err) {
      console.error('Failed to neutralize:', err)
      return null
    }
  },

  // ── Bulk Data Fetch ──
  fetchAllData: async () => {
    try {
      const [metricsRes, eventsRes, clusterRes, policiesRes, triageRes, timelineRes, healthRes] = await Promise.all([
        fetch(`${API_BASE}/api/metrics`).then(r => r.json()),
        fetch(`${API_BASE}/api/events?limit=100`).then(r => r.json()),
        fetch(`${API_BASE}/api/cluster`).then(r => r.json()),
        fetch(`${API_BASE}/api/policies`).then(r => r.json()),
        fetch(`${API_BASE}/api/triage/stats`).then(r => r.json()),
        fetch(`${API_BASE}/api/events/timeline`).then(r => r.json()),
        fetch(`${API_BASE}/api/health`).then(r => r.json()),
      ])
      set({
        metrics: metricsRes,
        events: eventsRes.events || [],
        cluster: clusterRes,
        policies: policiesRes.policies || [],
        triageStats: triageRes,
        timeline: timelineRes.buckets || [],
        health: healthRes,
      })
      // Also fetch immunity score
      get().fetchImmunityScore()
    } catch (err) {
      console.error('Failed to fetch data:', err)
    }
  },
}))

// Helper to normalize the real Sentinel event payload into what the UI expects
function normalizeEvent(event) {
  return {
    ...event,
    severity: event.severity || event.incident_report?.severity || (event.triage?.grade === 'TP' ? 'high' : 'medium'),
    description: event.description || event.reasoning?.summary || event.detection?.explanation || event.event_type || 'Unknown event',
    processing_time: {
      ebpf_intercept_ms: event.processing_time?.ebpf_intercept_ms || 0.1,
      guide_triage_ms: event.processing_time?.guide_triage_ms || (event.processing_time_ms ? Math.round(event.processing_time_ms * 0.1) : 0),
      ai_reasoning_ms: event.processing_time?.ai_reasoning_ms || (event.processing_time_ms ? Math.round(event.processing_time_ms * 0.9) : 0),
      total_ms: event.processing_time?.total_ms || event.processing_time_ms || 0
    },
    telemetry: event.telemetry || event.detection || {},
    explanation: event.explanation || event.triage || event.detection?.explanation || {}
  }
}
