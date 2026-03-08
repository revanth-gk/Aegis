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
  setEvents: (events) => set({ events }),
  addEvent: (event) => set((state) => ({
    events: [event, ...state.events.slice(0, 299)],
  })),

  // ── Metrics ──
  metrics: null,
  setMetrics: (metrics) => set({ metrics }),
  updateMetricsFromEvent: (event) => set((state) => {
    if (!state.metrics) return {}
    const newTotal = state.metrics.events_total + 1
    const byType = { ...state.metrics.events_by_type }
    byType[event.event_type] = (byType[event.event_type] || 0) + 1
    const severity = { ...state.metrics.severity_breakdown }
    if (event.severity) severity[event.severity] = (severity[event.severity] || 0) + 1
    return {
      metrics: {
        ...state.metrics,
        events_total: newTotal,
        events_by_type: byType,
        severity_breakdown: severity,
        last_event_timestamp: event.timestamp,
        active_alerts: (event.severity === 'critical' || event.severity === 'high')
          ? state.metrics.active_alerts + 1 : state.metrics.active_alerts,
      },
    }
  }),

  // ── Triage Stats ──
  triageStats: null,
  setTriageStats: (stats) => set({ triageStats: stats }),
  updateTriageFromEvent: (event) => set((state) => {
    if (!state.triageStats || !event.triage?.status) return {}
    const breakdown = { ...state.triageStats.breakdown }
    breakdown[event.triage.status] = (breakdown[event.triage.status] || 0) + 1
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
      const res = await fetch(`${API_BASE}/api/explain/${event.event_id}`)
      const data = await res.json()
      set({ forensicsData: data, forensicsLoading: false })
    } catch (err) {
      console.error('Failed to load forensics:', err)
      set({ forensicsLoading: false })
    }
  },
  closeForensics: () => set({ selectedEvent: null, forensicsData: null, currentPage: 'ledger' }),

  // ── Neutralize ──
  neutralizeLoading: false,
  neutralizeResult: null,
  neutralizeEvent: async (eventId) => {
    set({ neutralizeLoading: true, neutralizeResult: null })
    try {
      const res = await fetch(`${API_BASE}/api/remediation/execute/${eventId}`, { method: 'POST' })
      let data;
      try {
        data = await res.json()
      } catch (e) {
        data = { error: res.statusText }
      }
      if (res.ok && !data.error) {
        // Mark this event as neutralized in the local events array
        set((state) => ({
          events: state.events.map(e =>
            e.event_id === eventId ? { ...e, neutralized: true } : e
          ),
          immunityScore: data.immunity_score ?? state.immunityScore,
        }))
      }
      set({ neutralizeLoading: false, neutralizeResult: data })
      // Refresh all data to get updated metrics/counts from backend
      get().fetchAllData()
      return data
    } catch (err) {
      console.error('Failed to neutralize via remediation agent:', err)
      const errorResult = { error: err.message }
      set({ neutralizeLoading: false, neutralizeResult: errorResult })
      return errorResult
    }
  },
  clearNeutralizeResult: () => set({ neutralizeResult: null, neutralizeLoading: false }),

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
