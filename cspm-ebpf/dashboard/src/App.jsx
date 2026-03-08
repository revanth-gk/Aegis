import { useEffect, useRef, useCallback } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { TooltipProvider } from '@/components/ui/tooltip'
import { useStore } from './store'
import Sidebar from './components/Sidebar'
import Header from './components/Header'
import CommandCenter from './components/CommandCenter'
import IncidentLedger from './components/IncidentLedger'
import ForensicsPanel from './components/ForensicsPanel'
import SyscallTicker from './components/SyscallTicker'

const WS_URL = `ws://${window.location.hostname}:8080/api/ws/events`

const pageVariants = {
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0, transition: { duration: 0.3, ease: 'easeOut' } },
  exit: { opacity: 0, y: -12, transition: { duration: 0.2, ease: 'easeIn' } },
}

function App() {
  const {
    currentPage,
    fetchAllData,
    addEvent,
    updateMetricsFromEvent,
    updateTriageFromEvent,
    addNewEventId,
    removeNewEventId,
    setWsConnected,
    fetchImmunityScore,
  } = useStore()

  const wsRef = useRef(null)
  const reconnectTimeout = useRef(null)

  const connectWs = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) return

    const ws = new WebSocket(WS_URL)
    wsRef.current = ws

    ws.onopen = () => {
      setWsConnected(true)
    }

      ws.onmessage = (msg) => {
      try {
        const event = JSON.parse(msg.data)
        addEvent(event)
        updateMetricsFromEvent(event)
        updateTriageFromEvent(event)

        addNewEventId(event.event_id)
        setTimeout(() => removeNewEventId(event.event_id), 2000)

        // Periodically refresh immunity score
        if (Math.random() < 0.3) fetchImmunityScore()

      } catch (e) {
        console.error('WS parse error:', e)
      }
    }

    ws.onclose = () => {
      setWsConnected(false)
      console.log('[WS] Disconnected. Reconnecting in 3s...')
      reconnectTimeout.current = setTimeout(connectWs, 3000)
    }

    ws.onerror = () => ws.close()
  }, [])

  useEffect(() => {
    fetchAllData()
    connectWs()

    const interval = setInterval(fetchAllData, 15000)

    return () => {
      clearInterval(interval)
      if (wsRef.current) wsRef.current.close()
      if (reconnectTimeout.current) clearTimeout(reconnectTimeout.current)
    }
  }, [fetchAllData, connectWs])

  const renderPage = () => {
    switch (currentPage) {
      case 'command':
        return (
          <motion.div key="command" variants={pageVariants} initial="initial" animate="animate" exit="exit" className="flex-1 flex flex-col overflow-hidden">
            <CommandCenter />
          </motion.div>
        )
      case 'ledger':
        return (
          <motion.div key="ledger" variants={pageVariants} initial="initial" animate="animate" exit="exit" className="flex-1 flex flex-col overflow-hidden">
            <IncidentLedger />
          </motion.div>
        )
      case 'forensics':
        return (
          <motion.div key="forensics" variants={pageVariants} initial="initial" animate="animate" exit="exit" className="flex-1 flex flex-col overflow-hidden">
            <ForensicsPanel />
          </motion.div>
        )
      default:
        return (
          <motion.div key="command" variants={pageVariants} initial="initial" animate="animate" exit="exit" className="flex-1 flex flex-col overflow-hidden">
            <CommandCenter />
          </motion.div>
        )
    }
  }

  return (
    <TooltipProvider>
      <div className="flex h-screen w-full bg-background text-foreground overflow-hidden font-sans">
        <Sidebar />
        <div className="flex-1 flex flex-col overflow-hidden">
          <Header />
          <AnimatePresence mode="wait">
            {renderPage()}
          </AnimatePresence>
          <SyscallTicker />
        </div>
      </div>
    </TooltipProvider>
  )
}

export default App
