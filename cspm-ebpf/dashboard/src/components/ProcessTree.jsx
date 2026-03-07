export default function ProcessTree({ events }) {
  // Build a process tree from the most recent events
  const processes = []
  const seen = new Set()

  for (const event of (events || []).slice(0, 30)) {
    const tel = event.telemetry
    if (!tel) continue

    const key = `${tel.binary}-${tel.pid}`
    if (seen.has(key)) continue
    seen.add(key)

    processes.push({
      binary: tel.binary,
      pid: tel.pid,
      user: tel.user,
      parentBinary: tel.parent_binary,
      parentPid: tel.parent_pid,
      pod: tel.pod,
    })

    if (processes.length >= 10) break
  }

  if (processes.length === 0) {
    return <div style={{ color: 'var(--text-dim)', textAlign: 'center', padding: '20px' }}>No process data</div>
  }

  return (
    <div className="process-tree">
      {processes.map((proc, idx) => (
        <div className="process-node" key={idx}>
          <span className="process-indent">
            {proc.parentBinary ? '├─' : '──'}
          </span>
          {proc.parentBinary && (
            <>
              <span className="process-binary" style={{ opacity: 0.5 }}>{shortBinary(proc.parentBinary)}</span>
              <span className="process-pid" style={{ opacity: 0.4 }}>({proc.parentPid})</span>
              <span style={{ color: 'var(--text-dim)' }}>→</span>
            </>
          )}
          <span className="process-binary">{shortBinary(proc.binary)}</span>
          <span className="process-pid">pid:{proc.pid}</span>
          <span className="process-user">{proc.user}</span>
        </div>
      ))}
    </div>
  )
}

function shortBinary(path) {
  if (!path) return '?'
  const parts = path.split('/')
  return parts[parts.length - 1]
}
