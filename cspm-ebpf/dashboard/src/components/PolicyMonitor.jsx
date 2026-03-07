export default function PolicyMonitor({ policies }) {
  if (!policies || policies.length === 0) {
    return <div style={{ color: 'var(--text-dim)', padding: '20px', textAlign: 'center' }}>No policies loaded</div>
  }

  return (
    <div className="policy-list">
      {policies.map(policy => (
        <div className="policy-item" key={policy.name}>
          <span className="policy-status"></span>
          <div>
            <div className="policy-name">{policy.name}</div>
            <div className="policy-desc">{policy.description}</div>
          </div>
          <div className="policy-targets">
            {policy.targets.slice(0, 2).map(t => (
              <span className="policy-target-chip" key={t}>
                {t.replace('__x64_sys_', '')}
              </span>
            ))}
            {policy.targets.length > 2 && (
              <span className="policy-target-chip">+{policy.targets.length - 2}</span>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}
