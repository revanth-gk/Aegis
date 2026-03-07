export default function ClusterTopology({ cluster }) {
  if (!cluster) return <div style={{ color: 'var(--text-dim)', padding: '20px', textAlign: 'center' }}>Loading cluster...</div>

  const podsByNode = {}
  for (const pod of cluster.pods || []) {
    if (!podsByNode[pod.node]) podsByNode[pod.node] = []
    podsByNode[pod.node].push(pod)
  }

  return (
    <div className="cluster-topology">
      {(cluster.nodes || []).map(node => (
        <div className="cluster-node" key={node.name}>
          <div className="node-header">
            <span className="node-name">
              <span style={{ color: 'var(--green)' }}>●</span>
              {node.name}
            </span>
            <span className="node-role">{node.role}</span>
          </div>
          <div className="node-pods">
            {(podsByNode[node.name] || []).map(pod => (
              <span
                key={pod.name}
                className={`pod-chip ${pod.role === 'attacker-simulation' ? 'highlight' : ''}`}
                title={`${pod.name} (${pod.namespace}) — ${pod.status}`}
              >
                {pod.name.length > 24 ? pod.name.slice(0, 22) + '…' : pod.name}
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
