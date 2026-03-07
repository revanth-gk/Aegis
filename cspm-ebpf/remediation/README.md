# RemediationAgent - Autonomous Security Response

The RemediationAgent is Node D in the Sentinel-Core LangGraph pipeline, providing autonomous execution of security remediation actions for ML-triaged events.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RemediationAgent (Node D)                 │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Decision   │  │   Routing    │  │  Execution   │      │
│  │     Gate     │  │    Engine    │  │    Engine    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐                         │
│  │    Audit     │  │    Config    │                         │
│  │    Logger    │  │   Manager    │                         │
│  └──────────────┘  └──────────────┘                         │
│                                                               │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
   Kubernetes API        Redis Store         Prometheus
```

## Components

### Decision Gate
Evaluates remediation actions against confidence thresholds:
- SIGKILL (process termination): >= 0.92 confidence
- YAML (resource patch): >= 0.95 confidence

### Routing Engine
Routes actions based on MITRE ATT&CK tactics:
- **SIGKILL**: Execution, Privilege Escalation, Credential Access
- **YAML**: Persistence, Defense Evasion
- **Default**: YAML (safer option)

### Execution Engine
Executes kubectl commands with:
- Hybrid authentication (in-cluster ServiceAccount or external kubeconfig)
- Retry logic with exponential backoff (3 attempts)
- Circuit breaker (opens after 10 failures, 5-minute cooldown)

### Audit Logger
Records all remediation decisions to Redis with:
- 90-day TTL
- Batch writing (10 records or 1-second intervals)
- Idempotency checking

### Config Manager
Manages runtime configuration with:
- Environment variable loading
- REST API for runtime updates
- Validation and rollback on errors

## Configuration

### Environment Variables

```bash
# Autonomy mode: "autonomous", "tiered", "human-in-loop"
REMEDIATION_AUTONOMY_MODE=tiered

# Dry run mode (default: true for safety)
REMEDIATION_DRY_RUN=true

# Confidence thresholds (0.0-1.0)
REMEDIATION_SIGKILL_THRESHOLD=0.92
REMEDIATION_YAML_THRESHOLD=0.95

# Kubernetes authentication
KUBECONFIG_PATH=/path/to/kubeconfig  # Optional, uses in-cluster auth if not set

# Redis configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=  # Optional
```

### Autonomy Modes

1. **Autonomous**: Execute all approved actions without human confirmation
2. **Tiered** (default): Execute YAML without confirmation, require confirmation for SIGKILL
3. **Human-in-loop**: Require human confirmation for all actions

## API Endpoints

### Get Configuration
```bash
GET /api/remediation/config
```

Response:
```json
{
  "autonomy_mode": "tiered",
  "dry_run": true,
  "sigkill_threshold": 0.92,
  "yaml_threshold": 0.95,
  "kubeconfig_path": null
}
```

### Update Configuration
```bash
POST /api/remediation/config
Content-Type: application/json

{
  "autonomy_mode": "autonomous",
  "dry_run": false,
  "sigkill_threshold": 0.95,
  "yaml_threshold": 0.97
}
```

### Health Check
```bash
GET /api/remediation/health
```

Response (200 OK):
```json
{
  "status": "healthy",
  "dependencies": {
    "kubernetes": {
      "healthy": true,
      "message": "Kubernetes API reachable"
    },
    "redis": {
      "healthy": true,
      "message": "Redis reachable"
    }
  }
}
```

## Kubernetes RBAC

### ServiceAccount (In-Cluster)

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: remediation-agent
  namespace: sentinel-core
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: remediation-agent
  namespace: production  # Monitored namespace
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["create", "update", "patch"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: remediation-agent
  namespace: production
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: remediation-agent
subjects:
- kind: ServiceAccount
  name: remediation-agent
  namespace: sentinel-core
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sentinel-core
  namespace: sentinel-core
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sentinel-core
  template:
    metadata:
      labels:
        app: sentinel-core
    spec:
      serviceAccountName: remediation-agent
      containers:
      - name: sentinel-core
        image: sentinel-core:latest
        env:
        - name: REMEDIATION_AUTONOMY_MODE
          value: "tiered"
        - name: REMEDIATION_DRY_RUN
          value: "false"
        - name: REDIS_HOST
          value: "redis-service"
        - name: REDIS_PORT
          value: "6379"
```

## Prometheus Metrics

The agent exposes the following metrics:

- `remediation_actions_total{action_type, status}` - Total actions attempted
- `remediation_actions_succeeded{action_type}` - Successful actions
- `remediation_actions_failed{action_type, reason}` - Failed actions
- `remediation_processing_duration_seconds` - Processing time histogram

## Security Considerations

### Least Privilege
- ServiceAccount has minimal required permissions
- No cluster-admin or namespace-admin roles
- No delete permissions
- Limited to specific monitored namespaces

### Safe Defaults
- Dry run mode enabled by default
- Conservative confidence thresholds
- Tiered autonomy mode (human approval for SIGKILL)
- Circuit breaker prevents runaway failures

### Audit Trail
- All actions logged to Redis with 90-day retention
- Includes event_id, action_type, confidence, status, errors
- Supports compliance and forensic analysis

## Testing

### Dry Run Mode
Test remediation logic without affecting production:

```bash
export REMEDIATION_DRY_RUN=true
python -m remediation.agent
```

### Manual Testing
```python
from remediation import RemediationAgent, RemediationConfig

config = RemediationConfig(
    autonomy_mode="autonomous",
    dry_run=True,
    sigkill_threshold=0.92,
    yaml_threshold=0.95
)

agent = RemediationAgent(config)

# Test event
state = {
    "event_id": "test-001",
    "guide_grade": "TP",
    "guide_score": 0.95,
    "mitre_techniques": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", 
         "tactic": "Execution", "url": "..."}
    ],
    "raw_event": {
        "pod_name": "test-pod",
        "namespace": "default",
        "pid": 1234
    },
    "yaml_fix": "apiVersion: v1\nkind: Pod\n..."
}

result = agent.process_event(state)
print(result["remediation_status"])
```

## Troubleshooting

### Circuit Breaker Open
If you see "Circuit breaker open" errors:
1. Check Kubernetes API connectivity: `kubectl version`
2. Verify ServiceAccount permissions
3. Wait for 5-minute cooldown period
4. Check logs for underlying failure cause

### Redis Connection Failed
1. Verify Redis is running: `redis-cli ping`
2. Check REDIS_HOST and REDIS_PORT environment variables
3. Verify network connectivity
4. Check Redis authentication if password is set

### SIGKILL Failed
1. Verify pod exists: `kubectl get pod <pod> -n <namespace>`
2. Check ServiceAccount has pods/exec permission
3. Verify process ID is correct
4. Check pod logs for process status

### YAML Apply Failed
1. Validate YAML syntax
2. Check ServiceAccount has required permissions for resource type
3. Verify namespace exists
4. Check for resource conflicts (e.g., existing NetworkPolicy)

## Development

### Adding New Action Types
1. Update `RoutingEngine.SIGKILL_TACTICS` or `YAML_TACTICS`
2. Add confidence threshold to `RemediationConfig`
3. Update `DecisionGate.evaluate_action()`
4. Add execution logic to `ExecutionEngine`

### Custom Tactic Mappings
Modify `RoutingEngine` to customize MITRE tactic routing:

```python
class CustomRoutingEngine(RoutingEngine):
    SIGKILL_TACTICS = {
        "Execution",
        "Privilege Escalation",
        "Credential Access",
        "Impact"  # Added custom tactic
    }
```

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [LangGraph Documentation](https://langchain-ai.github.io/langgraph/)
- [Prometheus Metrics](https://prometheus.io/docs/concepts/metric_types/)
