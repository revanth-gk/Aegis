# RemediationAgent Quick Start Guide

Get the RemediationAgent up and running in 5 minutes.

## Prerequisites

- Kubernetes cluster (v1.24+)
- kubectl configured
- Redis instance
- Python 3.11+

## Step 1: Install Dependencies

```bash
cd cspm-ebpf
pip install -r requirements.txt
```

## Step 2: Configure Environment

```bash
# Copy example configuration
cp .env.remediation.example .env

# Edit configuration
nano .env
```

Minimal configuration for testing:
```bash
REMEDIATION_AUTONOMY_MODE=tiered
REMEDIATION_DRY_RUN=true  # IMPORTANT: Start with dry run!
REDIS_HOST=localhost
REDIS_PORT=6379
```

## Step 3: Set Up Kubernetes RBAC

```bash
# Create namespace
kubectl create namespace sentinel-core

# Apply ServiceAccount and RBAC
kubectl apply -f remediation/k8s-serviceaccount.yaml

# Verify
kubectl get serviceaccount remediation-agent -n sentinel-core
kubectl get role remediation-agent -n production
```

## Step 4: Start Redis (if not already running)

```bash
# Using Docker
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Or using Kubernetes
kubectl apply -f remediation/k8s-deployment.yaml
```

## Step 5: Test the Agent

### Option A: Python REPL Test

```python
from remediation import RemediationAgent, RemediationConfig

# Initialize with dry run
config = RemediationConfig(
    autonomy_mode="tiered",
    dry_run=True,  # Safe testing mode
    sigkill_threshold=0.92,
    yaml_threshold=0.95
)

agent = RemediationAgent(config)

# Test event (simulated TP event)
test_state = {
    "event_id": "test-001",
    "guide_grade": "TP",
    "guide_score": 0.95,
    "mitre_techniques": [
        {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "url": "https://attack.mitre.org/techniques/T1059/"
        }
    ],
    "raw_event": {
        "pod_name": "test-pod",
        "namespace": "default",
        "pid": 1234
    },
    "yaml_fix": """apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  securityContext:
    runAsNonRoot: true
"""
}

# Process event
result = agent.process_event(test_state)

# Check result
print(f"Status: {result['remediation_status']}")
print(f"Action: {result['remediation_action']}")
print(f"Timestamp: {result['remediation_timestamp']}")
```

Expected output:
```
Status: dry_run
Action: SIGKILL
Timestamp: 2026-03-08T...
```

### Option B: Integration Test

```bash
# Run the orchestrator with a test event
python orchestrator.py
```

## Step 6: Check Health

```bash
# If running locally
curl http://localhost:8002/api/remediation/health

# If running in Kubernetes
kubectl port-forward -n sentinel-core svc/sentinel-core 8000:8000
curl http://localhost:8002/api/remediation/health
```

Expected response:
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

## Step 7: View Configuration

```bash
curl http://localhost:8002/api/remediation/config
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

## Step 8: Monitor Metrics

```bash
# View Prometheus metrics
curl http://localhost:8000/metrics | grep remediation
```

Expected metrics:
```
remediation_actions_total{action_type="SIGKILL",status="dry_run"} 1.0
remediation_processing_duration_seconds_bucket{le="1.0"} 1.0
```

## Step 9: Check Audit Trail

```python
from remediation import AuditLogger

logger = AuditLogger()
records = logger.query_by_event_id("test-001")

for record in records:
    print(f"Action: {record['action_type']}")
    print(f"Status: {record['execution_status']}")
    print(f"Confidence: {record['confidence_score']}")
```

## Step 10: Enable Production Mode (When Ready)

⚠️ **WARNING**: Only enable after thorough testing in dry_run mode!

```bash
# Update configuration
export REMEDIATION_DRY_RUN=false

# Or via API
curl -X POST http://localhost:8002/api/remediation/config \
  -H "Content-Type: application/json" \
  -d '{"dry_run": false}'
```

## Common Issues

### Issue: "Circuit breaker open"
**Solution**: Check Kubernetes API connectivity
```bash
kubectl version
kubectl get pods -n production
```

### Issue: "Redis connection failed"
**Solution**: Verify Redis is running
```bash
redis-cli ping
# Should return: PONG
```

### Issue: "kubectl not found"
**Solution**: Install kubectl in container
```dockerfile
RUN apt-get update && apt-get install -y kubectl
```

### Issue: "Permission denied" for kubectl exec
**Solution**: Verify RBAC permissions
```bash
kubectl auth can-i create pods/exec -n production --as=system:serviceaccount:sentinel-core:remediation-agent
# Should return: yes
```

## Next Steps

1. ✅ Test with dry_run=true
2. ✅ Verify health checks pass
3. ✅ Review audit trail
4. ✅ Monitor metrics
5. ⏭️ Test with real security events
6. ⏭️ Gradually enable production mode
7. ⏭️ Set up alerting for failures
8. ⏭️ Configure backup and recovery

## Production Checklist

Before enabling production mode:

- [ ] Tested in dry_run mode for at least 1 week
- [ ] Reviewed all audit trail entries
- [ ] Verified RBAC permissions are minimal
- [ ] Set up Prometheus alerting
- [ ] Configured backup for Redis audit trail
- [ ] Documented incident response procedures
- [ ] Trained team on human approval workflow
- [ ] Established rollback procedures
- [ ] Set up monitoring dashboards
- [ ] Conducted security review

## Support

For issues or questions:
1. Check the [README.md](README.md) for detailed documentation
2. Review the [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)
3. Check logs: `kubectl logs -n sentinel-core -l app=sentinel-core`
4. Review audit trail in Redis
5. Check Prometheus metrics for anomalies

## Example Scenarios

### Scenario 1: Test SIGKILL Action
```python
state = {
    "event_id": "sigkill-test",
    "guide_grade": "TP",
    "guide_score": 0.93,  # Above SIGKILL threshold
    "mitre_techniques": [{"tactic": "Execution"}],
    "raw_event": {"pod_name": "malicious-pod", "namespace": "default", "pid": 5678}
}
result = agent.process_event(state)
# Expected: action=SIGKILL, status=dry_run
```

### Scenario 2: Test YAML Action
```python
state = {
    "event_id": "yaml-test",
    "guide_grade": "TP",
    "guide_score": 0.96,  # Above YAML threshold
    "mitre_techniques": [{"tactic": "Persistence"}],
    "yaml_fix": "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n..."
}
result = agent.process_event(state)
# Expected: action=YAML, status=dry_run
```

### Scenario 3: Test Confidence Rejection
```python
state = {
    "event_id": "reject-test",
    "guide_grade": "TP",
    "guide_score": 0.85,  # Below both thresholds
    "mitre_techniques": [{"tactic": "Execution"}]
}
result = agent.process_event(state)
# Expected: status=skipped, error contains "confidence_too_low"
```

## Success Criteria

You'll know the agent is working correctly when:

1. ✅ Health check returns 200 OK
2. ✅ Dry run actions are logged but not executed
3. ✅ Audit trail records all decisions
4. ✅ Metrics show processing duration < 5 seconds
5. ✅ Configuration updates work via API
6. ✅ Circuit breaker opens on repeated failures
7. ✅ Idempotency prevents duplicate execution

Happy remediating! 🛡️
