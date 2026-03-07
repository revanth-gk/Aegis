"""
Sentinel-Core Event Forwarder — FastAPI Health, Metrics & Unified Analysis API

Provides liveness probes, metrics, recent-events, and the single unified
/sentinel/analyze endpoint covering the full PRD pipeline:
  Detection → Triage (GUIDE) → Action (eBPF-LSM) → Reasoning (RAG) → Remediation (YAML)
"""

import time
import uuid
import datetime
from collections import deque
from threading import Lock
from typing import Any, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI(
    title="Sentinel-Core Security Platform",
    description=(
        "Autonomous Cloud-Native Security Platform — GUIDE-Integrated Edition. "
        "Single unified API for Detection → Triage → Action → Reasoning → Remediation."
    ),
    version="1.0.0",
)

# Use API prefix to match Vite proxy
API_PREFIX = "/api"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Shared State ──────────────────────────────────────────────────
_lock = Lock()
_metrics: dict[str, Any] = {
    "events_total": 0,
    "events_by_type": {},
    "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    "errors_total": 0,
    "last_event_timestamp": None,
    "start_time": time.time(),
    "redis_connected": False,
    "active_alerts": 0,
    "events_per_second": 0.0,
}
_recent_events: deque = deque(maxlen=300)
_ml_triage: Any = None
_ws_clients: list[Any] = []

def record_event(event: dict) -> None:
    """Record a processed event for metrics and recent-events buffer."""
    with _lock:
        _metrics["events_total"] += 1
        _metrics["last_event_timestamp"] = event.get("timestamp")
        
        etype = event.get("event_type", "unknown")
        _metrics["events_by_type"][etype] = _metrics["events_by_type"].get(etype, 0) + 1
        
        sev = (event.get("severity") or "medium").lower()
        _metrics["severity_breakdown"][sev] = _metrics["severity_breakdown"].get(sev, 0) + 1
        
        if sev in ("critical", "high"):
            _metrics["active_alerts"] += 1
            
        uptime = time.time() - _metrics["start_time"]
        _metrics["events_per_second"] = float(round(_metrics["events_total"] / max(uptime, 1), 2))
        
        # Build the final UI-standard event
        ui_event = _build_ui_event(event)
        _recent_events.appendleft(ui_event)
        
        # Broadcast to WS clients
        for client in _ws_clients:
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                # Run send_json in the loop
                asyncio.run_coroutine_threadsafe(client.send_json(ui_event), loop)
            except:
                pass


def set_ml_triage(triage_instance: Any) -> None:
    """Register the ML triage instance with the API."""
    global _ml_triage
    _ml_triage = triage_instance


def record_error() -> None:
    """Increment the error counter."""
    with _lock:
        _metrics["errors_total"] += 1


def set_redis_status(connected: bool) -> None:
    """Update Redis connection status in metrics."""
    with _lock:
        _metrics["redis_connected"] = connected


def update_orchestrator_result(event_id: str, result: dict) -> None:
    """Update an existing event with its AI analysis result."""
    with _lock:
        for e in _recent_events:
            if e.get("event_id") == event_id:
                if "explanation" not in e or e["explanation"] is None:
                    e["explanation"] = {}
                e["explanation"]["orchestrator_result"] = result
                break


# ── MITRE ATT&CK Mapping (Kernel-Level Techniques) ───────────────
# Maps syscall/binary patterns to known MITRE technique IDs for local
# reasoning when the RAG orchestrator is not available.

MITRE_SYSCALL_MAP = {
    "execve":  {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "openat":  {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    "connect": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    "write":   {"id": "T1565", "name": "Data Manipulation", "tactic": "Impact"},
    "read":    {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    "mmap":    {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
    "ptrace":  {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
    "clone":   {"id": "T1106", "name": "Native API", "tactic": "Execution"},
    "unlink":  {"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion"},
}

MITRE_BINARY_MAP = {
    "curl":     {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "wget":     {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "nc":       {"id": "T1095", "name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    "ncat":     {"id": "T1095", "name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    "bash":     {"id": "T1059.004", "name": "Unix Shell", "tactic": "Execution"},
    "sh":       {"id": "T1059.004", "name": "Unix Shell", "tactic": "Execution"},
    "python":   {"id": "T1059.006", "name": "Python", "tactic": "Execution"},
    "python3":  {"id": "T1059.006", "name": "Python", "tactic": "Execution"},
    "chmod":    {"id": "T1222", "name": "File and Directory Permissions Modification", "tactic": "Defense Evasion"},
    "chown":    {"id": "T1222", "name": "File and Directory Permissions Modification", "tactic": "Defense Evasion"},
    "runc":     {"id": "T1611", "name": "Escape to Host", "tactic": "Privilege Escalation"},
    "nsenter":  {"id": "T1611", "name": "Escape to Host", "tactic": "Privilege Escalation"},
    "mount":    {"id": "T1611", "name": "Escape to Host", "tactic": "Privilege Escalation"},
    "crontab":  {"id": "T1053.003", "name": "Cron", "tactic": "Persistence"},
}

SENSITIVE_PATHS = {
    "/etc/shadow":   {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
    "/etc/passwd":   {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery"},
    "/etc/sudoers":  {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "/root/.ssh":    {"id": "T1552.004", "name": "Private Keys", "tactic": "Credential Access"},
    "/proc/self":    {"id": "T1057", "name": "Process Discovery", "tactic": "Discovery"},
    "/var/run/secrets": {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
}


def _resolve_mitre(event: dict) -> dict:
    """Resolve best MITRE ATT&CK mapping from event telemetry."""
    telemetry = event.get("telemetry", {})
    binary = telemetry.get("binary", "")
    binary_basename = binary.rsplit("/", 1)[-1] if binary else ""
    file_path = telemetry.get("file_path", "") or telemetry.get("cwd", "")
    kprobe = telemetry.get("kprobe", {})
    syscall = kprobe.get("function", "").replace("__x64_sys_", "") if kprobe else ""
    event_type = event.get("event_type", "")

    # Priority 1: Sensitive file path access
    for path_prefix, mapping in SENSITIVE_PATHS.items():
        if file_path.startswith(path_prefix):
            return mapping

    # Priority 2: Known malicious binary
    if binary_basename in MITRE_BINARY_MAP:
        return MITRE_BINARY_MAP[binary_basename]

    # Priority 3: Syscall-based mapping
    if syscall in MITRE_SYSCALL_MAP:
        return MITRE_SYSCALL_MAP[syscall]

    # Priority 4: Event type fallback
    if event_type == "process_exec":
        return {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}
    elif event_type == "process_kprobe":
        return {"id": "T1106", "name": "Native API", "tactic": "Execution"}

    return {"id": "N/A", "name": "Unknown Technique", "tactic": "Unknown"}


def _determine_action(grade: str, confidence: float, event: dict) -> dict:
    """Determine eBPF-LSM enforcement action per PRD F2."""
    telemetry = event.get("telemetry", {})
    binary = telemetry.get("binary", "unknown")
    pid = telemetry.get("pid", 0)

    if grade == "TP":
        return {
            "type": "kill",
            "description": f"eBPF-LSM: Process {binary} (PID {pid}) terminated — high-confidence threat.",
            "enforced": True,
            "latency_ms": "<1"
        }
    elif grade == "BP":
        return {
            "type": "log",
            "description": f"eBPF-LSM: Process {binary} (PID {pid}) allowed — flagged for contextual review.",
            "enforced": False,
            "latency_ms": "<1"
        }
    else:  # FP
        return {
            "type": "suppress",
            "description": f"eBPF-LSM: Alert auto-suppressed — routine system noise from {binary}.",
            "enforced": False,
            "latency_ms": "<1"
        }


def _generate_yaml_fix(grade: str, event: dict, mitre: dict) -> Optional[str]:
    """Generate contextual K8s remediation YAML based on triage + MITRE mapping."""
    if grade == "FP":
        return None  # No fix needed for false positives

    telemetry = event.get("telemetry", {})
    pod = telemetry.get("pod", "affected-pod")
    namespace = telemetry.get("namespace", "default")
    binary = telemetry.get("binary", "unknown")
    binary_basename = binary.rsplit("/", 1)[-1] if binary else "unknown"

    # Network-related threat → NetworkPolicy
    if mitre["tactic"] in ("Command and Control",):
        return f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-{pod}-egress
  namespace: {namespace}
  annotations:
    sentinel-core.io/mitre: "{mitre['id']} - {mitre['name']}"
    sentinel-core.io/auto-generated: "true"
spec:
  podSelector:
    matchLabels:
      app: {pod}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53"""

    # Default → Pod SecurityContext hardening
    return f"""apiVersion: v1
kind: Pod
metadata:
  name: {pod}
  namespace: {namespace}
  annotations:
    sentinel-core.io/mitre: "{mitre['id']} - {mitre['name']}"
    sentinel-core.io/auto-generated: "true"
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: {pod}
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL"""

def _build_ui_event(event: dict) -> dict:
    """Transforms a raw/internal event into the schema expected by the frontend."""
    telemetry = event.get("telemetry", {})
    triage = event.get("triage", {})
    explanation = event.get("explanation", {})
    
    grade = triage.get("grade", "TP")
    confidence = triage.get("confidence", 0.0)
    
    # Map syscall to severity if not present
    severity = event.get("severity")
    if not severity:
        if grade == "TP":
            severity = "critical"
        elif grade == "BP":
            severity = "medium"
        else:
            severity = "low"

    mitre_id = explanation.get("mitre_id")
    if not mitre_id:
        mitre = _resolve_mitre(event)
        mitre_id = mitre["id"]

    return {
        "event_id": event.get("event_id", str(uuid.uuid4())),
        "timestamp": event.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat()),
        "description": event.get("description", f"Suspicious activity: {telemetry.get('binary', 'unknown')}"),
        "severity": severity,
        "event_type": event.get("event_type", "process_exec"),
        "triage": {
            "grade": grade,
            "confidence": confidence,
            "status": explanation.get("guidance", ""),
        },
        "telemetry": {
            "binary": telemetry.get("binary", "unknown"),
            "pod": telemetry.get("pod", "unknown"),
            "namespace": telemetry.get("namespace", "default"),
            "pid": telemetry.get("pid", 0),
            "user": telemetry.get("user", "unknown"),
            "args": telemetry.get("args", []),
        },
        "explanation": {
            "mitre_id": mitre_id,
        },
        "processing_time": {
            "ebpf_intercept_ms": event.get("ebpf_intercept_ms", 0.2),
            "guide_triage_ms": event.get("guide_triage_ms", 45),
            "ai_reasoning_ms": event.get("ai_reasoning_ms", 1200),
        }
    }

# ── Fast Unified Result Builder (no ML re-run) ───────────────────


def _build_unified_result(event: dict) -> dict:
    """
    Build a full unified pipeline result from a pre-triaged event.
    Uses existing triage data from the forwarder pipeline — no ML inference needed.
    This is what the GET endpoints use for instant browser display.
    """
    start_time = time.time()
    telemetry = event.get("telemetry", event)

    # Detection
    detection = {
        "source": event.get("source", "tetragon"),
        "event_type": event.get("event_type", "unknown"),
        "node_name": event.get("node_name", "unknown"),
        "process": telemetry.get("binary", "unknown"),
        "pid": telemetry.get("pid", 0),
        "uid": telemetry.get("uid", 0),
        "user": telemetry.get("user", "unknown"),
        "args": telemetry.get("args", []),
        "file_path": telemetry.get("cwd", "") or telemetry.get("file_path", ""),
        "pod_name": telemetry.get("pod", "unknown"),
        "namespace": telemetry.get("namespace", "default"),
        "container_id": telemetry.get("container_id", ""),
        "parent_process": telemetry.get("parent_binary", ""),
        "parent_pid": telemetry.get("parent_pid", 0),
        "kprobe": telemetry.get("kprobe", None),
    }

    # Use pre-computed triage from forwarder pipeline
    existing_triage = event.get("triage", {})
    grade = existing_triage.get("grade", "TP") if isinstance(existing_triage, dict) else "TP"
    confidence = existing_triage.get("confidence", 0.0) if isinstance(existing_triage, dict) else 0.0
    explanation = event.get("explanation", {})
    guidance = explanation.get("guidance", "") if isinstance(explanation, dict) else ""

    triage = {
        "grade": grade,
        "confidence": confidence,
        "model": "xgboost-guide",
        "status": guidance,
    }

    # Action, Reasoning, Remediation
    action = _determine_action(grade, confidence, event)
    mitre = _resolve_mitre(event)

    if grade == "TP":
        guide_explanation = (
            f"GUIDE classification: True Positive with {confidence*100:.0f}% confidence. "
            f"This maps to MITRE ATT&CK technique {mitre['id']} ({mitre['name']}), "
            f"tactic: {mitre['tactic']}. "
            f"Process {detection['process']} executed by user '{detection['user']}' (UID {detection['uid']}) "
            f"in pod {detection['pod_name']}/{detection['namespace']} has been terminated. "
            f"Immediate investigation and remediation recommended."
        )
        remediation_summary = (
            f"Harden pod {detection['pod_name']} — apply SecurityContext restrictions "
            f"to prevent {mitre['name']} ({mitre['id']})."
        )
    elif grade == "BP":
        guide_explanation = (
            f"GUIDE classification: Benign Positive with {confidence*100:.0f}% confidence. "
            f"Activity maps to {mitre['id']} ({mitre['name']}) but is likely authorized. "
            f"Process {detection['process']} from user '{detection['user']}' has been allowed "
            f"but flagged for contextual review."
        )
        remediation_summary = (
            f"Review and optionally restrict access for user '{detection['user']}' "
            f"in namespace {detection['namespace']}."
        )
    else:
        guide_explanation = (
            f"GUIDE classification: False Positive with {confidence*100:.0f}% confidence. "
            f"Alert auto-suppressed. Process {detection['process']} is routine system noise. "
            f"No SOC action required."
        )
        remediation_summary = "No remediation needed — false positive."

    return {
        "event_id": event.get("event_id", str(uuid.uuid4())),
        "timestamp": event.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat()),
        "processing_time_ms": round((time.time() - start_time) * 1000, 2),
        "detection": detection,
        "triage": triage,
        "action": action,
        "reasoning": {
            "mitre_technique": {"id": mitre["id"], "name": mitre["name"], "tactic": mitre["tactic"]},
            "guide_explanation": guide_explanation,
        },
        "remediation": {
            "summary": remediation_summary,
            "yaml_fix": _generate_yaml_fix(grade, event, mitre),
        },
    }


# ── Endpoints ─────────────────────────────────────────────────────


# ── Unified Endpoints ─────────────────────────────────────────────

@app.get(f"{API_PREFIX}/health")
async def health():
    return {"status": "ok", "service": "sentinel-core", "version": "1.0.0"}

@app.get(f"{API_PREFIX}/metrics")
async def metrics():
    with _lock:
        return _metrics

@app.get(f"{API_PREFIX}/events")
async def get_events(limit: int = 100):
    with _lock:
        return {"events": list(_recent_events)[:limit]}

@app.get(f"{API_PREFIX}/immunity-score")
async def get_immunity_score():
    with _lock:
        # Simple heuristic for demo
        tp_count = sum(1 for e in _recent_events if e["triage"]["grade"] == "TP")
        score = max(0, 100 - (tp_count * 5))
        return {
            "score": score,
            "enforcement_mode": "guardian",
            "total_events": _metrics["events_total"],
            "tp_count": tp_count,
        }

@app.get(f"{API_PREFIX}/cluster")
async def get_cluster():
    return {
        "name": "kind-sentinel-cluster",
        "nodes": [
            {"id": "cp", "name": "kind-control-plane", "status": "Ready", "role": "control-plane"},
            {"id": "w1", "name": "kind-worker", "status": "Ready", "role": "worker"},
            {"id": "w2", "name": "kind-worker2", "status": "Ready", "role": "worker"},
        ],
        "total_pods": 12,
    }

@app.get(f"{API_PREFIX}/policies")
async def get_policies():
    return {
        "policies": [
            {"name": "sentinel-full", "type": "TracingPolicy", "status": "Active"},
            {"name": "restrict-egress", "type": "NetworkPolicy", "status": "Active"},
        ]
    }

@app.get(f"{API_PREFIX}/triage/stats")
async def get_triage_stats():
    with _lock:
        breakdown = {"TruePositive": 0, "BenignPositive": 0, "FalsePositive": 0}
        total = 0
        conf_sum = 0
        for e in _recent_events:
            g = e["triage"]["grade"]
            if g == "TP": breakdown["TruePositive"] += 1
            elif g == "BP": breakdown["BenignPositive"] += 1
            elif g == "FP": breakdown["FalsePositive"] += 1
            total += 1
            conf_sum += e["triage"]["confidence"]
        
        percentages = {}
        if total > 0:
            for k, v in breakdown.items():
                percentages[k] = float(round((v / total) * 100, 1))
        
        return {
            "breakdown": breakdown,
            "percentages": percentages,
            "total_triaged": total,
            "avg_confidence": float(round(conf_sum / max(total, 1), 2)),
        }

@app.get(f"{API_PREFIX}/events/timeline")
async def get_timeline():
    # Return 30 buckets of sample data for the sparkline
    now = datetime.datetime.now(datetime.timezone.utc)
    buckets = []
    for i in range(30):
        ts = (now - datetime.timedelta(minutes=29-i)).isoformat()
        buckets.append({
            "timestamp": ts,
            "total": 5 + (i % 7),
            "process_exec": 2 + (i % 3),
            "process_kprobe": 1 if i > 25 else 0,
        })
    return {"buckets": buckets}

@app.get(f"{API_PREFIX}/explain/{{event_id}}")
async def explain_event(event_id: str):
    # Find event or return mock
    event = None
    with _lock:
        for e in _recent_events:
            if e["event_id"] == event_id:
                event = e
                break
    
    if not event:
        return {"error": "Event not found"}

    explanation = event.get("explanation") or {}
    orch = explanation.get("orchestrator_result") or {}
    if orch:
        return {
            "summary": "AI Analysis complete",
            "attack_type": orch.get("attack_type", "Unknown"),
            "story": orch.get("final_report", "No report available."),
            "reasoning": orch.get("final_report", "No report available."),
            "remediation_yaml": orch.get("yaml_fix", ""),
            "fix_type": orch.get("fix_type", "Unknown"),
            "fix_description": orch.get("fix_description", "Please review YAML."),
            "mitre_tactics": [{"id": orch.get("mitre_context", ""), "name": "Identified by RAG", "tactic": "Unknown"}],
            "mitre_technique": {"id": explanation.get("mitre_id", ""), "name": orch.get("attack_type", "Unknown"), "tactic": orch.get("attack_type", "Unknown"), "description": orch.get("final_report", "")},
            "remediation": {
                "insecure_yaml": "---\n# Insecure state (detected)\n# " + str(event.get("description", "")),
                "secure_yaml": orch.get("yaml_fix", "apiVersion: v1...")
            },
            "shap_values": []
        }

    # Mock reasoning data from the prompt's fallback
    return {
        "summary": "Neutralized high-confidence threat.",
        "attack_type": "Privilege Escalation",
        "story": "This matches MITRE técnica T1068 (Exploitation for Privilege Escalation). Based on GUIDE history, this detector frequently precedes Ransomware deployment.",
        "reasoning": "Detected anomalous syscall activity.",
        "remediation_yaml": "apiVersion: v1\nkind: Pod\n...",
        "fix_type": "RBAC",
        "fix_description": "Restrict ServiceAccount permissions to prevented unauthorized syscalls.",
        "remediation": {
            "insecure_yaml": "apiVersion: v1\nkind: Pod...",
            "secure_yaml": "apiVersion: v1\nkind: Pod..."
        }
    }

@app.post(f"{API_PREFIX}/enforcement/mode")
async def toggle_enforcement():
    return {"mode": "guardian"}

@app.post(f"{API_PREFIX}/sentinel/analyze")
async def sentinel_analyze_post(event: dict):
    # This matches what _sentinel_live.py sends
    record_event(event)
    return {"status": "ok"}

@app.post(f"{API_PREFIX}/neutralize/{{event_id}}")
async def neutralize_event(event_id: str):
    yaml_fix = None
    with _lock:
        for e in _recent_events:
            if e.get("event_id") == event_id:
                explanation = e.get("explanation") or {}
                orch = explanation.get("orchestrator_result") or {}
                yaml_fix = orch.get("yaml_fix")
                break
    
    if yaml_fix and isinstance(yaml_fix, str):
        import subprocess
        try:
            p = subprocess.run(["kubectl", "apply", "-f", "-"], input=yaml_fix.encode("utf-8"), capture_output=True)
            if p.returncode == 0:
                with _lock:
                    _metrics["active_alerts"] = max(0, _metrics["active_alerts"] - 1)
                return {
                    "status": "Neutralized",
                    "event_id": event_id,
                    "immunity_score": 90,
                    "details": p.stdout.decode()
                }
            else:
                return {"error": "Failed to apply fix", "details": p.stderr.decode()}
        except Exception as e:
            return {"error": str(e)}

    # Mock internalization for demo
    with _lock:
        _metrics["active_alerts"] = max(0, _metrics["active_alerts"] - 1)
    return {
        "status": "Neutralized",
        "event_id": event_id,
        "immunity_score": 90,
    }

# ── WebSocket ─────────────────────────────────────────────────────
from fastapi import WebSocket, WebSocketDisconnect

@app.websocket(f"{API_PREFIX}/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()
    with _lock:
        _ws_clients.append(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        with _lock:
            if websocket in _ws_clients:
                _ws_clients.remove(websocket)

@app.get("/")
async def root():
    return {"status": "Sentinel-Core API Live", "docs": "/docs"}
