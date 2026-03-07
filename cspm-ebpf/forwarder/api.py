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
    "errors_total": 0,
    "last_event_timestamp": None,
    "start_time": time.time(),
    "redis_connected": False,
}
_recent_events: deque[dict] = deque(maxlen=100)
_ml_triage: Any = None


def set_ml_triage(triage_instance: Any) -> None:
    """Register the ML triage instance with the API."""
    global _ml_triage
    _ml_triage = triage_instance


def record_event(event: dict) -> None:
    """Record a processed event for metrics and recent-events buffer."""
    with _lock:
        _metrics["events_total"] += 1
        _metrics["last_event_timestamp"] = event.get("timestamp")
        etype = event.get("event_type", "unknown")
        _metrics["events_by_type"][etype] = _metrics["events_by_type"].get(etype, 0) + 1
        _recent_events.appendleft(event)


def record_error() -> None:
    """Increment the error counter."""
    with _lock:
        _metrics["errors_total"] += 1


def set_redis_status(connected: bool) -> None:
    """Update Redis connection status in metrics."""
    with _lock:
        _metrics["redis_connected"] = connected


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


@app.get("/health")
async def health():
    """Liveness probe."""
    return {"status": "ok", "service": "sentinel-event-forwarder"}


@app.get("/metrics")
async def metrics():
    """Return event processing metrics."""
    with _lock:
        uptime = time.time() - _metrics["start_time"]
        return JSONResponse(
            content={
                **_metrics,
                "uptime_seconds": round(uptime, 1),
                "events_per_second": round(
                    _metrics["events_total"] / max(uptime, 1), 2
                ),
            }
        )


@app.get("/events/latest")
async def latest_events(limit: int = 20):
    """Return the most recent processed events."""
    with _lock:
        events = list(_recent_events)[:limit]
    return {"count": len(events), "events": events}


@app.get("/events/stream")
async def event_stream_info():
    """Info about how to consume events."""
    return {
        "redis_stream": "sentinel:events",
        "consume_command": "redis-cli XREAD BLOCK 0 STREAMS sentinel:events $",
        "api_latest": "/events/latest?limit=50",
    }


@app.get("/")
async def root():
    """
    Root endpoint — displays full unified analysis of all recent events.
    Uses pre-computed triage data from the forwarder pipeline (instant, no ML re-run).
    Visit http://127.0.0.1:8081/ in your browser to see live results.
    """
    with _lock:
        events = list(_recent_events)[:20]

    if not events:
        return {
            "service": "Sentinel-Core Security Platform",
            "version": "1.0.0",
            "status": "running",
            "message": "No events captured yet. Waiting for eBPF telemetry...",
            "endpoints": {
                "unified_analysis": "/sentinel/analyze  (POST an event or GET for latest)",
                "health": "/health",
                "metrics": "/metrics",
                "latest_events": "/events/latest",
                "docs": "/docs",
            },
        }

    # Build results using pre-computed triage (no ML re-run)
    analyzed = []
    for event in events:
        analyzed.append(_build_unified_result(event))

    return {
        "service": "Sentinel-Core Security Platform",
        "version": "1.0.0",
        "pipeline": "Detection → Triage (GUIDE) → Action (eBPF-LSM) → Reasoning (MITRE) → Remediation (YAML)",
        "total_events_analyzed": len(analyzed),
        "results": analyzed,
    }


@app.get("/sentinel/analyze")
async def sentinel_analyze_get():
    """
    GET version — auto-analyzes the most recent event.
    Visit http://127.0.0.1:8081/sentinel/analyze in your browser.
    """
    with _lock:
        events = list(_recent_events)[:1]

    if not events:
        return {"error": "No events captured yet. Waiting for eBPF telemetry..."}

    return _build_unified_result(events[0])


# ── Unified Sentinel Analyse Endpoint (PRD F1–F3) ────────────────


@app.post("/sentinel/analyze")
async def sentinel_analyze(event: dict):
    """
    Sentinel-Core Unified Analysis Endpoint.

    Executes the full PRD pipeline in a single call:
      1. Detection  — Captures the raw eBPF telemetry.
      2. Triage     — GUIDE-aware ML classification (TP / BP / FP).
      3. Action     — eBPF-LSM enforcement decision (kill / log / suppress).
      4. Reasoning  — MITRE ATT&CK mapping + contextual explanation.
      5. Remediation — Kubernetes YAML fix to harden the workload.

    Returns a fully structured JSON covering all five stages.
    """
    start_time = time.time()

    # ── 1. Detection ──────────────────────────────────────────────
    telemetry = event.get("telemetry", event)
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

    # ── 2. Triage (GUIDE-Aware ML Classification) ─────────────────
    # Check if triage was already computed by the forwarder pipeline
    existing_triage = event.get("triage")
    if existing_triage and isinstance(existing_triage, dict) and "grade" in existing_triage:
        triage = {
            "grade": existing_triage.get("grade", "TP"),
            "confidence": existing_triage.get("confidence", 0.0),
            "model": "xgboost-guide",
            "status": event.get("explanation", {}).get("guidance", "") if isinstance(event.get("explanation"), dict) else "",
        }
    elif _ml_triage is None:
        triage = {
            "grade": "TP",
            "confidence": 0.0,
            "model": "unavailable",
            "status": "ML Triage service not initialized — defaulting to TP for safety.",
        }
    else:
        ml_result = _ml_triage.triage_event(event)
        triage_data = ml_result.get("triage") or {}
        triage = {
            "grade": triage_data.get("grade", "TP"),
            "confidence": triage_data.get("confidence", 0.0),
            "model": "xgboost-guide",
            "status": ml_result.get("deliverable", ""),
        }

    grade = triage["grade"]
    confidence = triage["confidence"]

    # ── 3. Action (eBPF-LSM Enforcement Decision) ─────────────────
    action = _determine_action(grade, confidence, event)

    # ── 4. Reasoning (MITRE ATT&CK + Contextual Explanation) ─────
    mitre = _resolve_mitre(event)

    # Build the contextual guidance based on grade
    if grade == "TP":
        guide_explanation = (
            f"GUIDE classification: True Positive with {confidence*100:.0f}% confidence. "
            f"This maps to MITRE ATT&CK technique {mitre['id']} ({mitre['name']}), "
            f"tactic: {mitre['tactic']}. "
            f"Process {detection['process']} executed by user '{detection['user']}' (UID {detection['uid']}) "
            f"in pod {detection['pod_name']}/{detection['namespace']} has been terminated. "
            f"Immediate investigation and remediation recommended."
        )
    elif grade == "BP":
        guide_explanation = (
            f"GUIDE classification: Benign Positive with {confidence*100:.0f}% confidence. "
            f"Activity maps to {mitre['id']} ({mitre['name']}) but is likely authorized. "
            f"Process {detection['process']} from user '{detection['user']}' has been allowed "
            f"but flagged for contextual review. Verify this is expected admin activity."
        )
    else:  # FP
        guide_explanation = (
            f"GUIDE classification: False Positive with {confidence*100:.0f}% confidence. "
            f"Alert auto-suppressed. Process {detection['process']} is routine system noise. "
            f"No SOC action required — saving analyst time."
        )

    reasoning = {
        "mitre_technique": {
            "id": mitre["id"],
            "name": mitre["name"],
            "tactic": mitre["tactic"],
        },
        "guide_explanation": guide_explanation,
    }

    # ── 5. Remediation (Kubernetes YAML Fix) ──────────────────────
    yaml_fix = _generate_yaml_fix(grade, event, mitre)
    if grade == "TP":
        remediation_summary = (
            f"Harden pod {detection['pod_name']} — apply SecurityContext restrictions "
            f"to prevent {mitre['name']} ({mitre['id']})."
        )
    elif grade == "BP":
        remediation_summary = (
            f"Review and optionally restrict access for user '{detection['user']}' "
            f"in namespace {detection['namespace']}."
        )
    else:
        remediation_summary = "No remediation needed — false positive."

    remediation = {
        "summary": remediation_summary,
        "yaml_fix": yaml_fix,
    }

    # ── Assemble Unified Response ─────────────────────────────────
    processing_time_ms = round((time.time() - start_time) * 1000, 2)

    return {
        "event_id": event.get("event_id", str(uuid.uuid4())),
        "timestamp": event.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat()),
        "processing_time_ms": processing_time_ms,
        "detection": detection,
        "triage": triage,
        "action": action,
        "reasoning": reasoning,
        "remediation": remediation,
    }


# ── Backwards-compatible /triage alias ────────────────────────────

@app.post("/triage")
async def triage_event(event: dict):
    """
    Legacy /triage endpoint — redirects to /sentinel/analyze.
    Kept for backwards compatibility.
    """
    return await sentinel_analyze(event)
