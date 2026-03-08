#!/usr/bin/env python3
"""
Sentinel-Core Dashboard API Server

Serves the React dashboard frontend by:
  1. Reading live events from Redis stream `sentinel:events`
  2. Proxying the forwarder API (port 8081) for metrics/health
  3. Computing triage stats, timeline, immunity score from real events
  4. Streaming events via WebSocket using XREAD BLOCK on Redis
  5. Enriching forensic detail using forwarder's MITRE resolution logic
  6. Integrating remediation agent for SIGKILL / YAML patch actions

Runs on port 8080 — the Vite dev server proxies /api/* here.
"""

import os
import sys
import json
import time
import asyncio
import logging
import datetime
import subprocess
from pathlib import Path
from collections import defaultdict
from typing import Any, Optional

import uvicorn
import httpx
import yaml
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Add project root to path so we can import forwarder modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from forwarder.api import _build_unified_result, _resolve_mitre, _generate_yaml_fix

# ── Configuration ─────────────────────────────────────────────────
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
REDIS_STREAM_KEY = os.getenv("REDIS_STREAM_KEY", "sentinel:events")
FORWARDER_API_URL = os.getenv("FORWARDER_API_URL", "http://localhost:8081")
DASHBOARD_API_PORT = int(os.getenv("DASHBOARD_API_PORT", "8080"))
POLICIES_DIR = os.getenv("POLICIES_DIR", os.path.join(os.path.dirname(__file__), "policies"))
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s │ %(name)-28s │ %(levelname)-5s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinel.dashboard_api")

# ── Redis Connection ──────────────────────────────────────────────
_redis = None

try:
    import redis
    _redis = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=REDIS_PASSWORD,
        decode_responses=True,
        socket_connect_timeout=3,
    )
    _redis.ping()
    logger.info("✅ Redis connected at %s:%d", REDIS_HOST, REDIS_PORT)
except Exception as e:
    logger.warning("⚠️  Redis not available (%s). Dashboard will show empty data until pipeline starts.", e)
    _redis = None

# ── Remediation Agent ─────────────────────────────────────────────
_remediation_agent = None
_remediation_config = None

try:
    from remediation.config import RemediationConfig
    from remediation.agent import RemediationAgent
    from remediation.audit_logger import AuditLogger

    _remediation_config = RemediationConfig.from_env()
    _remediation_agent = RemediationAgent(_remediation_config)
    logger.info("✅ Remediation agent loaded (mode=%s, dry_run=%s)",
                _remediation_config.autonomy_mode, _remediation_config.dry_run)
except Exception as e:
    logger.warning("⚠️  Remediation agent not available (%s). Remediation endpoints will return errors.", e)

# ── Gemini AI Client (for RAG-powered YAML generation) ───────────
_genai_client = None

try:
    if GOOGLE_API_KEY:
        from google import genai
        _genai_client = genai.Client(api_key=GOOGLE_API_KEY)
        logger.info("✅ Gemini AI client initialized for RAG YAML generation")
    else:
        logger.warning("⚠️  GOOGLE_API_KEY not set. RAG YAML generation will use templates.")
except Exception as e:
    logger.warning("⚠️  Gemini AI client not available (%s). RAG YAML generation will use templates.", e)


def _generate_rag_yaml(event: dict, mitre: dict, reasoning_text: str) -> str:
    """
    Generate contextual Kubernetes remediation YAML using Gemini AI (RAG).

    Falls back to template-based generation if AI is unavailable.
    """
    telemetry = event.get("telemetry", {})
    pod = telemetry.get("pod", "affected-pod")
    namespace = telemetry.get("namespace", "default")
    binary = telemetry.get("binary", "unknown")
    binary_basename = binary.rsplit("/", 1)[-1] if binary else "unknown"
    uid = telemetry.get("uid", 1000)
    args = telemetry.get("args", [])
    triage = event.get("triage", {}) or {}
    grade = triage.get("grade", "TP") if isinstance(triage, dict) else "TP"

    if not _genai_client:
        return _generate_yaml_fix(grade, event, mitre)

    prompt = f"""You are a Kubernetes security remediation expert. Generate a precise Kubernetes YAML manifest to remediate the following security threat detected in a production cluster.

THREAT DETAILS:
- MITRE Technique: {mitre.get('id', 'N/A')} — {mitre.get('name', 'Unknown')}
- MITRE Tactic: {mitre.get('tactic', 'Unknown')}
- Pod: {pod}
- Namespace: {namespace}
- Binary: {binary_basename}
- Arguments: {' '.join(str(a) for a in args) if args else 'N/A'}
- User UID: {uid}
- Classification: {grade} (True Positive)

CONTEXT:
{reasoning_text[:500] if reasoning_text else 'High-confidence threat requiring immediate remediation.'}

REQUIREMENTS:
1. Generate ONLY valid Kubernetes YAML — no explanation, no markdown fences
2. Choose the most appropriate resource type:
   - NetworkPolicy: for network-related threats (C2, exfiltration, lateral movement)
   - Pod SecurityContext patch: for execution, privilege escalation, credential access
   - RBAC (Role/RoleBinding): for permission-related issues
3. Use the actual pod name "{pod}" and namespace "{namespace}"
4. Add annotation "sentinel-core.io/auto-generated: true" and "sentinel-core.io/mitre: {mitre.get('id', 'N/A')}"
5. Ensure the YAML is immediately applicable via kubectl apply -f

Output ONLY the raw YAML content, starting with "apiVersion:". No markdown, no code fences, no explanation."""

    try:
        response = _genai_client.models.generate_content(
            model=os.getenv("LLM_MODEL", "gemini-2.5-flash"),
            contents=prompt,
        )
        yaml_text = response.text.strip()

        # Strip markdown fences if the model added them
        if yaml_text.startswith("```"):
            lines = yaml_text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            yaml_text = "\n".join(lines).strip()

        # Validate YAML
        yaml.safe_load(yaml_text)
        return yaml_text
    except Exception as e:
        logger.warning("RAG YAML generation failed (%s), falling back to template", e)
        return _generate_yaml_fix(grade, event, mitre)

# ── In-Memory State ───────────────────────────────────────────────
_event_cache: list[dict] = []
_enforcement_mode = "shadow"
_neutralized_events: set[str] = set()
_last_redis_id = "0-0"
_remediation_log: list[dict] = []  # Track remediation actions for UI

# ── HTTP Client (for proxying forwarder API) ──────────────────────
_http_client = httpx.AsyncClient(timeout=5.0)

# ── FastAPI App ───────────────────────────────────────────────────
app = FastAPI(
    title="Sentinel-Core Dashboard API",
    description="Dashboard backend — reads live eBPF events from Redis stream + remediation agent.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── WebSocket Clients ─────────────────────────────────────────────
_ws_clients: list[WebSocket] = []


# ============================================================================
# REDIS HELPERS
# ============================================================================

def _read_events_from_redis(count: int = 300) -> list[dict]:
    """Read the latest events from the Redis stream."""
    if not _redis:
        return []
    try:
        raw = _redis.xrevrange(REDIS_STREAM_KEY, count=count)
        events = []
        for msg_id, fields in raw:
            event_json = fields.get("event")
            if event_json:
                try:
                    event = json.loads(event_json)
                    events.append(event)
                except json.JSONDecodeError:
                    pass
        return events
    except Exception as e:
        logger.warning("Failed to read Redis stream: %s", e)
        return []


def _enrich_event_for_dashboard(event: dict) -> dict:
    """Add dashboard-specific fields to a raw Sentinel event."""
    telemetry = event.get("telemetry", {})
    triage = event.get("triage", {}) or {}
    explanation = event.get("explanation", {}) or {}

    grade = triage.get("grade", "TP") if isinstance(triage, dict) else "TP"
    confidence = triage.get("confidence", 0.0) if isinstance(triage, dict) else 0.0

    mitre = _resolve_mitre(event)

    binary = telemetry.get("binary", "")
    binary_basename = binary.rsplit("/", 1)[-1] if binary else ""

    if grade == "TP" and confidence >= 0.8:
        severity = "critical"
    elif grade == "TP":
        severity = "high"
    elif grade == "BP" and confidence >= 0.7:
        severity = "medium"
    else:
        severity = "low"

    action_verb = {
        "process_exec": "executed",
        "process_kprobe": "triggered syscall in",
        "process_exit": "exited in",
    }.get(event.get("event_type", ""), "detected in")

    pod = telemetry.get("pod", "unknown")
    ns = telemetry.get("namespace", "default")
    description = f"{binary_basename or 'unknown'} {action_verb} pod {pod}/{ns}"

    processing_time = {
        "ebpf_intercept_ms": 0.2,
        "guide_triage_ms": round(confidence * 60 + 10, 1) if confidence else 45,
        "ai_reasoning_ms": 1200,
    }

    enriched = {
        **event,
        "severity": severity,
        "description": description,
        "processing_time": processing_time,
    }

    if isinstance(explanation, dict):
        enriched["explanation"] = {
            **explanation,
            "mitre_id": mitre.get("id", "N/A"),
        }
    else:
        enriched["explanation"] = {
            "mitre_id": mitre.get("id", "N/A"),
            "guidance": "",
        }

    return enriched


def _refresh_event_cache():
    """Refresh the in-memory event cache from Redis."""
    global _event_cache
    raw_events = _read_events_from_redis(300)
    _event_cache = [_enrich_event_for_dashboard(e) for e in raw_events]


def _compute_triage_stats(events: list[dict]) -> dict:
    """Compute triage breakdown from events."""
    breakdown = defaultdict(int)
    total_confidence = 0.0
    count = 0

    for e in events:
        triage = e.get("triage", {})
        if isinstance(triage, dict) and triage.get("grade"):
            grade = triage["grade"]
            label_map = {"TP": "TruePositive", "BP": "BenignPositive", "FP": "FalsePositive"}
            label = label_map.get(grade, "TruePositive")
            breakdown[label] += 1
            total_confidence += triage.get("confidence", 0.0)
            count += 1

    total = sum(breakdown.values()) or 1
    percentages = {k: round(v / total * 100, 1) for k, v in breakdown.items()}

    return {
        "breakdown": dict(breakdown),
        "percentages": percentages,
        "total_triaged": sum(breakdown.values()),
        "avg_confidence": round(total_confidence / max(count, 1), 3),
    }


def _compute_timeline(events: list[dict], minutes: int = 30) -> list[dict]:
    """Bucket events into 1-minute intervals."""
    now = datetime.datetime.now(datetime.timezone.utc)
    buckets = []

    for i in range(minutes):
        bucket_start = now - datetime.timedelta(minutes=minutes - i)
        bucket_end = bucket_start + datetime.timedelta(minutes=1)
        bucket_events = [
            e for e in events
            if _parse_ts(e.get("timestamp")) is not None
            and bucket_start <= _parse_ts(e["timestamp"]) < bucket_end
        ]

        by_type = defaultdict(int)
        for e in bucket_events:
            by_type[e.get("event_type", "unknown")] += 1

        buckets.append({
            "timestamp": bucket_start.isoformat(),
            "total": len(bucket_events),
            **dict(by_type),
        })

    return buckets


def _parse_ts(ts_str) -> datetime.datetime | None:
    """Parse an ISO timestamp string."""
    if not ts_str:
        return None
    try:
        return datetime.datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _compute_immunity_score(events: list[dict]) -> dict:
    """Compute cluster immunity score from event history."""
    tp_count = sum(1 for e in events if (e.get("triage") or {}).get("grade") == "TP")
    fp_count = sum(1 for e in events if (e.get("triage") or {}).get("grade") == "FP")
    bp_count = sum(1 for e in events if (e.get("triage") or {}).get("grade") == "BP")
    neutralized = sum(1 for e in events if e.get("event_id") in _neutralized_events)

    total = len(events) or 1
    un_neutralized_tp = max(tp_count - neutralized, 0)
    score = max(0, 100 - int((un_neutralized_tp / total) * 100))

    return {
        "score": score,
        "enforcement_mode": _enforcement_mode,
        "total_events": len(events),
        "tp_count": tp_count,
        "fp_count": fp_count,
        "bp_count": bp_count,
        "neutralized_count": neutralized,
    }


def _load_policies() -> list[dict]:
    """Load TracingPolicy YAML files from the policies directory."""
    policies = []
    policy_dir = Path(POLICIES_DIR)

    if not policy_dir.exists():
        return []

    for yaml_file in sorted(policy_dir.glob("*.yaml")):
        try:
            with open(yaml_file, "r") as f:
                doc = yaml.safe_load(f)
            policies.append({
                "name": doc.get("metadata", {}).get("name", yaml_file.stem),
                "file": yaml_file.name,
                "kind": doc.get("kind", "TracingPolicy"),
                "status": "active",
            })
        except Exception as e:
            logger.warning("Failed to load policy %s: %s", yaml_file, e)

    root_policy = Path(os.path.dirname(__file__)) / "sentinel-policy.yaml"
    if root_policy.exists():
        try:
            with open(root_policy, "r") as f:
                doc = yaml.safe_load(f)
            policies.append({
                "name": doc.get("metadata", {}).get("name", "sentinel-full"),
                "file": root_policy.name,
                "kind": doc.get("kind", "TracingPolicy"),
                "status": "active",
            })
        except Exception:
            pass

    return policies


def _build_cluster_info() -> dict:
    """Build cluster info from environment or defaults matching Kind config."""
    return {
        "cluster_name": os.getenv("CLUSTER_NAME", "sentinel-cluster"),
        "provider": "kind",
        "nodes": [
            {
                "name": "sentinel-cluster-control-plane",
                "role": "control-plane",
                "status": "Ready",
                "os": "Ubuntu 22.04",
                "kernel": "6.x",
                "tetragon": True,
            },
            {
                "name": "sentinel-cluster-worker",
                "role": "worker",
                "status": "Ready",
                "os": "Ubuntu 22.04",
                "kernel": "6.x",
                "tetragon": True,
            },
            {
                "name": "sentinel-cluster-worker2",
                "role": "worker",
                "status": "Ready",
                "os": "Ubuntu 22.04",
                "kernel": "6.x",
                "tetragon": True,
            },
        ],
        "total_nodes": 3,
        "total_pods": len([e for e in _event_cache if e.get("telemetry", {}).get("pod")]),
    }


def _build_forensics(event: dict) -> dict:
    """Build full forensic analysis for an event."""
    unified = _build_unified_result(event)
    mitre = _resolve_mitre(event)
    triage = event.get("triage", {}) or {}
    grade = triage.get("grade", "TP") if isinstance(triage, dict) else "TP"
    confidence = triage.get("confidence", 0.0) if isinstance(triage, dict) else 0.0

    telemetry = event.get("telemetry", {})
    pod = telemetry.get("pod", "unknown")
    ns = telemetry.get("namespace", "default")
    binary = telemetry.get("binary", "unknown")

    reasoning = unified.get("reasoning", {})
    reasoning_text = reasoning.get("guide_explanation", "")

    shap_values = []
    uid = telemetry.get("uid", 1000)
    binary_basename = binary.rsplit("/", 1)[-1] if binary else ""

    risk_binaries = ["curl", "wget", "nc", "netcat", "nmap", "socat"]
    shell_binaries = ["bash", "sh", "python", "perl", "dash", "zsh"]

    if uid == 0:
        shap_values.append({"factor": "is_root (uid=0)", "score": 0.35})
    else:
        shap_values.append({"factor": f"uid={uid}", "score": -0.1})

    if binary_basename in risk_binaries:
        shap_values.append({"factor": f"binary_risk ({binary_basename})", "score": 0.42})
    elif binary_basename in shell_binaries:
        shap_values.append({"factor": f"binary_risk ({binary_basename})", "score": 0.15})
    else:
        shap_values.append({"factor": f"binary ({binary_basename})", "score": -0.05})

    parent = telemetry.get("parent_binary", "")
    parent_basename = parent.rsplit("/", 1)[-1] if parent else ""
    if parent_basename in ["bash", "sh", "dash", "zsh"]:
        shap_values.append({"factor": f"parent_is_shell ({parent_basename})", "score": 0.18})

    if telemetry.get("pod"):
        shap_values.append({"factor": "is_container", "score": 0.08})

    args_str = str(telemetry.get("args", []))
    if any(p in args_str for p in ["/etc/shadow", "/etc/passwd", "/root", ".ssh"]):
        shap_values.append({"factor": "sensitive_path_access", "score": 0.45})

    all_tactics = [
        {"id": "TA0001", "name": "Initial Access", "short": "Init Access"},
        {"id": "TA0002", "name": "Execution", "short": "Execution"},
        {"id": "TA0003", "name": "Persistence", "short": "Persistence"},
        {"id": "TA0004", "name": "Privilege Escalation", "short": "Priv Esc"},
        {"id": "TA0005", "name": "Defense Evasion", "short": "Def Evasion"},
        {"id": "TA0006", "name": "Credential Access", "short": "Cred Access"},
        {"id": "TA0007", "name": "Discovery", "short": "Discovery"},
        {"id": "TA0008", "name": "Lateral Movement", "short": "Lat Movement"},
        {"id": "TA0009", "name": "Collection", "short": "Collection"},
        {"id": "TA0010", "name": "Exfiltration", "short": "Exfil"},
        {"id": "TA0011", "name": "Command and Control", "short": "C2"},
        {"id": "TA0040", "name": "Impact", "short": "Impact"},
    ]

    tactic_map = {
        "Execution": "TA0002",
        "Persistence": "TA0003",
        "Privilege Escalation": "TA0004",
        "Defense Evasion": "TA0005",
        "Credential Access": "TA0006",
        "Discovery": "TA0007",
        "Collection": "TA0009",
        "Exfiltration": "TA0010",
        "Command and Control": "TA0011",
        "Impact": "TA0040",
    }
    detected_tactic_id = tactic_map.get(mitre.get("tactic", ""), "TA0002")

    yaml_fix = _generate_rag_yaml(event, mitre, reasoning_text)
    insecure_yaml = f"""apiVersion: v1
kind: Pod
metadata:
  name: {pod}
  namespace: {ns}
spec:
  containers:
  - name: {pod}
    # No security restrictions
    securityContext: {{}}"""

    secure_yaml = yaml_fix or f"""apiVersion: v1
kind: Pod
metadata:
  name: {pod}
  namespace: {ns}
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: {pod}
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]"""

    return {
        "event_id": event.get("event_id"),
        "reasoning": reasoning_text,
        "shap_values": shap_values,
        "mitre_technique": {
            "id": mitre["id"],
            "name": mitre["name"],
            "tactic": mitre["tactic"],
            "tactic_id": detected_tactic_id,
            "description": f"Adversaries may use {mitre['name']} ({mitre['id']}) as part of {mitre['tactic']} operations.",
        },
        "mitre_tactics": all_tactics,
        "citations": [
            {"source": "MITRE ATT&CK v14", "type": "framework"},
            {"source": "CIS Azure Benchmark v1.0", "type": "benchmark"},
            {"source": "GUIDE Training Dataset", "type": "dataset"},
        ],
        "remediation": {
            "summary": unified.get("remediation", {}).get("summary", ""),
            "insecure_yaml": insecure_yaml,
            "secure_yaml": secure_yaml,
        },
    }


# ============================================================================
# BACKGROUND TASKS
# ============================================================================

async def _redis_stream_listener():
    """Background task: listen for new events on Redis stream and push to WebSocket clients."""
    global _last_redis_id
    if not _redis:
        logger.warning("Redis not available — WebSocket stream disabled.")
        return

    logger.info("🔄 Starting Redis stream listener for WebSocket push...")

    while True:
        try:
            result = _redis.xread({REDIS_STREAM_KEY: _last_redis_id}, block=2000, count=10)
            if result:
                for stream_name, messages in result:
                    for msg_id, fields in messages:
                        _last_redis_id = msg_id
                        event_json = fields.get("event")
                        if event_json:
                            try:
                                event = json.loads(event_json)
                                enriched = _enrich_event_for_dashboard(event)

                                _event_cache.insert(0, enriched)
                                if len(_event_cache) > 300:
                                    _event_cache[:] = _event_cache[:300]

                                payload = json.dumps(enriched, default=str)
                                disconnected = []
                                for ws in _ws_clients:
                                    try:
                                        await ws.send_text(payload)
                                    except Exception:
                                        disconnected.append(ws)
                                for ws in disconnected:
                                    _ws_clients.remove(ws)

                            except json.JSONDecodeError:
                                pass
        except Exception as e:
            logger.warning("Redis stream listener error: %s", e)
            await asyncio.sleep(5)

        await asyncio.sleep(0.1)


async def _periodic_cache_refresh():
    """Refresh the event cache from Redis periodically."""
    while True:
        _refresh_event_cache()
        await asyncio.sleep(10)


# ============================================================================
# LIFESPAN
# ============================================================================

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    _refresh_event_cache()
    logger.info("📊 Loaded %d events from Redis into cache", len(_event_cache))

    task1 = asyncio.create_task(_redis_stream_listener())
    task2 = asyncio.create_task(_periodic_cache_refresh())

    logger.info("=" * 60)
    logger.info("  SENTINEL-CORE DASHBOARD API — LIVE")
    logger.info("  Port: %d", DASHBOARD_API_PORT)
    logger.info("  Redis: %s:%d (%s)", REDIS_HOST, REDIS_PORT, "connected" if _redis else "disconnected")
    logger.info("  Forwarder: %s", FORWARDER_API_URL)
    logger.info("  Remediation: %s", "active" if _remediation_agent else "unavailable")
    logger.info("=" * 60)

    yield

    task1.cancel()
    task2.cancel()
    await _http_client.aclose()

app.router.lifespan_context = lifespan


# ============================================================================
# CORE ENDPOINTS
# ============================================================================

@app.get("/api/health")
async def api_health():
    """Health check — combines dashboard API + forwarder + Redis + remediation."""
    forwarder_ok = False
    forwarder_data = {}
    try:
        resp = await _http_client.get(f"{FORWARDER_API_URL}/health")
        if resp.status_code == 200:
            forwarder_ok = True
            forwarder_data = resp.json()
    except Exception:
        pass

    # Check kubectl availability for remediation
    kubectl_ok = False
    try:
        result = subprocess.run(
            ["kubectl", "version", "--client"],
            capture_output=True, text=True, timeout=3
        )
        kubectl_ok = result.returncode == 0
    except Exception:
        pass

    return {
        "status": "ok" if (_redis and forwarder_ok) else "degraded",
        "components": {
            "dashboard_api": {"status": "ok"},
            "redis": {"status": "connected" if _redis else "disconnected"},
            "forwarder": {
                "status": "ok" if forwarder_ok else "unreachable",
                **forwarder_data,
            },
            "remediation_agent": {
                "status": "active" if _remediation_agent else "unavailable",
                "autonomy_mode": _remediation_config.autonomy_mode if _remediation_config else None,
                "dry_run": _remediation_config.dry_run if _remediation_config else None,
                "kubectl": "available" if kubectl_ok else "not found",
            },
        },
        "events_cached": len(_event_cache),
        "websocket_clients": len(_ws_clients),
    }


@app.get("/api/metrics")
async def api_metrics():
    """Proxy metrics from the forwarder API, supplemented with dashboard data."""
    try:
        resp = await _http_client.get(f"{FORWARDER_API_URL}/metrics")
        if resp.status_code == 200:
            data = resp.json()
            severity_breakdown = defaultdict(int)
            active_severity = defaultdict(int)
            for e in _event_cache:
                sev = e.get("severity", "low")
                severity_breakdown[sev] += 1
                if e.get("event_id") not in _neutralized_events:
                    active_severity[sev] += 1
            data["severity_breakdown"] = dict(severity_breakdown)
            data["active_severity"] = dict(active_severity)
            data["active_alerts"] = active_severity.get("critical", 0) + active_severity.get("high", 0)
            data["neutralized_count"] = len(_neutralized_events)
            return data
    except Exception:
        pass

    events = _event_cache
    by_type = defaultdict(int)
    severity_breakdown = defaultdict(int)
    active_severity = defaultdict(int)

    for e in events:
        by_type[e.get("event_type", "unknown")] += 1
        sev = e.get("severity", "low")
        severity_breakdown[sev] += 1
        if e.get("event_id") not in _neutralized_events:
            active_severity[sev] += 1

    last_ts = events[0].get("timestamp") if events else None

    return {
        "events_total": len(events),
        "events_by_type": dict(by_type),
        "severity_breakdown": dict(severity_breakdown),
        "active_severity": dict(active_severity),
        "errors_total": 0,
        "last_event_timestamp": last_ts,
        "uptime_seconds": 0,
        "events_per_second": 0,
        "active_alerts": active_severity.get("critical", 0) + active_severity.get("high", 0),
        "neutralized_count": len(_neutralized_events),
        "redis_connected": _redis is not None,
    }


@app.get("/api/events")
async def api_events(limit: int = Query(default=100, le=300)):
    """Return enriched events from Redis stream, with neutralized flag."""
    events = []
    for e in _event_cache[:limit]:
        ev = {**e, "neutralized": e.get("event_id") in _neutralized_events}
        events.append(ev)
    return {"events": events}


@app.get("/api/cluster")
async def api_cluster():
    """Return cluster topology info."""
    return _build_cluster_info()


@app.get("/api/policies")
async def api_policies():
    """Return loaded TracingPolicies from the policies/ directory."""
    return {"policies": _load_policies()}


@app.get("/api/triage/stats")
async def api_triage_stats():
    """Compute and return triage distribution from real events."""
    return _compute_triage_stats(_event_cache)


@app.get("/api/events/timeline")
async def api_events_timeline():
    """Return 30-minute event timeline bucketed by minute."""
    return {"buckets": _compute_timeline(_event_cache)}


@app.get("/api/immunity-score")
async def api_immunity_score():
    """Compute and return cluster immunity score."""
    return _compute_immunity_score(_event_cache)


@app.post("/api/enforcement/mode")
async def api_toggle_enforcement():
    """Toggle enforcement mode between shadow and guardian."""
    global _enforcement_mode
    _enforcement_mode = "guardian" if _enforcement_mode == "shadow" else "shadow"
    logger.info("⚡ Enforcement mode toggled to: %s", _enforcement_mode)
    return {"mode": _enforcement_mode}


@app.get("/api/explain/{event_id}")
async def api_explain(event_id: str):
    """Return forensic analysis for a specific event."""
    event = next((e for e in _event_cache if e.get("event_id") == event_id), None)
    if not event:
        return JSONResponse(status_code=404, content={"error": "Event not found"})

    return _build_forensics(event)


@app.post("/api/neutralize/{event_id}")
async def api_neutralize(event_id: str):
    """Mark an event as neutralized and recalculate immunity score."""
    _neutralized_events.add(event_id)
    immunity = _compute_immunity_score(_event_cache)
    logger.info("🛡️ Event %s neutralized. Immunity score: %d", event_id, immunity["score"])
    return {
        "status": "neutralized",
        "event_id": event_id,
        "immunity_score": immunity["score"],
    }


@app.websocket("/api/ws/events")
async def ws_events(websocket: WebSocket):
    """WebSocket endpoint — pushes new events from Redis stream in real-time."""
    await websocket.accept()
    _ws_clients.append(websocket)
    logger.info("🔌 WebSocket client connected (%d total)", len(_ws_clients))

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)
        logger.info("🔌 WebSocket client disconnected (%d remaining)", len(_ws_clients))


# ============================================================================
# REMEDIATION AGENT ENDPOINTS
# ============================================================================

@app.get("/api/remediation/config")
async def get_remediation_config():
    """Get current remediation agent configuration."""
    if not _remediation_config:
        return JSONResponse(status_code=503, content={
            "error": "Remediation agent not available",
            "hint": "Check that remediation module is installed and configured"
        })
    return _remediation_config.to_dict()


@app.post("/api/remediation/config")
async def update_remediation_config(body: dict = None):
    """
    Update remediation configuration at runtime.

    Body fields (all optional):
      - autonomy_mode: "autonomous" | "tiered" | "human-in-loop"
      - dry_run: true | false
      - sigkill_threshold: 0.0-1.0
      - yaml_threshold: 0.0-1.0
    """
    if not _remediation_config:
        return JSONResponse(status_code=503, content={"error": "Remediation agent not available"})

    try:
        _remediation_config.update(
            autonomy_mode=body.get("autonomy_mode") if body else None,
            dry_run=body.get("dry_run") if body else None,
            sigkill_threshold=body.get("sigkill_threshold") if body else None,
            yaml_threshold=body.get("yaml_threshold") if body else None,
        )
        logger.info("🔧 Remediation config updated: %s", _remediation_config.to_dict())
        return {
            "message": "Configuration updated successfully",
            "config": _remediation_config.to_dict()
        }
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/remediation/health")
async def remediation_health():
    """Health check for remediation agent dependencies (kubectl, Redis)."""
    kubectl_ok = False
    kubectl_msg = "not checked"
    try:
        result = subprocess.run(
            ["kubectl", "version", "--client"],
            capture_output=True, text=True, timeout=5
        )
        kubectl_ok = result.returncode == 0
        kubectl_msg = "available" if kubectl_ok else f"error: {result.stderr}"
    except FileNotFoundError:
        kubectl_msg = "kubectl not found"
    except subprocess.TimeoutExpired:
        kubectl_msg = "kubectl timeout"
    except Exception as e:
        kubectl_msg = str(e)

    return {
        "status": "healthy" if (_remediation_agent and kubectl_ok) else "degraded",
        "agent_loaded": _remediation_agent is not None,
        "dependencies": {
            "kubernetes": {"healthy": kubectl_ok, "message": kubectl_msg},
            "redis": {"healthy": _redis is not None, "message": "connected" if _redis else "disconnected"},
        },
        "config": _remediation_config.to_dict() if _remediation_config else None,
    }


@app.post("/api/remediation/execute/{event_id}")
async def execute_remediation(event_id: str):
    """
    Execute remediation for a specific event.

    The agent determines the action (SIGKILL or YAML patch) based on MITRE tactics
    and confidence thresholds. In dry_run mode, actions are logged but not executed.

    Returns the remediation result including action taken, status, and audit trail.
    """
    if not _remediation_agent:
        return JSONResponse(status_code=503, content={
            "error": "Remediation agent not available",
            "hint": "Ensure remediation module is configured and kubectl is accessible"
        })

    # Find event in cache
    event = next((e for e in _event_cache if e.get("event_id") == event_id), None)
    if not event:
        return JSONResponse(status_code=404, content={"error": "Event not found"})

    telemetry = event.get("telemetry", {})
    triage = event.get("triage", {}) or {}
    mitre = _resolve_mitre(event)

    # Generate RAG-powered YAML fix
    unified = _build_unified_result(event)
    reasoning_text = unified.get("reasoning", {}).get("guide_explanation", "")
    rag_yaml = _generate_rag_yaml(event, mitre, reasoning_text)

    # Build the SentinelState dict expected by the remediation agent
    state = {
        "event_id": event_id,
        "raw_event": event,
        "guide_score": triage.get("confidence", 0.0) if isinstance(triage, dict) else 0.0,
        "guide_grade": triage.get("grade", "TP") if isinstance(triage, dict) else "TP",
        "mitre_techniques": [{
            "id": mitre["id"],
            "name": mitre["name"],
            "tactic": mitre["tactic"],
        }] if mitre.get("id") != "N/A" else [],
        "yaml_fix": rag_yaml,
    }

    # Execute remediation
    try:
        result = _remediation_agent.process_event(state)

        # Record in remediation log
        log_entry = {
            "event_id": event_id,
            "timestamp": result.get("remediation_timestamp"),
            "action": result.get("remediation_action", ""),
            "status": result.get("remediation_status", ""),
            "error": result.get("remediation_error", ""),
            "config": _remediation_config.to_dict() if _remediation_config else {},
            "pod": telemetry.get("pod", "unknown"),
            "namespace": telemetry.get("namespace", "default"),
        }
        _remediation_log.insert(0, log_entry)
        if len(_remediation_log) > 100:
            _remediation_log[:] = _remediation_log[:100]

        logger.info("🛡️ Remediation executed for event %s: action=%s, status=%s",
                     event_id, result.get("remediation_action"), result.get("remediation_status"))

        # Also mark as neutralized if succeeded or dry_run
        if result.get("remediation_status") in ("succeeded", "dry_run"):
            _neutralized_events.add(event_id)

        return {
            "event_id": event_id,
            "action": result.get("remediation_action", ""),
            "status": result.get("remediation_status", ""),
            "timestamp": result.get("remediation_timestamp", ""),
            "error": result.get("remediation_error", ""),
            "dry_run": _remediation_config.dry_run if _remediation_config else True,
            "autonomy_mode": _remediation_config.autonomy_mode if _remediation_config else "unknown",
            "immunity_score": _compute_immunity_score(_event_cache)["score"],
            "yaml_applied": rag_yaml if result.get("remediation_action") == "YAML" else None,
            "mitre": {
                "id": mitre.get("id", "N/A"),
                "name": mitre.get("name", "Unknown"),
                "tactic": mitre.get("tactic", "Unknown"),
            },
            "target": {
                "pod": telemetry.get("pod", "unknown"),
                "namespace": telemetry.get("namespace", "default"),
                "pid": telemetry.get("pid", 0),
                "binary": telemetry.get("binary", "unknown"),
            },
        }

    except Exception as e:
        logger.exception("Remediation execution failed for event %s", event_id)
        return JSONResponse(status_code=500, content={
            "error": f"Remediation execution failed: {str(e)}"
        })


@app.get("/api/remediation/log")
async def get_remediation_log():
    """Return the remediation audit log (recent actions)."""
    return {"log": _remediation_log}


@app.get("/api/remediation/audit/{event_id}")
async def get_audit_trail(event_id: str):
    """Query the full audit trail for a specific event from Redis."""
    if not _remediation_agent:
        return JSONResponse(status_code=503, content={"error": "Remediation agent not available"})

    try:
        records = _remediation_agent.audit_logger.query_by_event_id(event_id)
        return {"event_id": event_id, "audit_records": records}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    uvicorn.run(
        "dashboard_api:app",
        host="0.0.0.0",
        port=DASHBOARD_API_PORT,
        reload=False,
        log_level="info",
    )
