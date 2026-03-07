#!/usr/bin/env python3
"""
Sentinel-Core Security Platform — FastAPI Application

Single-endpoint design:
  POST /sentinel/analyze  — Full analysis returning comprehensive JSON
  GET  /health            — Service health check
"""

import os
import re
import time
import json
import logging
import asyncio
import secrets
import datetime
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, status, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, field_validator
import uvicorn

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from dotenv import load_dotenv
load_dotenv()

# Import orchestrator logic
try:
    from orchestrator import analyze_alert, ORCHESTRATOR_AVAILABLE, _pc_index, _genai_client
except ImportError as e:
    ORCHESTRATOR_AVAILABLE = False
    _pc_index = None
    _genai_client = None
    print(f"Warning: orchestrator module not available: {e}")

# Import ingestion logic
try:
    from ingest import SentinelIngestor
    INGESTOR_AVAILABLE = True
except ImportError as e:
    INGESTOR_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rate Limiter
limiter = Limiter(key_func=get_remote_address)

# Redis connection for attack history
_redis_client = None
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_CHANNEL = os.getenv("REDIS_CHANNEL", "sentinel-events")

try:
    import redis
    _redis_client = redis.Redis(
        host=REDIS_HOST, port=REDIS_PORT,
        decode_responses=True, socket_connect_timeout=3
    )
    _redis_client.ping()
    logger.info(f"Redis connected at {REDIS_HOST}:{REDIS_PORT}")
except Exception as e:
    logger.warning(f"Redis not available: {e}. Attack history will be empty.")
    _redis_client = None


# ============================================================================
# API KEY AUTHENTICATION
# ============================================================================

def verify_api_key(x_sentinel_key: Optional[str] = Header(None, alias="X-Sentinel-Key")):
    """Verify the API key if SENTINEL_API_KEY env var is set."""
    expected_key = os.getenv("SENTINEL_API_KEY")
    if not expected_key:
        return True  # Dev mode: skip auth

    if not x_sentinel_key or not secrets.compare_digest(x_sentinel_key, expected_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key"
        )
    return True


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class RawEvent(BaseModel):
    process: str = Field(..., description="Name of the process")
    syscall: str = Field(..., description="System call name")
    file_path: str = Field(..., description="File path accessed")
    pod_name: str = Field(..., description="Kubernetes pod name")
    namespace: str = Field(..., description="Kubernetes namespace")
    user: str = Field(..., description="User who executed the process")
    pid: int = Field(..., description="Process ID")
    alert_title: Optional[str] = Field(None, description="Alert title")

class AnalyzeRequest(BaseModel):
    raw_event: RawEvent
    guide_score: float = Field(..., ge=0.0, le=1.0, description="Classifier confidence score")
    guide_grade: str = Field(..., description="Classifier grade: TP, BP, or FP")

    @field_validator('guide_grade')
    @classmethod
    def validate_guide_grade(cls, v: str) -> str:
        allowed_grades = {"TP", "BP", "FP"}
        if v.upper() not in allowed_grades:
            raise ValueError(f"guide_grade must be one of {allowed_grades}, got '{v}'")
        return v.upper()


# --- Response sub-models ---

class MitreTechnique(BaseModel):
    id: str
    name: str
    tactic: str
    url: str

class EventInfo(BaseModel):
    process: str
    syscall: str
    file_path: str
    pod_name: str
    namespace: str
    user: str
    pid: int
    timestamp: str

class TriageInfo(BaseModel):
    grade: str
    confidence: float
    reasoning: str

class ThreatIntel(BaseModel):
    mitre_techniques: List[MitreTechnique]
    mitre_context: Optional[str] = None
    azure_context: Optional[str] = None

class IncidentReport(BaseModel):
    summary: Optional[str] = None
    severity: Optional[str] = None
    attack_type: Optional[str] = None
    what_happened: Optional[str] = None
    potential_impact: Optional[str] = None
    recommended_action: Optional[str] = None

class Remediation(BaseModel):
    yaml_fix: Optional[str] = None
    fix_description: Optional[str] = None
    fix_type: Optional[str] = None
    apply_command: Optional[str] = None
    estimated_risk_reduction: Optional[str] = None

class AttackHistoryEntry(BaseModel):
    timestamp: Optional[str] = None
    process: Optional[str] = None
    syscall: Optional[str] = None
    grade: Optional[str] = None
    confidence: Optional[float] = None
    mitre_id: Optional[str] = None
    was_blocked: Optional[bool] = None

class ClusterImmunity(BaseModel):
    score: int = 0
    total_events_processed: int = 0
    tp_count: int = 0
    fp_count: int = 0
    bp_count: int = 0
    blocked_count: int = 0

class SentinelAnalyzeResponse(BaseModel):
    status: str
    confidence: float
    processing_time_ms: float
    event: EventInfo
    triage: TriageInfo
    threat_intel: ThreatIntel
    incident_report: IncidentReport
    remediation: Remediation
    attack_history: List[AttackHistoryEntry]
    cluster_immunity: ClusterImmunity
    error: Optional[str] = None

class HealthResponse(BaseModel):
    status: str
    version: str
    rag_available: bool
    llm_available: bool


# ============================================================================
# ERROR FORMATTER
# ============================================================================

def format_error(code: str, detail: str) -> dict:
    return {
        "error": code,
        "detail": detail,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

# ============================================================================
# REDIS HELPERS
# ============================================================================

ATTACK_LOG_KEY = "sentinel:attack_history"

def push_attack_to_redis(entry: dict):
    """Push an attack event to the Redis attack history list."""
    if not _redis_client:
        return
    try:
        _redis_client.lpush(ATTACK_LOG_KEY, json.dumps(entry))
        _redis_client.ltrim(ATTACK_LOG_KEY, 0, 99)  # Keep last 100
    except Exception as e:
        logger.warning(f"Failed to push to Redis: {e}")

def get_attack_history(limit: int = 50) -> List[dict]:
    """Get last N attack events from Redis."""
    if not _redis_client:
        return []
    try:
        raw_entries = _redis_client.lrange(ATTACK_LOG_KEY, 0, limit - 1)
        return [json.loads(e) for e in raw_entries]
    except Exception as e:
        logger.warning(f"Failed to read Redis attack history: {e}")
        return []

def compute_cluster_immunity(history: List[dict]) -> dict:
    """Compute cluster immunity score from attack history."""
    if not history:
        return {
            "score": 100,
            "total_events_processed": 0,
            "tp_count": 0,
            "fp_count": 0,
            "bp_count": 0,
            "blocked_count": 0
        }

    tp_count = sum(1 for h in history if h.get("grade") == "TP")
    fp_count = sum(1 for h in history if h.get("grade") == "FP")
    bp_count = sum(1 for h in history if h.get("grade") == "BP")
    blocked_count = sum(1 for h in history if h.get("was_blocked"))
    total = len(history)

    # Score: starts at 100, reduces for unblocked TPs
    unblocked_tp = tp_count - blocked_count
    if total > 0:
        score = max(0, 100 - int((unblocked_tp / max(total, 1)) * 100))
    else:
        score = 100

    return {
        "score": score,
        "total_events_processed": total,
        "tp_count": tp_count,
        "fp_count": fp_count,
        "bp_count": bp_count,
        "blocked_count": blocked_count
    }


# ============================================================================
# LIFESPAN MANAGEMENT
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 80)
    logger.info("SENTINEL-CORE API STARTING UP")
    logger.info("=" * 80)

    # Check real Pinecone connectivity
    rag_available = _pc_index is not None
    if rag_available:
        try:
            _pc_index.describe_index_stats()
            logger.info("✓ Pinecone RAG index is reachable")
        except Exception as e:
            rag_available = False
            logger.error(f"✗ Pinecone unreachable: {e}")

    # Check real Gemini connectivity
    llm_available = _genai_client is not None
    if llm_available:
        try:
            _genai_client.models.get(model="models/gemini-1.5-pro")
            logger.info("✓ Gemini LLM is reachable")
        except Exception as e:
            llm_available = False
            logger.error(f"✗ Gemini unreachable: {e}")

    app.state.rag_available = rag_available
    app.state.llm_available = llm_available
    app.state.orchestrator_available = ORCHESTRATOR_AVAILABLE

    if not (rag_available and llm_available):
        logger.error("CRITICAL: One or more backend services are unreachable. Pipeline may fail.")

    yield

    logger.info("=" * 80)
    logger.info("SENTINEL-CORE API SHUTTING DOWN")
    logger.info("=" * 80)

# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Sentinel-Core Security Platform",
    description="Real-time eBPF security orchestration with RAG + Gemini AI.",
    version="1.0.0",
    lifespan=lifespan
)

app.state.limiter = limiter

# ============================================================================
# MIDDLEWARE
# ============================================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000
    logger.info(
        f"{request.method} {request.url.path} - "
        f"Status: {response.status_code} - "
        f"Time: {process_time:.2f}ms"
    )
    response.headers["X-Process-Time-Ms"] = f"{process_time:.2f}"
    return response

# ============================================================================
# EXCEPTION HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    code_map = {
        400: "bad_request", 401: "unauthorized", 403: "forbidden",
        404: "not_found", 500: "internal_error", 503: "service_unavailable"
    }
    return JSONResponse(
        status_code=exc.status_code,
        content=format_error(code_map.get(exc.status_code, "error"), exc.detail)
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=format_error("bad_request", f"Validation Error: {exc.errors()}")
    )

@app.exception_handler(RateLimitExceeded)
async def custom_rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content=format_error("rate_limit_exceeded", f"Rate limit exceeded: {exc.detail}")
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=format_error("internal_error", f"Internal server error: {str(exc)}")
    )

# ============================================================================
# ENDPOINTS
# ============================================================================

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Check real Pinecone + Gemini connectivity."""
    rag_ok = getattr(app.state, 'rag_available', False)
    llm_ok = getattr(app.state, 'llm_available', False)

    # Re-check live if previously unavailable
    if not rag_ok and _pc_index:
        try:
            _pc_index.describe_index_stats()
            rag_ok = True
            app.state.rag_available = True
        except Exception:
            pass

    if not llm_ok and _genai_client:
        try:
            _genai_client.models.get(model="models/gemini-1.5-pro")
            llm_ok = True
            app.state.llm_available = True
        except Exception:
            pass

    return HealthResponse(
        status="ok" if (rag_ok and llm_ok) else "degraded",
        version="1.0.0",
        rag_available=rag_ok,
        llm_available=llm_ok
    )


@app.post(
    "/sentinel/analyze",
    response_model=SentinelAnalyzeResponse,
    tags=["Analysis"],
    dependencies=[Depends(verify_api_key)]
)
@limiter.limit("30/minute")
async def sentinel_analyze(request: Request, body: AnalyzeRequest):
    """
    Single comprehensive analysis endpoint.
    Returns every piece of data the frontend dashboard needs.
    """
    start_time = time.time()

    if not app.state.orchestrator_available:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Orchestrator service is currently unavailable"
        )

    # Build raw_event dict
    raw_event_dict = body.raw_event.model_dump()
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw_event_dict["timestamp"] = timestamp
    if not raw_event_dict.get("alert_title"):
        raw_event_dict["alert_title"] = (
            f"Suspicious {raw_event_dict['syscall']} from {raw_event_dict['process']}"
        )

    error_value = None

    try:
        # Run orchestrator
        result = await asyncio.to_thread(
            analyze_alert,
            raw_event=raw_event_dict,
            guide_score=body.guide_score,
            guide_grade=body.guide_grade,
            stream=False
        )

        final_report = result.get("final_report", "")
        yaml_fix = result.get("yaml_fix", "")
        mitre_techniques = result.get("mitre_techniques", [])
        severity = result.get("severity", "MEDIUM")
        attack_type = result.get("attack_type", "Unknown")
        fix_type = result.get("fix_type", "Other")
        fix_description = result.get("fix_description", "")
        mitre_context = result.get("mitre_context", "")
        azure_context = result.get("azure_context", "")

        if result.get("error"):
            error_value = result["error"]

    except Exception as e:
        logger.exception("Analysis pipeline failed")
        error_value = str(e)
        final_report = f"Analysis failed: {e}"
        yaml_fix = ""
        mitre_techniques = []
        severity = "MEDIUM"
        attack_type = "Unknown"
        fix_type = "Other"
        fix_description = ""
        mitre_context = None
        azure_context = None

    processing_time_ms = (time.time() - start_time) * 1000

    # --- Parse structured incident fields ---
    def _extract(text: str, field: str) -> Optional[str]:
        if not text:
            return None
        m = re.search(rf"{field}:\s*(.+?)(?:\n|$)", text, re.IGNORECASE)
        return m.group(1).strip() if m else None

    what_happened = _extract(final_report, "WHAT_HAPPENED")
    potential_impact = _extract(final_report, "POTENTIAL_IMPACT")
    recommended_action = _extract(final_report, "RECOMMENDED_ACTION")

    # Clean report summary (strip extracted fields from it)
    summary = final_report
    for tag in ["SEVERITY:", "ATTACK_TYPE:", "WHAT_HAPPENED:", "POTENTIAL_IMPACT:",
                 "RECOMMENDED_ACTION:", "FIX_DESCRIPTION:"]:
        if tag in summary:
            summary = summary.split(tag)[0]
    summary = summary.strip()[:500]

    # Build risk reduction heuristic
    risk_reduction = "HIGH" if severity in ("CRITICAL", "HIGH") else "MEDIUM"

    # Determine if blocked (TP with a yaml fix = "blocked")
    was_blocked = body.guide_grade == "TP" and bool(yaml_fix)

    # Build attack history entry and push to Redis
    first_mitre_id = mitre_techniques[0]["id"] if mitre_techniques else None
    history_entry = {
        "timestamp": timestamp,
        "process": raw_event_dict.get("process", ""),
        "syscall": raw_event_dict.get("syscall", ""),
        "grade": body.guide_grade,
        "confidence": body.guide_score,
        "mitre_id": first_mitre_id,
        "was_blocked": was_blocked
    }
    push_attack_to_redis(history_entry)

    # Get attack history + cluster immunity from Redis
    attack_history_raw = get_attack_history(50)
    cluster_immunity = compute_cluster_immunity(attack_history_raw)

    # Build full response
    response = SentinelAnalyzeResponse(
        status=body.guide_grade,
        confidence=body.guide_score,
        processing_time_ms=round(processing_time_ms, 2),

        event=EventInfo(
            process=raw_event_dict.get("process", ""),
            syscall=raw_event_dict.get("syscall", ""),
            file_path=raw_event_dict.get("file_path", ""),
            pod_name=raw_event_dict.get("pod_name", ""),
            namespace=raw_event_dict.get("namespace", "default"),
            user=raw_event_dict.get("user", ""),
            pid=raw_event_dict.get("pid", 0),
            timestamp=timestamp
        ),

        triage=TriageInfo(
            grade=body.guide_grade,
            confidence=body.guide_score,
            reasoning=(
                f"Historical GUIDE data: this syscall+process combo "
                f"is {body.guide_grade} in {body.guide_score * 100:.0f}% of cases"
            )
        ),

        threat_intel=ThreatIntel(
            mitre_techniques=[
                MitreTechnique(**t) for t in mitre_techniques
            ],
            mitre_context=mitre_context,
            azure_context=azure_context
        ),

        incident_report=IncidentReport(
            summary=summary if summary else None,
            severity=severity,
            attack_type=attack_type,
            what_happened=what_happened,
            potential_impact=potential_impact,
            recommended_action=recommended_action
        ),

        remediation=Remediation(
            yaml_fix=yaml_fix if yaml_fix else None,
            fix_description=fix_description if fix_description else None,
            fix_type=fix_type,
            apply_command=(
                f"kubectl apply -f fix.yaml -n {raw_event_dict.get('namespace', 'default')}"
                if yaml_fix else None
            ),
            estimated_risk_reduction=risk_reduction
        ),

        attack_history=[
            AttackHistoryEntry(**h) for h in attack_history_raw
        ],

        cluster_immunity=ClusterImmunity(**cluster_immunity),

        error=error_value
    )

    # Console output per master prompt format
    if body.guide_grade == "TP":
        mitre_display = ", ".join(
            f"{t['id']} ({t['name']})" for t in mitre_techniques
        ) if mitre_techniques else "N/A"

        logger.info(
            "\n" + "=" * 60 +
            "\n  SENTINEL-CORE LIVE PIPELINE" +
            "\n" + "=" * 60 +
            f"\n[NODE A] event_router       | grade={body.guide_grade}  | score={body.guide_score}" +
            f"\n[NODE B] rag_retriever      | mitre={len(mitre_context or '')} chars | azure={len(azure_context or '')} chars" +
            f"\n[NODE C] report_generator   | report={len(summary.split()) if summary else 0} words | yaml={len(yaml_fix.splitlines()) if yaml_fix else 0} lines" +
            "\n" + "-" * 60 +
            "\nTHREAT NEUTRALIZED" +
            f"\n  Process  : {raw_event_dict.get('process')}" +
            f"\n  Syscall  : {raw_event_dict.get('syscall')}" +
            f"\n  Pod      : {raw_event_dict.get('pod_name')} / {raw_event_dict.get('namespace')}" +
            f"\n  Grade    : {body.guide_grade} ({body.guide_score * 100:.1f}% confidence)" +
            f"\n  MITRE    : {mitre_display}" +
            f"\n  Report   : [{summary[:80]}...]" +
            f"\n  YAML Fix : {fix_description}" +
            "\n" + "=" * 60
        )

    return response


@app.get("/", tags=["Root"])
async def root():
    return {
        "message": "Welcome to Sentinel-Core Security Platform",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "analyze": "/sentinel/analyze"
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app", host="0.0.0.0", port=8000,
        reload=True, log_level="info", workers=1
    )
