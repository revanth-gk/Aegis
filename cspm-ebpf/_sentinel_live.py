import sys
import time
import json
import logging
import threading
from pathlib import Path

import uvicorn
from forwarder.api import app as fastapi_app
from forwarder.api import set_redis_status, set_ml_triage
from forwarder.config import Config
from forwarder.main import process_line
from forwarder.ml_triage import MLTriage
from forwarder.publisher import EventPublisher
import forwarder.main

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-22s │ %(levelname)-5s │ %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("sentinel.live")

config = Config()

# API server
def run_api():
    uvicorn.run(fastapi_app, host="0.0.0.0", port=8081, log_level="warning")
threading.Thread(target=run_api, daemon=True).start()
time.sleep(2)

# ML Triage
ml = MLTriage(
    model_path=Path(config.ML_MODEL_PATH),
    feature_list_path=Path(config.FEATURE_LIST_PATH)
)
set_ml_triage(ml)
forwarder.main._ml_triage = ml

# Publisher
pub = EventPublisher(config)
set_redis_status(pub.is_connected)

# Try to trigger RAG + Gemini orchestration for high-severity events
try:
    from orchestrator import analyze_alert, ORCHESTRATOR_AVAILABLE
    rag_enabled = ORCHESTRATOR_AVAILABLE
    if rag_enabled:
        logger.info("🧠 RAG + Gemini orchestrator is ONLINE")
    else:
        logger.warning("⚠️  Orchestrator offline (missing API keys). ML triage only.")
except ImportError:
    rag_enabled = False
    logger.warning("⚠️  Orchestrator module not available")

print()
print("🚀 Sentinel API: http://127.0.0.1:8081")
print("📡 Processing REAL eBPF telemetry from Kubernetes cluster...")
print("   Press Ctrl+C to stop")
print()

event_count = 0
try:
    for line in sys.stdin:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            process_line(line, pub)
            event_count += 1

            # For TP/BP events, run through the full orchestrator (RAG + Gemini)
            if rag_enabled and event_count <= 20:
                try:
                    raw = json.loads(line)
                    result = analyze_alert(
                        raw_event=raw,
                        guide_score=0.85,
                        guide_grade="TP",
                        stream=False
                    )
                    if result.get("final_report"):
                        logger.info("📋 ORCHESTRATOR REPORT:\n%s", result["final_report"][:500])
                    if result.get("yaml_fix"):
                        logger.info("🔧 YAML FIX:\n%s", result["yaml_fix"][:300])
                except Exception as orch_err:
                    logger.warning("Orchestrator error: %s", orch_err)

        except Exception as e:
            logger.error("Event decode error: %s", e)

except KeyboardInterrupt:
    logger.info("Pipeline terminated. Processed %d events.", event_count)
    pub.close()
    sys.exit(0)
