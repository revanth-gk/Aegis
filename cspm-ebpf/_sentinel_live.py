import sys
import time
import json
import logging
import threading
from pathlib import Path

# Suppress noisy library logs
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("sentence_transformers").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

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

# ML Triage - Try huge model if exists, fallback to config
huge_model = Path("xgboost_model.json")
if huge_model.exists() and huge_model.stat().st_size > 1000000:
    logger.info("🧠 Found high-capacity model in root. Overriding config.")
    ml_path = huge_model
else:
    ml_path = Path(config.ML_MODEL_PATH)

ml = MLTriage(
    model_path=ml_path,
    feature_list_path=Path(config.FEATURE_LIST_PATH)
)
set_ml_triage(ml)
forwarder.main._ml_triage = ml

# Publisher
pub = EventPublisher(config)
set_redis_status(pub.is_connected)

# RAG check
try:
    from orchestrator import analyze_alert, ORCHESTRATOR_AVAILABLE
    rag_enabled = ORCHESTRATOR_AVAILABLE
except ImportError:
    rag_enabled = False

print("\n🚀 Sentinel API: http://127.0.0.1:8081")
print("📡 Pipeline INITIALIZED and monitoring events...")

event_count = 0
try:
    for line in sys.stdin:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            sentinel_event = process_line(line, pub)
            if sentinel_event:
                event_count += 1
                triage = sentinel_event.get("triage", {})
                grade = triage.get("grade", "UNKNOWN")
                score = float(triage.get("confidence", 0.0))

                if rag_enabled and grade in ("TP", "BP") and event_count <= 20:
                    try:
                        raw = json.loads(line)
                        analyze_alert(raw_event=raw, guide_score=score, guide_grade=grade, stream=False)
                    except Exception as orch_err:
                        logger.warning("Orchestrator error: %s", orch_err)
        except Exception as e:
            logger.error("Event decode error: %s", e)

except KeyboardInterrupt:
    logger.info("Pipeline terminated.")
    pub.close()
    sys.exit(0)
