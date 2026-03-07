#!/bin/bash
source .venv/bin/activate
export PATH="$PWD/bin:$PATH"

echo "Starting Sentinel-Core Live Event Forwarder..."
echo "Streaming events from kind-sentinel-cluster via eBPF Tetragon"
echo "--------------------------------------------------------"

cat << 'PYEOF' > live_backend.py
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

# Output logs
logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(name)-22s │ %(levelname)-5s │ %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("sentinel.live")

config = Config()

# Start API
def run_api():
    uvicorn.run(fastapi_app, host="0.0.0.0", port=8081, log_level="warning")
threading.Thread(target=run_api, daemon=True).start()

# Let HTTP API bind to port 8081 fully
time.sleep(2)

# Load Triage Engine
ml = MLTriage(
    model_path=Path(config.ML_MODEL_PATH),
    feature_list_path=Path(config.FEATURE_LIST_PATH)
)
set_ml_triage(ml)
forwarder.main._ml_triage = ml

# Ensure Publisher
pub = EventPublisher(config)
set_redis_status(pub.is_connected)

print(f"\n🚀 API live at http://127.0.0.1:8081")
print(f"📥 Awaiting live tetragon pipe...\n")

try:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            # We skip some internal noise from tetragon startup text if it's not JSON
            if not line.startswith("{"):
                continue
            process_line(line, pub)
        except Exception as e:
            logger.error(f"Event decode error: {e}")
except KeyboardInterrupt:
    logger.info("Pipeline terminated")
    pub.close()
    sys.exit(0)
PYEOF

kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | python live_backend.py
