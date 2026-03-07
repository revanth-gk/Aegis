#!/usr/bin/env python3
"""
Sentinel-Core Demo Runner
Starts the FastAPI server on :8080 and continuously replays fixture events.

Usage:
    python run_demo.py [--fixture PATH] [--delay SECONDS]
"""

import argparse
import json
import logging
import signal
import sys
import threading
import time
from pathlib import Path

# ── Logging ─────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-22s │ %(levelname)-5s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinel.demo")

# ── Parse args ──────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="Sentinel-Core Demo Runner")
parser.add_argument("--fixture", default="fixtures/sample-tetragon-raw.jsonl")
parser.add_argument("--delay", type=float, default=2.0, help="Seconds between events")
parser.add_argument("--loop-delay", type=float, default=10.0, help="Seconds between replay loops")
args = parser.parse_args()

# ── Imports (after args so --help works without heavy imports) ───────
try:
    import uvicorn
    from forwarder.api import app as fastapi_app
    from forwarder.api import record_event, record_error, set_ml_triage, set_redis_status
    from forwarder.config import Config
    from forwarder.publisher import EventPublisher
    from forwarder.transformer import transform_event
    from forwarder.ml_triage import MLTriage
    from forwarder import main as forwarder_main
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("   Run: source .venv/bin/activate")
    sys.exit(1)

# ── Config ──────────────────────────────────────────────────────────
config = Config()
config.API_PORT = 8080  # Must match Vite proxy

_shutdown = threading.Event()


def _handle_signal(signum, frame):
    logger.info("🛑 Signal %d received — shutting down gracefully…", signum)
    _shutdown.set()


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ── API Server thread ────────────────────────────────────────────────
def start_api():
    uvicorn.run(
        fastapi_app,
        host="0.0.0.0",
        port=8080,
        log_level="warning",
        access_log=False,
    )


api_thread = threading.Thread(target=start_api, daemon=True, name="api-server")
api_thread.start()
logger.info("🌐 API server starting on http://0.0.0.0:8080 …")
time.sleep(1.5)  # Wait for uvicorn to bind

# ── Publisher (Redis optional) ───────────────────────────────────────
publisher = EventPublisher(config)
set_redis_status(publisher.is_connected)
if publisher.is_connected:
    logger.info("✅ Redis connected — events will be published to stream")
else:
    logger.info("⚠️  Redis not available — events logged to stdout only")

# ── ML Triage ───────────────────────────────────────────────────────
ml = MLTriage(
    model_path=Path(config.ML_MODEL_PATH),
    feature_list_path=Path(config.FEATURE_LIST_PATH),
)
set_ml_triage(ml)
forwarder_main._ml_triage = ml
logger.info("🤖 ML Triage model loaded from %s", config.ML_MODEL_PATH)

# ── Fixture loading ──────────────────────────────────────────────────
fixture_path = Path(args.fixture)
if not fixture_path.exists():
    logger.error("❌ Fixture file not found: %s", fixture_path)
    sys.exit(1)

lines = [l.strip() for l in fixture_path.read_text().splitlines() if l.strip()]
logger.info("📂 Loaded %d fixture events from %s", len(lines), fixture_path)

# ── Print startup banner ────────────────────────────────────────────
print()
print("╔════════════════════════════════════════════════════════════╗")
print("║           🛡️  Sentinel-Core Backend is RUNNING             ║")
print("╠════════════════════════════════════════════════════════════╣")
print(f"║  API : http://localhost:8080                               ║")
print(f"║  Events per loop  : {len(lines):<5}                              ║")
print(f"║  Delay between    : {args.delay:.1f}s                               ║")
print(f"║  Loop rest period : {args.loop_delay:.1f}s                             ║")
print("╠════════════════════════════════════════════════════════════╣")
print("║  Open dashboard   : http://localhost:5173                  ║")
print("║  Press Ctrl+C to stop                                      ║")
print("╚════════════════════════════════════════════════════════════╝")
print()

# ── Main replay loop ─────────────────────────────────────────────────
loop = 1
try:
    while not _shutdown.is_set():
        logger.info("━━━ Loop #%d — replaying %d events ━━━", loop, len(lines))
        for i, line in enumerate(lines, 1):
            if _shutdown.is_set():
                break
            try:
                forwarder_main.process_line(line, publisher)
            except Exception as e:
                logger.warning("Error processing line %d: %s", i, e)
                record_error()
            time.sleep(args.delay)

        if _shutdown.is_set():
            break

        logger.info(
            "✅ Loop #%d complete — %d events sent — resting %ds…",
            loop, len(lines), int(args.loop_delay)
        )
        _shutdown.wait(timeout=args.loop_delay)
        loop += 1

finally:
    logger.info("👋 Cleaning up…")
    try:
        publisher.close()
    except Exception:
        pass
    logger.info("🛑 Demo runner stopped.")
