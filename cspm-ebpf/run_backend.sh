#!/usr/bin/env bash
# Sentinel-Core — Backend Launcher
# Activates venv, sets API_PORT=8080 to match the Vite proxy, then starts demo runner.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

source .venv/bin/activate

# Load .env if it exists (Google API, Pinecone keys, etc.)
set -o allexport
source .env 2>/dev/null || true
set +o allexport

# Override port to match Vite proxy
export API_PORT=8080
export PYTHONPATH="$SCRIPT_DIR"

exec python run_demo.py "$@"
