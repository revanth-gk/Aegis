# Implementation Plan

## 1. Remediation Agent Port Fix
*   Update `.env` and `.env.example` to set `REMEDIATION_PORT=8002` (or hardcode in the running script config if necessary).
*   Check `remediation/main.py` (or equivalent startup file) to ensure it uses the updated port.
*   Update `orchestrator.py` or any scripts that depend on the `8002` port.

## 2. Attacker Pod Enhancement
*   The attacker pod already runs `sleep 3600`. We don't need to change the pod definition itself. 
*   We'll create a new backend service specifically to execute `kubectl exec` commands against this pod.

## 3. Minimal Control Dashboard (Backend)
*   Create a new directory `attacker-dashboard/`.
*   Create `attacker-dashboard/app.py` using FastAPI.
*   Add endpoints: `/api/fire/tp`, `/api/fire/fp`, `/api/fire/bp`, `/api/fire/loop/start`, `/api/fire/loop/stop`.
*   TP Payloads (True Positive): Use commands from `demo_attacks.sh` (e.g., `wget httpbin.org`, `cat /etc/shadow`, `nc reverse shell`).
*   FP Payloads (False Positive): Suspicious but allowed (e.g., a dev process reading a config).
*   BP Payloads (Benign Positive): Normal system behavior (e.g., `apt update`, `curl localhost`).

## 4. Minimal Control Dashboard (Frontend)
*   Create `attacker-dashboard/static/index.html`.
*   Aesthetic: "Cybersecurity Utilitarian" (dark background `#0a0a0c`, monospace fonts `@font-face` like JetBrains Mono or local monospace fallbacks, neon terminal green/cyan accents).
*   Structure:
    *   Title/Header.
    *   Payload buttons (TP, FP, BP).
    *   Continuous Fire toggle.
    *   Mock terminal output to show results of the fired attacks.
*   JS Logic to call the backend APIs and update the terminal.

## 5. Script Updates
*   Update `start_app.sh` or create `start_attacker_dashboard.sh`.
*   Update documentation (`README.md` or similar) noting the new dashboard port `8003`.
