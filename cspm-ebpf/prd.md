# Execution PRD: Sentinel-Core (GUIDE-Integrated Edition)
**Target Execution Agent:** Gemini 3.1 Pro (Antigravity IDE)
**Project Scope:** Autonomous AI-Powered CSPM (Application Security)
**Team Structure:** Optimized for rapid iteration by a 4-to-5 member development team.
**Objective:** Ingest modular codebase components, install dependencies, wire the overarching application logic, and launch the autonomous cloud-native security platform.

---

## 1. System Architecture & Context
Sentinel-Core shifts security from "Alert-Only" to "Guided Autonomous Response." It intercepts kernel-level events, triages them using Microsoft GUIDE dataset intelligence, enforces immediate action, and generates AI-driven remediation steps.

### 1.1 Core Modules to Integrate
* **Module A: Telemetry (The Eyes):** Tetragon/eBPF JSON event stream watcher.
* **Module B: Triage Engine (The Logic):** Scikit-learn/XGBoost classifier trained on GUIDE.
* **Module C: Enforcement (The Muscle):** eBPF-LSM hook execution script.
* **Module D: Agentic Orchestrator (The Brain):** LangGraph + Gemini 1.5 Pro + RAG (ChromaDB/Pinecone).

---

## 2. Phase 1: Dependency Installation & Environment Setup
The agent must first establish the environment. Execute or generate bash scripts for the following installations:

### 2.1 System & Kernel Dependencies
* **eBPF & Tetragon:** Ensure the kernel supports BTF (BPF Type Format). Install Cilium Tetragon for syscall observability.
* **Kubernetes (Local/Test):** Minikube or kind for simulating the cluster environment and testing RBAC remediations.

### 2.2 Python Ecosystem (Requirements.txt)
Create a `requirements.txt` file with the following:
` ` `text
# Machine Learning & Triage
xgboost==2.0.3
scikit-learn==1.3.2
pandas==2.1.4
numpy==1.26.2

# AI & Orchestration
langchain==0.1.0
langgraph==0.0.15
google-genai==0.3.0
chromadb==0.4.22
sentence-transformers==2.2.2

# System Interfacing & API
fastapi==0.104.1
uvicorn==0.24.0
watchdog==3.0.0
` ` `

---

## 3. Phase 2: Codebase Integration Plan
To transform the modular functionalities into the unified user flow, the agent must construct a **Main Orchestrator Daemon (`sentinel_daemon.py`)** that connects the modules linearly.

### Step 3.1: Wire the Detection to Classification (A -> B)
* **Action:** Create a real-time log watcher (using `watchdog` or asyncio file reading) tailing the Tetragon JSON output (`/var/run/cilium/tetragon/tetragon.log`).
* **Logic:** Filter for high-risk syscalls (e.g., `execve`, `openat` on sensitive paths). Extract features matching the GUIDE schema (DetectorId, AlertTitle, User, Path).
* **Pass:** Send these features to the loaded XGBoost model (`triage_model.predict()`).

### Step 3.2: Wire Classification to Enforcement (B -> C)
* **Action:** Implement the routing logic based on the ML prediction.
* **Logic:**
    * `if grade == "TP"`: Trigger the eBPF-LSM kill script (`os.system("bpftool map update...")`) in <1ms.
    * `if grade == "BP"`: Pass to the logging queue for contextual reasoning.
    * `if grade == "FP"`: Drop the event silently to save human time.

### Step 3.3: Wire Enforcement to Agentic Reasoning (C -> D)
* **Action:** If a "TP" is triggered, construct a JSON payload with the event details and send it to the LangGraph Orchestrator.
* **Logic:** The LangGraph Agent queries ChromaDB (Vector DB containing MITRE ATT&CK v15+ and Azure Security Benchmarks) using the GUIDE `AlertTitle`.
    * Gemini formats the response: *"I neutralized a high-confidence threat... This matches MITRE technique..."*

### Step 3.4: Wire Reasoning to Remediation (Closing the Loop)
* **Action:** The LangGraph agent outputs a structured JSON containing the human-readable explanation AND the newly generated Kubernetes RBAC YAML.
* **Logic:** Expose an API endpoint (`/apply-fix`) that takes the YAML and applies it to the cluster (`kubectl apply -f temp_fix.yaml`), achieving "Cluster Immunity."

---

## 4. Phase 3: Execution & Run Protocol
Once the integration code is generated and saved, the agent should instruct the environment to start the system in the following order:

### 4.1 Initialization (The Baseline)
1.  **Start Vector DB:** Initialize ChromaDB and embed the local MITRE/Azure/GUIDE documents.
    * `python scripts/ingest_rag_data.py`
2.  **Load Baseline:** Run the environment scanner to establish the Cluster Immunity Score.
    * `python scripts/baseline_audit.py`

### 4.2 Start the Sentinel Daemon
1.  **Engage Muscle:** Start Tetragon with the custom LSM policies.
    * `sudo tetragon --bpf-lib /var/lib/tetragon/ ...`
2.  **Engage Brain:** Run the unified orchestrator script that listens to Tetragon and holds the ML/AI models in memory for sub-millisecond inference.
    * `sudo python3 sentinel_daemon.py`

### 4.3 Trigger the Demo Flow
To simulate the attack for the environment:
1.  Deploy a test pod: `kubectl run victim-pod --image=nginx`
2.  Execute the simulated attacker script: `kubectl exec -it victim-pod -- /bin/sh -c "cat /etc/shadow"`
3.  Observe the instantaneous eBPF kill, the XGBoost TP classification log, and the RAG-generated explanation in the terminal/dashboard.