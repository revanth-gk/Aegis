#!/usr/bin/env python3
"""
Sentinel-Core Security Orchestration System — LangGraph Module

Pipeline nodes:
  Node A: event_router   — Routes alerts based on classifier grade
  Node B: rag_retriever   — Enriches alerts with MITRE + Azure context from Pinecone
  Node C: report_generator — Generates incident report + YAML fix via Gemini LLM

Public API:
  analyze_alert(raw_event, guide_score, guide_grade, stream=False) -> dict
"""

import os
import re
import json
import yaml
import logging
import time
import traceback
from typing import TypedDict, Optional, List, Dict, Any
from dotenv import load_dotenv

from langgraph.graph import StateGraph, END
from pinecone import Pinecone
from google import genai
from langchain_google_genai import ChatGoogleGenerativeAI

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

LLM_MODEL = os.getenv("LLM_MODEL", "gemini-1.5-pro")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
PINECONE_INDEX_HOST = os.getenv("PINECONE_INDEX_HOST")
GOOGLE_EMBEDDING_MODEL = "text-embedding-004"

MITRE_TOP_K = 3
AZURE_TOP_K = 2
OFFLINE_MODE = os.getenv("OFFLINE_MODE", "false").lower() == "true"

# ============================================================================
# THREAD-SAFE GLOBAL INITIALIZATION
# ============================================================================

ORCHESTRATOR_AVAILABLE = False
_genai_client = None
_pc_client = None
_pc_index = None
_llm = None

# --- Gemini Client (new google-genai SDK) ---
if GOOGLE_API_KEY and not OFFLINE_MODE:
    try:
        _genai_client = genai.Client(api_key=GOOGLE_API_KEY)
        _llm = ChatGoogleGenerativeAI(
            model=LLM_MODEL,
            api_key=GOOGLE_API_KEY,
            temperature=0.3,
            max_tokens=2000
        )
        ORCHESTRATOR_AVAILABLE = True
        logger.info("Gemini client initialized successfully (google-genai SDK)")
    except Exception as e:
        logger.exception("Failed to initialize Gemini client")
else:
    logger.warning("GOOGLE_API_KEY not set or OFFLINE_MODE. Generative AI disabled.")

# --- Pinecone Client (v3 SDK) ---
if PINECONE_API_KEY and PINECONE_INDEX_HOST and not OFFLINE_MODE:
    try:
        _pc_client = Pinecone(api_key=PINECONE_API_KEY)
        _pc_index = _pc_client.Index(host=PINECONE_INDEX_HOST)
        logger.info(f"Pinecone index connected via host: {PINECONE_INDEX_HOST}")
    except Exception as e:
        logger.exception("Failed to initialize Pinecone client")
else:
    logger.warning("Pinecone keys not set or OFFLINE_MODE. RAG disabled.")

# ============================================================================
# STATE SCHEMA
# ============================================================================

class SentinelState(TypedDict):
    raw_event: dict
    guide_score: float
    guide_grade: str
    stream: bool
    mitre_context: str
    azure_context: str
    mitre_techniques: list          # list of dicts: {id, name, tactic, url}
    final_report: str
    yaml_fix: str
    severity: str
    attack_type: str
    fix_type: str
    fix_description: str
    error: str

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

MITRE_TECHNIQUE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")

def generate_safe_default_yaml(raw_event: dict) -> str:
    """Generates a safe default K8s YAML if generation fails."""
    pod_name = raw_event.get("pod_name", raw_event.get("pod", "affected-pod"))
    namespace = raw_event.get("namespace", "default")
    return f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-{pod_name}-egress
  namespace: {namespace}
spec:
  podSelector:
    matchLabels:
      app: {pod_name}
  policyTypes:
  - Egress
  - Ingress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
  ingress: []
---
apiVersion: v1
kind: Pod
metadata:
  name: {pod_name}
  namespace: {namespace}
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: {pod_name}
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL"""


def robust_yaml_extract(text: str, raw_event: dict) -> str:
    """Robustly extracts YAML block and validates with pyyaml."""
    yaml_str = None

    for pattern in [r"```yaml\s*(.*?)\s*```", r"```YAML\s*(.*?)\s*```"]:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            yaml_str = match.group(1).strip()
            break

    if not yaml_str and "apiVersion:" in text:
        yaml_str = "apiVersion:" + text.split("apiVersion:", 1)[1]
        if "```" in yaml_str:
            yaml_str = yaml_str.split("```")[0].strip()

    if not yaml_str:
        gen_match = re.search(r"```\s*(.*?)\s*```", text, re.DOTALL)
        if gen_match and "apiVersion:" in gen_match.group(1):
            yaml_str = gen_match.group(1).strip()

    if yaml_str:
        try:
            yaml.safe_load(yaml_str)
            return yaml_str
        except yaml.YAMLError as e:
            logger.warning(f"Extracted YAML was invalid: {e}")

    logger.warning("Falling back to safe default YAML template.")
    return generate_safe_default_yaml(raw_event)


def extract_mitre_techniques(text: str) -> list:
    """Extract MITRE technique IDs from text and return structured objects."""
    raw_ids = list(set(MITRE_TECHNIQUE_PATTERN.findall(text)))

    # Well-known technique name mapping (subset for common attacks)
    KNOWN_TECHNIQUES = {
        "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
        "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
        "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
        "T1059.004": {"name": "Command and Scripting Interpreter: Unix Shell", "tactic": "Execution"},
        "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
        "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
        "T1003.008": {"name": "OS Credential Dumping: /etc/passwd and /etc/shadow", "tactic": "Credential Access"},
        "T1057": {"name": "Process Discovery", "tactic": "Discovery"},
        "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
        "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
        "T1048.003": {"name": "Exfiltration Over Unencrypted Non-C2 Protocol", "tactic": "Exfiltration"},
        "T1095": {"name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
        "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
        "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
        "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
        "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
        "T1552.001": {"name": "Unsecured Credentials: Credentials In Files", "tactic": "Credential Access"},
        "T1611": {"name": "Escape to Host", "tactic": "Privilege Escalation"},
        "T1610": {"name": "Deploy Container", "tactic": "Defense Evasion"},
    }

    techniques = []
    for tid in raw_ids:
        info = KNOWN_TECHNIQUES.get(tid, {"name": "Unknown Technique", "tactic": "Unknown"})
        base_id = tid.split(".")[0]
        sub = tid.replace(".", "/") if "." in tid else tid
        techniques.append({
            "id": tid,
            "name": info["name"],
            "tactic": info["tactic"],
            "url": f"https://attack.mitre.org/techniques/{sub}/"
        })

    return techniques


def infer_severity(guide_grade: str, guide_score: float) -> str:
    """Infer severity from grade + confidence."""
    if guide_grade == "FP":
        return "LOW"
    if guide_grade == "BP":
        return "MEDIUM" if guide_score > 0.7 else "LOW"
    # TP
    if guide_score >= 0.9:
        return "CRITICAL"
    elif guide_score >= 0.7:
        return "HIGH"
    elif guide_score >= 0.5:
        return "MEDIUM"
    return "LOW"


def infer_attack_type(raw_event: dict) -> str:
    """Infer attack type from syscall + process."""
    syscall = raw_event.get("syscall", "").lower()
    process = raw_event.get("process", "").lower()
    file_path = raw_event.get("file_path", "").lower()

    if "shadow" in file_path or "passwd" in file_path:
        return "Credential Access"
    if process in ("curl", "wget") and syscall == "connect":
        return "Command and Control"
    if process in ("nc", "ncat", "netcat") or "reverse" in process:
        return "Reverse Shell"
    if process in ("ps", "top", "netstat", "ss") and syscall == "execve":
        return "Discovery"
    if syscall == "connect" and "53" in str(raw_event.get("file_path", "")):
        return "Data Exfiltration"
    if syscall == "execve":
        return "Execution"
    if syscall == "openat":
        return "File Access"
    return "Suspicious Activity"


def infer_fix_type(yaml_text: str) -> str:
    """Infer the fix type from YAML content."""
    if "NetworkPolicy" in yaml_text:
        return "NetworkPolicy"
    if "securityContext" in yaml_text or "PodSecurity" in yaml_text:
        return "PodSecurityContext"
    if "Role" in yaml_text or "ClusterRole" in yaml_text:
        return "RBAC"
    return "Other"


# ============================================================================
# NODES
# ============================================================================

def event_router(state: SentinelState) -> dict:
    """Node A: Route alerts based on classifier grade."""
    start_time = time.time()

    try:
        guide_grade = state.get("guide_grade", "")
        guide_score = state.get("guide_score", 0.0)

        if guide_grade == "FP":
            result = {
                **state,
                "final_report": "Auto-suppressed: False Positive. No action needed.",
                "yaml_fix": "",
                "severity": "LOW",
                "attack_type": "None (False Positive)",
                "fix_type": "None",
                "fix_description": "No remediation needed for false positive alerts."
            }
        elif guide_grade == "BP":
            result = {
                **state,
                "mitre_context": f"[AUDIT LOG] BP classification at {guide_score} confidence"
            }
        else:
            result = state

        duration = (time.time() - start_time) * 1000
        logger.info(
            f"[NODE A] event_router       | grade={guide_grade}  "
            f"| score={guide_score} | {duration:.0f}ms"
        )
        return result
    except Exception as e:
        duration = (time.time() - start_time) * 1000
        logger.exception(f"[NODE A] event_router FAILED | {duration:.0f}ms")
        return {**state, "error": str(e), "final_report": f"Error in event_router: {e}"}


def rag_retriever(state: SentinelState) -> dict:
    """Node B: Retrieve MITRE + Azure context from Pinecone."""
    start_time = time.time()

    try:
        if state.get("final_report", "").startswith("Auto-suppressed"):
            duration = (time.time() - start_time) * 1000
            logger.info(f"[NODE B] rag_retriever      | SKIPPED (suppressed) | {duration:.0f}ms")
            return state

        if not _pc_index or not _genai_client:
            raise RuntimeError("Pinecone or Gemini client not initialized.")

        raw_event = state.get("raw_event", {})
        process_name = raw_event.get("process", "unknown_process")
        syscall = raw_event.get("syscall", "unknown_syscall")
        file_path = raw_event.get("file_path", raw_event.get("path", "unknown_path"))
        alert_title = raw_event.get("alert_title", f"{process_name} {syscall} alert")

        mitre_query = f"{process_name} {syscall} {file_path}"
        azure_query = alert_title

        # --- MITRE retrieval ---
        mitre_context = "No MITRE ATT&CK context found."
        try:
            m_result = _genai_client.models.embed_content(
                model=GOOGLE_EMBEDDING_MODEL,
                contents=mitre_query
            )
            m_vec = m_result.embeddings[0].values
            mitre_results = _pc_index.query(
                vector=m_vec, top_k=MITRE_TOP_K,
                namespace="mitre", include_metadata=True
            )
            mitre_texts = []
            for match in mitre_results.get('matches', []):
                meta = match.get('metadata', {})
                text = meta.get('text', '')
                tid = meta.get('technique_id', '')
                if text:
                    mitre_texts.append(f"[{tid}] {text}" if tid else text)
            if mitre_texts:
                mitre_context = "\n".join(mitre_texts)
        except Exception as e:
            logger.warning(f"MITRE retrieval failed: {e}")
            mitre_context = f"Error retrieving MITRE context: {e}"

        # --- Azure retrieval ---
        azure_context = "No Azure Security Benchmark context found."
        try:
            a_result = _genai_client.models.embed_content(
                model=GOOGLE_EMBEDDING_MODEL,
                contents=azure_query
            )
            a_vec = a_result.embeddings[0].values
            azure_results = _pc_index.query(
                vector=a_vec, top_k=AZURE_TOP_K,
                namespace="azure", include_metadata=True
            )
            azure_texts = [
                m.get('metadata', {}).get('text', '')
                for m in azure_results.get('matches', [])
                if m.get('metadata', {}).get('text')
            ]
            if azure_texts:
                azure_context = "\n".join(azure_texts)
        except Exception as e:
            logger.warning(f"Azure retrieval failed: {e}")
            azure_context = f"Error retrieving Azure context: {e}"

        duration = (time.time() - start_time) * 1000
        logger.info(
            f"[NODE B] rag_retriever      | mitre={len(mitre_context)} chars "
            f"| azure={len(azure_context)} chars | {duration:.0f}ms"
        )

        return {**state, "mitre_context": mitre_context, "azure_context": azure_context}
    except Exception as e:
        duration = (time.time() - start_time) * 1000
        logger.exception(f"[NODE B] rag_retriever FAILED | {duration:.0f}ms")
        return {**state, "error": str(e), "final_report": f"Error in rag_retriever: {e}"}


def report_generator(state: SentinelState) -> dict:
    """Node C: Generate incident report + YAML fix via Gemini LLM."""
    start_time = time.time()

    try:
        if state.get("final_report", "").startswith("Auto-suppressed"):
            duration = (time.time() - start_time) * 1000
            logger.info(f"[NODE C] report_generator   | SKIPPED (suppressed) | {duration:.0f}ms")
            return state

        raw_event = state.get("raw_event", {})
        guide_score = state.get("guide_score", 0.0)
        guide_grade = state.get("guide_grade", "UNKNOWN")
        mitre_context = state.get("mitre_context", "No MITRE context available.")
        azure_context = state.get("azure_context", "No Azure context available.")

        process_name = raw_event.get("process", "unknown")
        syscall = raw_event.get("syscall", "unknown")
        file_path = raw_event.get("file_path", raw_event.get("path", "unknown"))
        timestamp = raw_event.get("timestamp", "unknown")
        pod_name = raw_event.get("pod_name", raw_event.get("pod", "unknown"))
        namespace = raw_event.get("namespace", "default")

        severity = infer_severity(guide_grade, guide_score)
        attack_type = infer_attack_type(raw_event)

        if not _llm:
            logger.info("LLM not configured. Using offline fallback.")
            yaml_fix = generate_safe_default_yaml(raw_event)
            offline_report = (
                f"Process '{process_name}' triggered '{syscall}' on '{file_path}' "
                f"in pod '{pod_name}/{namespace}'. "
                f"Grade: {guide_grade} ({guide_score:.2f} confidence). "
                f"Severity: {severity}. Attack type: {attack_type}."
            )
            fix_type = infer_fix_type(yaml_fix)
            duration = (time.time() - start_time) * 1000
            logger.info(f"[NODE C] report_generator   | OFFLINE | report={len(offline_report)} chars | {duration:.0f}ms")
            return {
                **state,
                "final_report": offline_report,
                "yaml_fix": yaml_fix,
                "severity": severity,
                "attack_type": attack_type,
                "fix_type": fix_type,
                "fix_description": f"Restricts network egress and applies security context hardening for pod '{pod_name}'.",
                "mitre_techniques": extract_mitre_techniques(mitre_context)
            }

        user_prompt = f"""SECURITY ALERT ANALYSIS REQUEST

EVENT DETAILS:
- Process: {process_name}
- Syscall: {syscall}
- File/Path Accessed: {file_path}
- Pod: {pod_name}
- Namespace: {namespace}
- Timestamp: {timestamp}

CLASSIFIER INFORMATION:
- Grade: {guide_grade}
- Confidence Score: {guide_score}

MITRE ATT&CK CONTEXT:
{mitre_context}

AZURE SECURITY BENCHMARK CONTEXT:
{azure_context}

TASK:
Analyze this security alert and provide:
1. A concise incident report (max 200 words) explaining the threat, its MITRE technique mapping, and potential impact
2. A structured analysis with these exact fields (one per line, use the prefix labels):
   SEVERITY: CRITICAL or HIGH or MEDIUM or LOW
   ATTACK_TYPE: short label (e.g. "Privilege Escalation", "Command and Control")
   WHAT_HAPPENED: one sentence
   POTENTIAL_IMPACT: one sentence
   RECOMMENDED_ACTION: one sentence
3. A specific Kubernetes YAML patch to remediate or mitigate this issue
4. A plain English description of what the YAML fix does (prefix with FIX_DESCRIPTION:)

Format your response as:
REPORT: [Your incident report here]

SEVERITY: [value]
ATTACK_TYPE: [value]
WHAT_HAPPENED: [value]
POTENTIAL_IMPACT: [value]
RECOMMENDED_ACTION: [value]
FIX_DESCRIPTION: [value]

YAML FIX:
```yaml
[Your Kubernetes YAML patch here]
```"""

        system_prompt = (
            "You are Sentinel-Core's AI Security Analyst. You write precise, "
            "expert-level incident reports for SOC teams. Be concise. Always cite "
            "MITRE technique IDs. Always end with a YAML fix."
        )

        stream_enabled = state.get("stream", False)
        full_response = ""

        if stream_enabled:
            logger.info("Streaming enabled — generating report token-by-token...")
            for chunk in _llm.stream(f"{system_prompt}\n\n{user_prompt}"):
                content = chunk.content if hasattr(chunk, 'content') else str(chunk)
                print(content, end="", flush=True)
                full_response += content
            print()
        else:
            response = _llm.invoke(f"{system_prompt}\n\n{user_prompt}")
            full_response = response.content if hasattr(response, 'content') else str(response)

        # Parse report
        yaml_marker = "```yaml"
        if yaml_marker in full_response.lower():
            report_part = re.split(r"```[yY][aA][mM][lL]", full_response)[0].replace("REPORT:", "").strip()
        else:
            report_part = full_response.replace("REPORT:", "").strip()

        final_report = report_part[:2000]
        yaml_fix = robust_yaml_extract(full_response, raw_event)

        # Extract structured fields from LLM response
        def extract_field(text: str, field: str, default: str) -> str:
            pattern = rf"{field}:\s*(.+?)(?:\n|$)"
            match = re.search(pattern, text, re.IGNORECASE)
            return match.group(1).strip() if match else default

        llm_severity = extract_field(full_response, "SEVERITY", severity)
        if llm_severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity = llm_severity

        llm_attack_type = extract_field(full_response, "ATTACK_TYPE", attack_type)
        if llm_attack_type and llm_attack_type != attack_type:
            attack_type = llm_attack_type

        fix_description = extract_field(
            full_response, "FIX_DESCRIPTION",
            f"Applies security hardening to pod '{pod_name}' in namespace '{namespace}'."
        )

        fix_type = infer_fix_type(yaml_fix)

        # Extract MITRE techniques from both report and RAG context
        all_text = f"{final_report}\n{mitre_context}"
        mitre_techniques = extract_mitre_techniques(all_text)

        duration = (time.time() - start_time) * 1000
        logger.info(
            f"[NODE C] report_generator   | report={len(final_report.split())} words "
            f"| yaml={len(yaml_fix.splitlines())} lines | {duration:.0f}ms"
        )

        return {
            **state,
            "final_report": final_report,
            "yaml_fix": yaml_fix,
            "severity": severity,
            "attack_type": attack_type,
            "fix_type": fix_type,
            "fix_description": fix_description,
            "mitre_techniques": mitre_techniques
        }
    except Exception as e:
        duration = (time.time() - start_time) * 1000
        logger.exception(f"[NODE C] report_generator FAILED | {duration:.0f}ms")
        yaml_fix = generate_safe_default_yaml(state.get("raw_event", {}))
        return {
            **state,
            "error": str(e),
            "final_report": f"Error in report_generator: {e}",
            "yaml_fix": yaml_fix,
            "severity": infer_severity(state.get("guide_grade", "TP"), state.get("guide_score", 0.5)),
            "attack_type": infer_attack_type(state.get("raw_event", {})),
            "fix_type": infer_fix_type(yaml_fix),
            "fix_description": "Default security hardening applied due to report generation failure.",
            "mitre_techniques": []
        }


# ============================================================================
# GRAPH ROUTING & CONSTRUCTION
# ============================================================================

def continue_or_end(state: SentinelState) -> str:
    if state.get("error") or state.get("final_report", "").startswith("Auto-suppressed"):
        return END
    return "rag_retriever"

def rag_or_end(state: SentinelState) -> str:
    if state.get("error"):
        return END
    return "report_generator"

def report_or_end(state: SentinelState) -> str:
    return END

def build_sentinel_graph() -> StateGraph:
    logger.info("Building Sentinel-Core LangGraph workflow...")
    workflow = StateGraph(SentinelState)
    workflow.add_node("event_router", event_router)
    workflow.add_node("rag_retriever", rag_retriever)
    workflow.add_node("report_generator", report_generator)

    workflow.set_entry_point("event_router")

    workflow.add_conditional_edges("event_router", continue_or_end)
    workflow.add_conditional_edges("rag_retriever", rag_or_end)
    workflow.add_conditional_edges("report_generator", report_or_end)

    logger.info("LangGraph workflow built successfully")
    return workflow.compile()


# ============================================================================
# PUBLIC API
# ============================================================================

_shared_graph = build_sentinel_graph()


def analyze_alert(raw_event: dict, guide_score: float, guide_grade: str, stream: bool = False) -> dict:
    """
    Public API for analyzing a security alert through the full pipeline.

    Args:
        raw_event: Dictionary describing the security event.
        guide_score: Confidence score from the classifier (0.0-1.0).
        guide_grade: Triage grade ('TP', 'BP', 'FP').
        stream: Whether to stream LLM generation tokens to stdout.

    Returns:
        A dict containing final_report, yaml_fix, severity, attack_type,
        fix_type, fix_description, mitre_techniques, and error fields.
    """
    initial_state: SentinelState = {
        "raw_event": raw_event,
        "guide_score": guide_score,
        "guide_grade": guide_grade,
        "stream": stream,
        "mitre_context": "",
        "azure_context": "",
        "mitre_techniques": [],
        "final_report": "",
        "yaml_fix": "",
        "severity": "",
        "attack_type": "",
        "fix_type": "",
        "fix_description": "",
        "error": ""
    }

    initial_state["stream"] = stream
    return _shared_graph.invoke(initial_state)


if __name__ == "__main__":
    print("=" * 80)
    print("SENTINEL-CORE ORCHESTRATOR — TEST MODE")
    print("=" * 80)

    mock_event = {
        "process": "runc",
        "syscall": "execve",
        "file_path": "/bin/sh",
        "pod_name": "vulnerable-app-7d8f9c",
        "namespace": "production",
        "timestamp": "2026-03-06T14:32:15Z",
        "alert_title": "Suspicious execve from runc in container",
        "user": "root",
        "uid": 0
    }

    logger.info("TESTING: analyze_alert() — TP EVENT (STREAMING=TRUE)")
    res = analyze_alert(mock_event, 0.92, "TP", stream=True)

    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80)

    print("\n📋 FINAL REPORT:")
    print("-" * 80)
    print(res.get("final_report"))

    print("\n🔧 YAML FIX:")
    print("-" * 80)
    print(res.get("yaml_fix"))

    print("\n🎯 MITRE TECHNIQUES:")
    print("-" * 80)
    for tech in res.get("mitre_techniques", []):
        print(f"  {tech['id']} — {tech['name']} ({tech['tactic']})")
