import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import xgboost as xgb

logger = logging.getLogger("sentinel.ml_triage")

def rule_based_triage(event: dict) -> tuple:
    """
    Rule-based fallback when ML model fails.
    Used when GUIDE model features don't match Tetragon features.
    """
    telemetry = event.get("telemetry", event)
    binary = telemetry.get("binary", telemetry.get("process", "")).lower()
    binary_name = binary.rsplit("/", 1)[-1] if binary else ""
    path_args = " ".join([
        str(telemetry.get("file_path", "")),
        str(telemetry.get("path", "")),
        str(telemetry.get("args", "")),
    ]).lower()
    uid = telemetry.get("uid", 1000)
    namespace = telemetry.get("namespace", "default")

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

class MLTriage:
    """Handles ML-based triage for Sentinel events."""

    def __init__(self, model_path: Path, feature_list_path: Path):
        self.model_path = model_path
        self.feature_list_path = feature_list_path
        self.model = None
        self.features = []
        self.label_map = {}
        self.reverse_label_map = {}
        
        self._load_resources()

    def _load_resources(self):
        """Load the model and feature/label metadata."""
        if not self.model_path.exists():
            logger.warning("ML model not found at %s. Triage will be disabled.", self.model_path)
            return

        try:
            self.model = xgb.Booster()
            self.model.load_model(str(self.model_path))
            logger.info("✅ ML model loaded from %s", self.model_path)

            if self.feature_list_path.exists():
                with open(self.feature_list_path, "r") as f:
                    data = json.load(f)
                    self.features = data.get("features", [])
                    self.label_map = data.get("labels", {})
                    self.reverse_label_map = {int(k): v for k, v in self.label_map.items()}
                logger.info("✅ Feature list loaded: %d features", len(self.features))
            else:
                logger.warning("Feature list not found. Triage disabled.")
                self.model = None

        except Exception as e:
            logger.error("❌ Failed to load ML resources: %s", e)
            self.model = None

    def triage_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Predict triage status for a Sentinel event.
        Returns a dict with triage results.
        """
        if self.model is None or not self.features:
            return {
                "triage": None,
                "explanation": {"mitre_id": "N/A", "guidance": "ML Triage disabled."},
                "deliverable": "ML Triage unavailable."
            }

        # Check rule-based override first
        rule_grade, rule_conf = rule_based_triage(event)
        if rule_grade in ("TP", "BP"):
            return {
                "triage": {"grade": rule_grade, "confidence": rule_conf},
                "explanation": {"mitre_id": "N/A", "guidance": f"Rule-based detection matched: {rule_grade}"},
                "deliverable": f"Hardcoded rule overridden logic: {rule_grade} with {rule_conf} confidence."
            }

        try:
            # Prepare features for inference
            feature_data = self._prepare_features(event)
            
            # Ensure order matches training
            ordered_features = [feature_data.get(f, 0) for f in self.features]
            
            # Use raw numpy array to avoid pandas type mismatch completely
            dmat = xgb.DMatrix(np.array([ordered_features]), feature_names=self.features)
            
            # Predict
            preds = self.model.predict(dmat)
            
            # Multi-class softprob gives an array of probabilities per class
            if len(preds.shape) > 1 and preds.shape[1] > 1:
                probs = preds[0]
                prediction = int(np.argmax(probs))
                confidence = float(np.max(probs))
            else:
                prediction = int(preds[0])
                confidence = 1.0

            status = self.reverse_label_map.get(prediction, "TruePositive")
            status_formatted = status.replace("Positive", " Positive")

            grade_map = {
                "FalsePositive": "FP",
                "BenignPositive": "BP",
                "TruePositive": "TP"
            }
            grade = grade_map.get(status, "TP")
            
            return {
                "triage": {
                    "grade": grade,
                    "confidence": round(confidence, 2)
                },
                "explanation": {
                    "mitre_id": "N/A",  # Resolving this later in API
                    "guidance": f"ML model predicted {status_formatted} with {confidence*100:.1f}% confidence."
                },
                "deliverable": f"This event is a {confidence*100:.0f}% {status_formatted}."
            }

        except Exception as e:
            logger.error(f"ML Inference failed: {e}")
            grade, confidence = rule_based_triage(event)
            return {
                "triage": {"grade": grade, "confidence": confidence},
                "explanation": {"mitre_id": "N/A", "guidance": f"ML Inference failed: {str(e)}"},
                "deliverable": f"Rule-based fallback: {grade} with {confidence} confidence."
            }

    def _prepare_features(self, event: dict[str, Any]) -> dict[str, Any]:
        """Map Sentinel event fields to ML features using security heuristics."""
        telemetry = event.get("telemetry", {})
        
        # 1. Base ID/Auth 
        uid = int(telemetry.get("uid", 1000))
        pid = int(telemetry.get("pid", 0))
        is_root = 1 if uid == 0 else 0
        
        # 2. Binary Risk
        binary = telemetry.get("binary", "").lower()
        if any(b in binary for b in ["curl", "wget", "nc", "netcat", "nmap", "socat"]):
            binary_risk = 2
        elif any(b in binary for b in ["bash", "sh", "python", "perl", "ruby"]):
            binary_risk = 1
        else:
            binary_risk = 0
            
        # 3. Syscall Risk
        syscall = event.get("syscall", "").lower()
        if any(s in syscall for s in ["execve", "ptrace", "bpf"]):
            syscall_risk = 2
        elif any(s in syscall for s in ["connect", "write", "openat"]):
            syscall_risk = 1
        else:
            syscall_risk = 0
            
        # 4. Sensitive Path Access
        path = telemetry.get("file_path", telemetry.get("path", "")).lower()
        args = str(telemetry.get("args", [])).lower()
        target_str = path + " " + args
        sensitive_paths = ["/etc/shadow", "/etc/passwd", "/root", "/var/run/secrets", "/proc", ".ssh"]
        sensitive_path = 1 if any(p in target_str for p in sensitive_paths) else 0
        
        # 5. Event Type mapping
        evt_type_str = event.get("event_type", "process_exec")
        evt_map = {"process_exec": 0, "process_kprobe": 1, "process_exit": 2}
        event_type = evt_map.get(evt_type_str, 0)
        
        # 6. Network Indicators
        # Super simple check for IPs or ports in arguments
        import re
        has_network_args = 1 if re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(:\d+)', args) else 0
        
        # 7. Container
        is_container = 1 if telemetry.get("container_id") or telemetry.get("pod") else 0
        
        # 8. Parent process
        parent = telemetry.get("parent_binary", "").lower()
        parent_is_shell = 1 if any(b in parent for b in ["bash", "sh", "dash", "zsh"]) else 0

        return {
            "uid": uid,
            "pid": pid,
            "is_root": is_root,
            "binary_risk": binary_risk,
            "syscall_risk": syscall_risk,
            "sensitive_path": sensitive_path,
            "event_type": event_type,
            "has_network_args": has_network_args,
            "is_container": is_container,
            "parent_is_shell": parent_is_shell
        }
