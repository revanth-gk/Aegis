#!/usr/bin/env python3
"""
train_model.py - Sentinel-Core ML Triage Model Trainer

Trains an XGBoost multi-class classifier to triage eBPF security events.
Since we don't have a massive labeled corpus of real attacks, this script
generates a high-quality SYNTHETIC dataset based on Microsoft GUIDE heuristics
to train the model.

Classes:
    0: False Positive (Routine system activity)
    1: Benign Positive (Anomalous but non-malicious admin activity)
    2: True Positive (High confidence malicious behavior)
"""

import os
import json
import logging
import numpy as np
import pandas as pd
import xgboost as xgb
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
MODEL_DIR = Path("forwarder/model")
MODEL_PATH = MODEL_DIR / "xgboost_model.json"
FEATURE_PATH = MODEL_DIR / "feature_list.json"

# ==============================================================================
# 1. Dataset Generation (Synthetic Heuristics)
# ==============================================================================

def generate_synthetic_data(num_samples=4000):
    """Generates synthetic eBPF telemetry data labeled using security heuristics."""
    logger.info(f"Generating {num_samples} synthetic security events...")
    np.random.seed(42)  # For reproducibility
    
    data = []
    
    for _ in range(num_samples):
        # Base features
        uid = np.random.choice([0, 33, 1000, 1001], p=[0.2, 0.1, 0.5, 0.2])
        pid = np.random.randint(100, 65535)
        is_root = 1 if uid == 0 else 0
        
        # Binary Risk (0=Low, 1=Medium, 2=High)
        binary_risk = np.random.choice([0, 1, 2], p=[0.7, 0.2, 0.1])
        
        # Syscall Risk (0=Low, 1=Medium, 2=High)
        syscall_risk = np.random.choice([0, 1, 2], p=[0.6, 0.3, 0.1])
        
        # Target Path (0=Normal, 1=Sensitive)
        sensitive_path = int(np.random.choice([0, 1], p=[0.85, 0.15]))
        
        # Event Type (0=process_exec, 1=process_kprobe, 2=process_exit)
        event_type = int(np.random.choice([0, 1, 2], p=[0.4, 0.4, 0.2]))
        
        # Network Args (0=No, 1=Yes)
        has_network_args = int(np.random.choice([0, 1], p=[0.9, 0.1]))
        
        # Container execution (0=Host, 1=Container)
        is_container = int(np.random.choice([0, 1], p=[0.6, 0.4]))
        
        # Parent Process (0=Service/Init, 1=Shell)
        parent_is_shell = int(np.random.choice([0, 1], p=[0.8, 0.2]))
        
        # ----------------------------------------------------------------------
        # Labeling Logic (The "Instructor" Heuristic)
        # 0 = FalsePositive, 1 = BenignPositive, 2 = TruePositive
        # ----------------------------------------------------------------------
        
        label = 0 # Default FP
        
        # TRUE POSITIVE CONDITIONS (Attack Indicators)
        if binary_risk == 2 and is_root and has_network_args and is_container:
            # e.g. root curl with IP inside container
            label = 2
        elif syscall_risk == 2 and sensitive_path and is_container:
            # e.g. ptrace or module load accessing sensitive file in container
            label = 2
        elif parent_is_shell and binary_risk == 2 and uid == 33:
            # e.g. www-data spawning netcat from a web shell
            label = 2
        elif syscall_risk == 2 and sensitive_path == 1 and parent_is_shell == 1:
            label = 2
            
        # BENIGN POSITIVE CONDITIONS (Admin/Debugging)
        elif syscall_risk == 1 and is_root and not is_container:
            # e.g. root doing normal admin tasks on host
            label = 1
        elif binary_risk == 1 and has_network_args and not is_container:
            # e.g. developer using curl on host
            label = 1
        elif syscall_risk == 2 and not sensitive_path and is_root:
            label = 1
            
        # Ensure some noisy edge cases based on pure randomness to force learning
        noise = np.random.random()
        if noise > 0.95:
            label = np.random.choice([0, 1, 2])
            
        # Append feature row
        data.append({
            "uid": uid,
            "pid": pid,
            "is_root": is_root,
            "binary_risk": binary_risk,
            "syscall_risk": syscall_risk,
            "sensitive_path": sensitive_path,
            "event_type": event_type,
            "has_network_args": has_network_args,
            "is_container": is_container,
            "parent_is_shell": parent_is_shell,
            "label": label
        })
        
    df = pd.DataFrame(data)
    logger.info(f"Class distribution:\n{df['label'].value_counts(normalize=True)}")
    return df

# ==============================================================================
# 2. Model Training
# ==============================================================================

def train_xgboost(df: pd.DataFrame):
    """Trains the XGBoost classifier on the synthetic data."""
    logger.info("Initializing XGBoost Model Training Pipeline...")
    
    # Ensure directories exist
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    
    # Split features and labels
    X = df.drop(columns=["label"])
    y = df["label"]
    
    # Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)
    logger.info(f"Train size: {len(X_train)}, Test size: {len(X_test)}")
    
    # Define XGBoost Model
    # We use multi:softprob to output probabilities for confidence grading
    clf = xgb.XGBClassifier(
        objective='multi:softprob',
        num_class=3,
        n_estimators=100,
        max_depth=5,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric='mlogloss',
        use_label_encoder=False
    )
    
    # Train Model
    logger.info("Training XGBoost Classifier...")
    clf.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)
    
    # Evaluate
    logger.info("Evaluating Model...")
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    logger.info(f"Model Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, target_names=['FalsePositive', 'BenignPositive', 'TruePositive']))
    
    # Export Model
    logger.info(f"Saving XGBoost model to {MODEL_PATH}")
    clf.save_model(MODEL_PATH)
    
    # Export Feature List for Inference Runtime
    features = list(X.columns)
    feature_meta = {
        "features": features,
        "labels": {
            "0": "FalsePositive",
            "1": "BenignPositive",
            "2": "TruePositive"
        },
        "version": "1.1",
        "description": "Sentinel-Core eBPF Event Classifier (Synthetic)"
    }
    
    logger.info(f"Saving Feature List to {FEATURE_PATH}")
    with open(FEATURE_PATH, "w") as f:
        json.dump(feature_meta, f, indent=2)
        
    logger.info("Training complete and artifacts exported successfully.")

# ==============================================================================
# MAIN EXECUTOR
# ==============================================================================

if __name__ == "__main__":
    df_synthetic = generate_synthetic_data()
    train_xgboost(df_synthetic)
