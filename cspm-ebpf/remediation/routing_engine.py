"""
routing_engine.py

MITRE tactic-based action routing for remediation.

This module implements the Routing Engine component that determines the
appropriate remediation action type based on MITRE ATT&CK tactics.

Validates: Requirements 4.1-4.7, 17.1-17.3
"""

import logging
from typing import List, Literal

logger = logging.getLogger(__name__)

ActionType = Literal["SIGKILL", "YAML"]


class RoutingEngine:
    """
    Routes remediation actions based on MITRE ATT&CK tactics.
    
    The Routing Engine applies conservative action selection:
    - High-risk tactics (Execution, Privilege Escalation, Credential Access) → SIGKILL
    - Configuration tactics (Persistence, Defense Evasion) → YAML
    - SIGKILL takes precedence if any SIGKILL-eligible tactic is present
    - Unknown tactics default to YAML (safer option)
    """
    
    # Tactics that warrant immediate process termination
    SIGKILL_TACTICS = {
        "Execution",
        "Privilege Escalation",
        "Credential Access"
    }
    
    # Tactics that warrant configuration changes
    YAML_TACTICS = {
        "Persistence",
        "Defense Evasion"
    }
    
    # All 14 MITRE ATT&CK tactics for recognition
    ALL_MITRE_TACTICS = {
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact"
    }
    
    def __init__(self):
        """Initialize Routing Engine with default tactic mappings."""
        logger.info(
            f"Routing Engine initialized: SIGKILL tactics={self.SIGKILL_TACTICS}, "
            f"YAML tactics={self.YAML_TACTICS}"
        )
    
    def determine_action(self, mitre_techniques: List[dict]) -> ActionType:
        """
        Determine remediation action type based on MITRE tactics.
        
        Args:
            mitre_techniques: List of MITRE technique dicts with 'tactic' field
                Example: [{"id": "T1059", "name": "...", "tactic": "Execution", "url": "..."}]
        
        Returns:
            Action type: "SIGKILL" or "YAML"
        
        Logic:
            1. Extract all tactics from mitre_techniques
            2. If any SIGKILL-eligible tactic present → SIGKILL (priority)
            3. If any YAML-eligible tactic present → YAML
            4. If no recognized tactics → YAML (default/safer)
        
        Requirements:
            4.1: Execution → SIGKILL
            4.2: Privilege Escalation → SIGKILL
            4.3: Credential Access → SIGKILL
            4.4: Persistence → YAML
            4.5: Defense Evasion → YAML
            4.6: SIGKILL priority with mixed tactics
            4.7: YAML default for unrecognized tactics
            17.1: Parse mitre_techniques as list of tactic strings
            17.2: Recognize all 14 MITRE tactics
            17.3: Log warnings for unrecognized tactics
        """
        if not mitre_techniques:
            logger.warning("No MITRE techniques provided, defaulting to YAML")
            return "YAML"
        
        # Extract tactics from technique objects
        tactics = []
        for technique in mitre_techniques:
            if isinstance(technique, dict) and "tactic" in technique:
                tactic = technique["tactic"]
                tactics.append(tactic)
                
                # Log warning for unrecognized tactics
                if tactic not in self.ALL_MITRE_TACTICS:
                    logger.warning(
                        f"Unrecognized MITRE tactic: '{tactic}' "
                        f"(technique: {technique.get('id', 'unknown')})"
                    )
        
        if not tactics:
            logger.warning("No tactics extracted from techniques, defaulting to YAML")
            return "YAML"
        
        # Check for SIGKILL-eligible tactics (highest priority)
        sigkill_matches = [t for t in tactics if t in self.SIGKILL_TACTICS]
        if sigkill_matches:
            logger.info(
                f"SIGKILL action selected due to tactics: {sigkill_matches} "
                f"(all tactics: {tactics})"
            )
            return "SIGKILL"
        
        # Check for YAML-eligible tactics
        yaml_matches = [t for t in tactics if t in self.YAML_TACTICS]
        if yaml_matches:
            logger.info(
                f"YAML action selected due to tactics: {yaml_matches} "
                f"(all tactics: {tactics})"
            )
            return "YAML"
        
        # Default to YAML for unrecognized or other tactics (safer option)
        logger.info(
            f"YAML action selected (default) for tactics: {tactics}"
        )
        return "YAML"
