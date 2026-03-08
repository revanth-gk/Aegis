"""
config.py

Configuration management for the RemediationAgent.

This module implements the configuration hierarchy:
ENV VAR (boot default) → API endpoint (runtime change) → Per-event flag (test/debug only)

Validates: Requirements 5.5, 8.4, 11.1, 11.5
"""

import os
import logging
from typing import Optional, Literal
from dataclasses import dataclass, field
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)

# Type alias for autonomy modes
AutonomyMode = Literal["autonomous", "tiered", "human-in-loop"]


@dataclass
class RemediationConfig:
    """
    Configuration class for RemediationAgent with runtime update support.
    
    Configuration hierarchy:
    1. Environment variables (boot defaults)
    2. Runtime updates via API endpoint
    3. Per-event flags (test/debug only)
    
    Attributes:
        autonomy_mode: Controls human approval requirements
            - "autonomous": Execute all approved actions without confirmation
            - "tiered": Execute YAML without confirmation, require confirmation for SIGKILL
            - "human-in-loop": Require confirmation for all actions
        dry_run: If True, log actions without executing kubectl commands
        sigkill_threshold: Minimum confidence score (0.0-1.0) required for SIGKILL actions
        yaml_threshold: Minimum confidence score (0.0-1.0) required for YAML patch actions
        kubeconfig_path: Path to kubeconfig file for external cluster authentication
            If None, uses in-cluster ServiceAccount authentication
    """
    
    autonomy_mode: AutonomyMode = field(default="tiered")
    dry_run: bool = field(default=True)
    sigkill_threshold: float = field(default=0.85)
    yaml_threshold: float = field(default=0.75)
    kubeconfig_path: Optional[str] = field(default=None)
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate()
    
    def _validate(self) -> None:
        """
        Validate configuration values.
        
        Raises:
            ValueError: If configuration values are invalid
        """
        # Validate autonomy_mode
        valid_modes = ["autonomous", "tiered", "human-in-loop"]
        if self.autonomy_mode not in valid_modes:
            raise ValueError(
                f"Invalid autonomy_mode '{self.autonomy_mode}'. "
                f"Must be one of: {', '.join(valid_modes)}"
            )
        
        # Validate confidence thresholds
        if not 0.0 <= self.sigkill_threshold <= 1.0:
            raise ValueError(
                f"sigkill_threshold must be between 0.0 and 1.0, "
                f"got {self.sigkill_threshold}"
            )
        
        if not 0.0 <= self.yaml_threshold <= 1.0:
            raise ValueError(
                f"yaml_threshold must be between 0.0 and 1.0, "
                f"got {self.yaml_threshold}"
            )
        
        # Validate kubeconfig_path if provided
        if self.kubeconfig_path is not None:
            if not isinstance(self.kubeconfig_path, str):
                raise ValueError(
                    f"kubeconfig_path must be a string or None, "
                    f"got {type(self.kubeconfig_path)}"
                )
            if self.kubeconfig_path and not os.path.exists(self.kubeconfig_path):
                logger.warning(
                    f"kubeconfig_path '{self.kubeconfig_path}' does not exist. "
                    "Kubernetes authentication may fail."
                )
    
    def update(
        self,
        autonomy_mode: Optional[AutonomyMode] = None,
        dry_run: Optional[bool] = None,
        sigkill_threshold: Optional[float] = None,
        yaml_threshold: Optional[float] = None,
        kubeconfig_path: Optional[str] = None,
    ) -> None:
        """
        Update configuration at runtime (typically via API endpoint).
        
        Args:
            autonomy_mode: New autonomy mode
            dry_run: New dry run setting
            sigkill_threshold: New SIGKILL confidence threshold
            yaml_threshold: New YAML confidence threshold
            kubeconfig_path: New kubeconfig path
        
        Raises:
            ValueError: If new configuration values are invalid
        """
        # Store original values for rollback on validation failure
        original_values = {
            "autonomy_mode": self.autonomy_mode,
            "dry_run": self.dry_run,
            "sigkill_threshold": self.sigkill_threshold,
            "yaml_threshold": self.yaml_threshold,
            "kubeconfig_path": self.kubeconfig_path,
        }
        
        try:
            # Update provided values
            if autonomy_mode is not None:
                self.autonomy_mode = autonomy_mode
            if dry_run is not None:
                self.dry_run = dry_run
            if sigkill_threshold is not None:
                self.sigkill_threshold = sigkill_threshold
            if yaml_threshold is not None:
                self.yaml_threshold = yaml_threshold
            if kubeconfig_path is not None:
                self.kubeconfig_path = kubeconfig_path
            
            # Validate new configuration
            self._validate()
            
            logger.info(
                f"Configuration updated: autonomy_mode={self.autonomy_mode}, "
                f"dry_run={self.dry_run}, sigkill_threshold={self.sigkill_threshold}, "
                f"yaml_threshold={self.yaml_threshold}, kubeconfig_path={self.kubeconfig_path}"
            )
        
        except ValueError as e:
            # Rollback to original values on validation failure
            self.autonomy_mode = original_values["autonomy_mode"]
            self.dry_run = original_values["dry_run"]
            self.sigkill_threshold = original_values["sigkill_threshold"]
            self.yaml_threshold = original_values["yaml_threshold"]
            self.kubeconfig_path = original_values["kubeconfig_path"]
            
            logger.error(f"Configuration update failed: {e}")
            raise
    
    @classmethod
    def from_env(cls) -> "RemediationConfig":
        """
        Load configuration from environment variables.
        
        Environment variables:
            REMEDIATION_AUTONOMY_MODE: Autonomy mode (default: "tiered")
            REMEDIATION_DRY_RUN: Dry run mode (default: "true")
            REMEDIATION_SIGKILL_THRESHOLD: SIGKILL confidence threshold (default: "0.92")
            REMEDIATION_YAML_THRESHOLD: YAML confidence threshold (default: "0.95")
            KUBECONFIG_PATH: Path to kubeconfig file (default: None for in-cluster auth)
        
        Returns:
            RemediationConfig instance with values from environment
        """
        # Load autonomy mode
        autonomy_mode_str = os.getenv("REMEDIATION_AUTONOMY_MODE", "tiered")
        autonomy_mode: AutonomyMode = autonomy_mode_str  # type: ignore
        
        # Load dry run (default to True for safety)
        dry_run_str = os.getenv("REMEDIATION_DRY_RUN", "true").lower()
        dry_run = dry_run_str in ("true", "1", "yes")
        
        # Load confidence thresholds
        sigkill_threshold = float(os.getenv("REMEDIATION_SIGKILL_THRESHOLD", "0.85"))
        yaml_threshold = float(os.getenv("REMEDIATION_YAML_THRESHOLD", "0.75"))
        
        # Load kubeconfig path (None means in-cluster auth)
        kubeconfig_path = os.getenv("KUBECONFIG_PATH")
        
        config = cls(
            autonomy_mode=autonomy_mode,
            dry_run=dry_run,
            sigkill_threshold=sigkill_threshold,
            yaml_threshold=yaml_threshold,
            kubeconfig_path=kubeconfig_path,
        )
        
        logger.info(
            f"Loaded configuration from environment: autonomy_mode={config.autonomy_mode}, "
            f"dry_run={config.dry_run}, sigkill_threshold={config.sigkill_threshold}, "
            f"yaml_threshold={config.yaml_threshold}, kubeconfig_path={config.kubeconfig_path}"
        )
        
        return config
    
    def to_dict(self) -> dict:
        """
        Convert configuration to dictionary for serialization.
        
        Returns:
            Dictionary representation of configuration
        """
        return {
            "autonomy_mode": self.autonomy_mode,
            "dry_run": self.dry_run,
            "sigkill_threshold": self.sigkill_threshold,
            "yaml_threshold": self.yaml_threshold,
            "kubeconfig_path": self.kubeconfig_path,
        }
