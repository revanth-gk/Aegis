"""
config_api.py

REST API endpoint for runtime configuration updates.

This module implements a Flask blueprint for the RemediationAgent
configuration API, allowing runtime updates without restart.

Validates: Requirements 11.2, 11.3, 11.4, 11.5, 11.6
"""

import logging
from typing import Dict, Any
from flask import Blueprint, request, jsonify

from .config import RemediationConfig

logger = logging.getLogger(__name__)

# Create Flask blueprint
config_bp = Blueprint("remediation_config", __name__, url_prefix="/api/remediation")

# Global configuration instance (shared with agent)
_config_instance: RemediationConfig = None


def init_config_api(config: RemediationConfig):
    """
    Initialize the configuration API with a config instance.
    
    Args:
        config: RemediationConfig instance to manage
    """
    global _config_instance
    _config_instance = config
    logger.info("Configuration API initialized")


@config_bp.route("/config", methods=["GET"])
def get_config():
    """
    Get current remediation configuration.
    
    Returns:
        JSON response with current configuration
    
    Requirements:
        11.2: Expose REST API endpoint
    """
    if _config_instance is None:
        return jsonify({"error": "Configuration not initialized"}), 500
    
    return jsonify(_config_instance.to_dict()), 200


@config_bp.route("/config", methods=["POST"])
def update_config():
    """
    Update remediation configuration at runtime.
    
    Request body should contain configuration fields to update:
    {
        "autonomy_mode": "autonomous" | "tiered" | "human-in-loop",
        "dry_run": true | false,
        "sigkill_threshold": 0.0-1.0,
        "yaml_threshold": 0.0-1.0,
        "kubeconfig_path": "path/to/kubeconfig" | null
    }
    
    Returns:
        JSON response with updated configuration or error
    
    Requirements:
        11.2: Expose REST API endpoint
        11.3: Validate configuration before applying
        11.4: Reject invalid configuration
        11.5: Support updating all configuration fields
        11.6: Log configuration changes
    """
    if _config_instance is None:
        return jsonify({"error": "Configuration not initialized"}), 500
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No configuration data provided"}), 400
        
        # Extract fields from request
        autonomy_mode = data.get("autonomy_mode")
        dry_run = data.get("dry_run")
        sigkill_threshold = data.get("sigkill_threshold")
        yaml_threshold = data.get("yaml_threshold")
        kubeconfig_path = data.get("kubeconfig_path")
        
        # Update configuration (validation happens in config.update())
        _config_instance.update(
            autonomy_mode=autonomy_mode,
            dry_run=dry_run,
            sigkill_threshold=sigkill_threshold,
            yaml_threshold=yaml_threshold,
            kubeconfig_path=kubeconfig_path
        )
        
        # Log configuration change
        logger.info(
            f"Configuration updated via API: {data}"
        )
        
        # TODO: Log to audit trail (requires audit logger integration)
        
        return jsonify({
            "message": "Configuration updated successfully",
            "config": _config_instance.to_dict()
        }), 200
    
    except ValueError as e:
        # Validation error
        logger.warning(f"Configuration update rejected: {e}")
        return jsonify({"error": str(e)}), 400
    
    except Exception as e:
        logger.exception(f"Configuration update failed: {e}")
        return jsonify({"error": f"Internal error: {str(e)}"}), 500
