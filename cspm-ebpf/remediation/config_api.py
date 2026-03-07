"""
config_api.py

REST API endpoint for runtime configuration updates.

This module implements a FastAPI router for the RemediationAgent
configuration API, allowing runtime updates without restart.

Validates: Requirements 11.2, 11.3, 11.4, 11.5, 11.6
"""

import logging
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from .config import RemediationConfig

logger = logging.getLogger(__name__)

# Create FastAPI router
config_bp = APIRouter(prefix="/api/remediation")

# Global configuration instance (shared with agent)
_config_instance = None


def init_config_api(config: RemediationConfig):
    """
    Initialize the configuration API with a config instance.
    
    Args:
        config: RemediationConfig instance to manage
    """
    global _config_instance
    _config_instance = config
    logger.info("Configuration API initialized")

class ConfigUpdateRequest(BaseModel):
    autonomy_mode: Optional[str] = None
    dry_run: Optional[bool] = None
    sigkill_threshold: Optional[float] = None
    yaml_threshold: Optional[float] = None
    kubeconfig_path: Optional[str] = None

@config_bp.get("/config")
async def get_config():
    """
    Get current remediation configuration.
    """
    if _config_instance is None:
        raise HTTPException(status_code=500, detail="Configuration not initialized")
    
    return _config_instance.to_dict()


@config_bp.post("/config")
async def update_config(request: ConfigUpdateRequest):
    """
    Update remediation configuration at runtime.
    """
    if _config_instance is None:
        raise HTTPException(status_code=500, detail="Configuration not initialized")
    
    try:
        # Update configuration (validation happens in config.update())
        _config_instance.update(
            autonomy_mode=request.autonomy_mode, # type: ignore
            dry_run=request.dry_run,
            sigkill_threshold=request.sigkill_threshold,
            yaml_threshold=request.yaml_threshold,
            kubeconfig_path=request.kubeconfig_path
        )
        
        # Log configuration change
        logger.info(
            f"Configuration updated via API: {request.model_dump(exclude_unset=True)}"
        )
        
        return {
            "message": "Configuration updated successfully",
            "config": _config_instance.to_dict()
        }
    
    except ValueError as e:
        # Validation error
        logger.warning(f"Configuration update rejected: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    
    except Exception as e:
        logger.exception(f"Configuration update failed: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
