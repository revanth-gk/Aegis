import os
import uvicorn
from fastapi import FastAPI
from remediation.config_api import config_bp, init_config_api
from remediation.health import health_bp
from remediation.config import RemediationConfig

app = FastAPI(title="Remediation Agent Server")

# Initialize config
config = RemediationConfig.from_env()
init_config_api(config)

# Include routers
app.include_router(config_bp)
app.include_router(health_bp)

if __name__ == "__main__":
    port = int(os.environ.get("REMEDIATION_PORT", 8002))
    uvicorn.run("server:app", host="0.0.0.0", port=port, log_level="info")
