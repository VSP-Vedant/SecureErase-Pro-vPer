# =============================================================================
# SecureErase Pro — Verification Portal Entry Point
# =============================================================================
# Purpose  : Launches FastAPI backend application
# Inputs   : Environment variables via .env
# Outputs  : HTTP server on configured port
# =============================================================================

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "backend.app:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )
