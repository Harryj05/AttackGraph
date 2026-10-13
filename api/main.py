import os
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from contextlib import asynccontextmanager
from api.auth import verify_api_key, get_configured_api_key
from api.routes import scans, calibration, pattern_stats


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Strict fail-closed security: refuse to start without an API key configured
    get_configured_api_key()
    yield


app = FastAPI(
    title="AttackGraph AI API",
    description="Controlled Security Analysis Platform — Server-side allowlist protected",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS: Configured from env with strict localhost default, never wildcard
raw_cors = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:5173")
allowed_origins = [o.strip() for o in raw_cors.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Protected routes require valid X-API-Key header (query parameter authentication disallowed)
app.include_router(scans.router, dependencies=[Depends(verify_api_key)])
app.include_router(calibration.router, dependencies=[Depends(verify_api_key)])
app.include_router(pattern_stats.router, dependencies=[Depends(verify_api_key)])


@app.get("/health")
def health_check():
    """Unauthenticated liveness probe."""
    return {"status": "ok", "service": "AttackGraph AI API"}
