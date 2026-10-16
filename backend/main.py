"""
CYBERGUARD X — FastAPI Backend Entrypoint
==========================================

Responsibilities:
    - Create FastAPI application
    - Load configuration
    - Register API routers
    - Configure CORS
    - Initialize database
    - Health / readiness endpoints
    - Global exception handling

Run from project root:
    uvicorn backend.main:app --reload

Production:
    uvicorn backend.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from starlette.exceptions import HTTPException as StarletteHTTPException


# ============================================================
# PROJECT IMPORTS
# ============================================================

try:
    from backend.config import settings
except ImportError:
    from config import settings

try:
    from backend import database
except ImportError:
    import database

try:
    from backend.routers.auth import router as auth_router
    from backend.routers.scan import router as scan_router
    from backend.routers.history import router as history_router
except ImportError:
    from routers.auth import router as auth_router
    from routers.scan import router as scan_router
    from routers.history import router as history_router


# ============================================================
# LOGGING
# ============================================================

LOG_LEVEL = str(getattr(settings, "LOG_LEVEL", "INFO")).upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("cyberguard-x")


# ============================================================
# APPLICATION METADATA
# ============================================================

APP_NAME = str(getattr(settings, "APP_NAME", "CYBERGUARD X"))
APP_VERSION = str(getattr(settings, "APP_VERSION", "3.0.0"))
APP_DESCRIPTION = str(getattr(
    settings,
    "APP_DESCRIPTION",
    "CYBERGUARD X — Multi-signal cybersecurity threat detection platform.",
))
ENVIRONMENT = str(getattr(settings, "ENVIRONMENT", "development")).lower()


# ============================================================
# CORS CONFIGURATION
# ============================================================

def _load_cors_origins() -> list[str]:
    """Load CORS origins from configuration."""
    configured = getattr(settings, "CORS_ORIGINS", None)

    if configured is None:
        configured = os.getenv("CORS_ORIGINS", "")

    if isinstance(configured, str):
        origins = [o.strip() for o in configured.split(",") if o.strip()]
    elif isinstance(configured, (list, tuple, set)):
        origins = [str(o).strip() for o in configured if str(o).strip()]
    else:
        origins = []

    if not origins or origins == ["*"]:
        return [
            "http://localhost:3000",
            "http://localhost:5173",
            "http://localhost:5500",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:5500",
        ]

    return origins


CORS_ORIGINS = _load_cors_origins()


# ============================================================
# REQUEST LIMITS
# ============================================================

MAX_REQUEST_BODY_BYTES = int(
    getattr(settings, "MAX_REQUEST_BODY_BYTES", 10 * 1024 * 1024)
)
MAX_REQUEST_BODY_BYTES = max(1024, MAX_REQUEST_BODY_BYTES)


# ============================================================
# APPLICATION STATE
# ============================================================

APP_START_TIME = time.monotonic()


# ============================================================
# LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Application startup/shutdown lifecycle."""

    logger.info("Starting %s v%s", APP_NAME, APP_VERSION)
    logger.info("Environment: %s", ENVIRONMENT)

    # --------------------------------------------------------
    # Database init
    # --------------------------------------------------------

    try:
        init_fn = getattr(database, "init_db", None) or \
                  getattr(database, "initialize_database", None)

        if init_fn:
            result = init_fn()
            if hasattr(result, "__await__"):
                await result
            logger.info("Database initialized.")
        else:
            logger.warning("No database init function found.")

    except Exception:
        logger.exception("Database initialization failed.")
        raise

    logger.info("CORS origins: %s", CORS_ORIGINS)
    logger.info("Max request body: %d bytes", MAX_REQUEST_BODY_BYTES)
    logger.info("CYBERGUARD X backend startup complete.")

    try:
        yield
    finally:
        # ----------------------------------------------------
        # Database close
        # ----------------------------------------------------

        try:
            close_fn = getattr(database, "close_db", None) or \
                       getattr(database, "close_database", None)

            if close_fn:
                result = close_fn()
                if hasattr(result, "__await__"):
                    await result
                logger.info("Database closed.")
        except Exception:
            logger.exception("Error closing database.")

        logger.info("CYBERGUARD X backend shutdown complete.")


# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# ============================================================
# CORS MIDDLEWARE
# ============================================================

allow_credentials = bool(getattr(settings, "CORS_ALLOW_CREDENTIALS", False))

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# REQUEST ID MIDDLEWARE
# ============================================================

@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    """Attach a unique request ID to every request."""
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    request.state.request_id = request_id

    started = time.monotonic()

    try:
        response = await call_next(request)
    except Exception:
        elapsed = time.monotonic() - started
        logger.exception(
            "Unhandled exception | request_id=%s | method=%s | path=%s | duration=%.3fs",
            request_id, request.method, request.url.path, elapsed,
        )
        raise

    elapsed = time.monotonic() - started

    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time"] = f"{elapsed:.4f}s"

    logger.info(
        "HTTP | request_id=%s | method=%s | path=%s | status=%s | duration=%.3fs",
        request_id, request.method, request.url.path,
        response.status_code, elapsed,
    )

    return response


# ============================================================
# SECURITY HEADERS MIDDLEWARE
# ============================================================

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add defensive HTTP response headers."""
    response = await call_next(request)

    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Referrer-Policy", "strict-origin-when-cross-origin"
    )
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
    )

    if getattr(settings, "ENABLE_HSTS", False):
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )

    return response


# ============================================================
# REQUEST BODY SIZE MIDDLEWARE
# ============================================================

@app.middleware("http")
async def request_size_middleware(request: Request, call_next):
    """Reject obviously oversized requests."""
    content_length = request.headers.get("content-length")

    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                request_id = getattr(
                    request.state, "request_id", uuid.uuid4().hex
                )
                return JSONResponse(
                    status_code=413,
                    content={
                        "status": "error",
                        "error": "request_too_large",
                        "message": "Request body exceeds the configured maximum size.",
                        "request_id": request_id,
                    },
                )
        except ValueError:
            pass

    return await call_next(request)


# ============================================================
# EXCEPTION HANDLERS
# ============================================================

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Consistent HTTP error responses."""
    request_id = getattr(request.state, "request_id", uuid.uuid4().hex)

    detail = exc.detail
    message = str(detail or "Request failed.") if not isinstance(detail, dict) \
              else detail.get("message", "Request failed.")

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "error": "http_error",
            "message": message,
            "detail": detail,
            "request_id": request_id,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
):
    """Clean validation error responses."""
    request_id = getattr(request.state, "request_id", uuid.uuid4().hex)

    errors = []
    for error in exc.errors():
        errors.append({
            "location": [str(x) for x in error.get("loc", [])],
            "message": str(error.get("msg", "Invalid value.")),
            "type": str(error.get("type", "validation_error")),
        })

    return JSONResponse(
        status_code=422,
        content={
            "status": "error",
            "error": "validation_error",
            "message": "One or more request fields failed validation.",
            "details": errors,
            "request_id": request_id,
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Last-resort exception handler."""
    request_id = getattr(request.state, "request_id", uuid.uuid4().hex)

    logger.exception(
        "Unhandled error | request_id=%s | method=%s | path=%s",
        request_id, request.method, request.url.path,
    )

    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "error": "internal_server_error",
            "message": "An unexpected internal error occurred.",
            "request_id": request_id,
        },
    )


# ============================================================
# ROUTER REGISTRATION
# ============================================================

API_PREFIX = str(getattr(settings, "API_PREFIX", "")).rstrip("/")

# Auth endpoints — always at /auth
app.include_router(
    auth_router,
    prefix=f"{API_PREFIX}/auth" if API_PREFIX else "/auth",
    tags=["Authentication"],
)

# Scan endpoints — always at /scan
app.include_router(
    scan_router,
    prefix=f"{API_PREFIX}/scan" if API_PREFIX else "/scan",
    tags=["Scanning"],
)

# History endpoints — always at /history
app.include_router(
    history_router,
    prefix=f"{API_PREFIX}/history" if API_PREFIX else "/history",
    tags=["History"],
)


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/", tags=["System"])
async def root():
    """Public API information."""
    return {
        "status": "online",
        "service": APP_NAME,
        "version": APP_VERSION,
        "environment": ENVIRONMENT,
        "api_prefix": API_PREFIX or "/",
        "documentation": "/docs",
        "redoc": "/redoc",
        "health": "/health",
        "readiness": "/ready",
        "features": [
            "URL threat scanning",
            "Text / SMS / email analysis",
            "QR / quishing analysis",
            "Multi-signal risk scoring",
            "Explainable AI",
            "Threat intelligence",
            "Authentication",
            "Scan history",
            "SSRF protection",
            "Redirect analysis",
            "Domain intelligence",
            "UPI / financial signal analysis",
        ],
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health", tags=["System"])
async def health():
    """Liveness endpoint."""
    uptime = time.monotonic() - APP_START_TIME

    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": APP_VERSION,
        "environment": ENVIRONMENT,
        "uptime_seconds": round(uptime, 2),
    }


# ============================================================
# READINESS CHECK
# ============================================================

@app.get("/ready", tags=["System"])
async def readiness():
    """Readiness endpoint — checks DB and risk engine."""

    checks: dict = {}

    # Database
    try:
        health_fn = getattr(database, "health_check", None) or \
                    getattr(database, "check_database_health", None)

        if health_fn:
            result = health_fn()
            if hasattr(result, "__await__"):
                result = await result

            if isinstance(result, dict):
                checks["database"] = {
                    "ready": bool(result.get("healthy", result.get("ready", True))),
                    "message": str(result.get("message", "available")),
                }
            else:
                checks["database"] = {"ready": bool(result), "message": "available"}
        else:
            checks["database"] = {"ready": True, "message": "no health check defined"}

    except Exception as exc:
        checks["database"] = {"ready": False, "message": f"check failed: {exc}"}

    # Risk engine
    try:
        from backend.ai.risk_engine import CyberGuardRiskEngine
    except ImportError:
        try:
            from ai.risk_engine import CyberGuardRiskEngine
        except ImportError:
            try:
                from risk_engine import CyberGuardRiskEngine
            except ImportError:
                CyberGuardRiskEngine = None

    if CyberGuardRiskEngine is None:
        checks["risk_engine"] = {"ready": False, "message": "not importable"}
    else:
        try:
            engine = CyberGuardRiskEngine()
            checks["risk_engine"] = {"ready": engine is not None, "message": "available"}
        except Exception as exc:
            checks["risk_engine"] = {"ready": False, "message": f"init failed: {exc}"}

    overall = all(c.get("ready", False) for c in checks.values())

    return JSONResponse(
        status_code=200 if overall else 503,
        content={
            "status": "ready" if overall else "not_ready",
            "service": APP_NAME,
            "version": APP_VERSION,
            "checks": checks,
        },
    )


# ============================================================
# LOCAL ENTRYPOINT
# ============================================================

if __name__ == "__main__":
    import uvicorn

    host = str(getattr(settings, "HOST", "127.0.0.1"))
    port = int(getattr(settings, "PORT", 8000))
    reload_enabled = ENVIRONMENT == "development"

    uvicorn.run(
        "backend.main:app",
        host=host,
        port=port,
        reload=reload_enabled,
    )
