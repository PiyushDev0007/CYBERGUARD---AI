"""
CYBERGUARD X — Backend Application Entrypoint

Responsibilities
----------------
- Create the FastAPI application
- Load centralized configuration
- Register API routers
- Configure CORS
- Initialize database resources
- Configure application lifecycle
- Provide health/readiness endpoints
- Provide global exception handling
- Expose API metadata
- Keep business/scanning logic OUT of main.py

Expected project structure
--------------------------

backend/
├── main.py
├── config.py
├── database.py
├── security.py
├── schemas.py
├── auth_service.py
├── history_service.py
├── scan_service.py
├── threat_intelligence.py
├── ai/
│   └── risk_engine.py
└── routers/
    ├── auth.py
    ├── scan.py
    └── history.py

Run
---

From the project root:

    uvicorn backend.main:app --reload

Production example:

    uvicorn backend.main:app --host 0.0.0.0 --port 8000

"""

from __future__ import annotations

import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ============================================================
# OPTIONAL STARLETTE HTTP EXCEPTION
# ============================================================

try:
    from starlette.exceptions import HTTPException as StarletteHTTPException
except ImportError:
    StarletteHTTPException = Exception  # type: ignore


# ============================================================
# CONFIGURATION
# ============================================================

try:
    from config import settings
except ImportError as exc:
    raise RuntimeError(
        "Could not import 'settings' from config.py. "
        "Make sure backend/config.py exists and exposes "
        "a 'settings' object."
    ) from exc


# ============================================================
# DATABASE
# ============================================================

try:
    import database
except ImportError as exc:
    raise RuntimeError(
        "Could not import backend/database.py."
    ) from exc


# ============================================================
# ROUTERS
# ============================================================

try:
    from routers.auth import router as auth_router
except ImportError as exc:
    raise RuntimeError(
        "Could not import routers.auth."
    ) from exc

try:
    from routers.scan import router as scan_router
except ImportError as exc:
    raise RuntimeError(
        "Could not import routers.scan."
    ) from exc

try:
    from routers.history import router as history_router
except ImportError as exc:
    raise RuntimeError(
        "Could not import routers.history."
    ) from exc


# ============================================================
# LOGGING
# ============================================================

LOG_LEVEL = str(
    getattr(settings, "LOG_LEVEL", "INFO")
).upper()

LOG_FORMAT = (
    "%(asctime)s | "
    "%(levelname)s | "
    "%(name)s | "
    "%(message)s"
)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format=LOG_FORMAT,
)

logger = logging.getLogger("cyberguard-x")


# ============================================================
# APPLICATION METADATA
# ============================================================

APP_NAME = str(
    getattr(
        settings,
        "APP_NAME",
        "CYBERGUARD X",
    )
)

APP_VERSION = str(
    getattr(
        settings,
        "APP_VERSION",
        "3.0.0",
    )
)

APP_DESCRIPTION = str(
    getattr(
        settings,
        "APP_DESCRIPTION",
        (
            "CYBERGUARD X — Multi-signal cybersecurity "
            "threat detection and analysis platform."
        ),
    )
)

ENVIRONMENT = str(
    getattr(
        settings,
        "ENVIRONMENT",
        os.getenv(
            "ENVIRONMENT",
            "development",
        ),
    )
).lower()


# ============================================================
# CORS CONFIGURATION
# ============================================================

def _load_cors_origins() -> list[str]:
    """
    Load allowed CORS origins from configuration.

    Supports either:

        settings.CORS_ORIGINS

    as a list/tuple/set, or a comma-separated string.

    Development fallback:
        http://localhost:3000
        http://localhost:5173
        http://127.0.0.1:3000
        http://127.0.0.1:5173
    """

    configured = getattr(
        settings,
        "CORS_ORIGINS",
        None,
    )

    if configured is None:
        configured = os.getenv(
            "CORS_ORIGINS",
            "",
        )

    if isinstance(
        configured,
        str,
    ):
        origins = [
            item.strip()
            for item in configured.split(",")
            if item.strip()
        ]

    elif isinstance(
        configured,
        (list, tuple, set),
    ):
        origins = [
            str(item).strip()
            for item in configured
            if str(item).strip()
        ]

    else:
        origins = []

    if not origins:
        origins = [
            "http://localhost:3000",
            "http://localhost:5173",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
        ]

    return origins


CORS_ORIGINS = _load_cors_origins()


# ============================================================
# REQUEST LIMITS
# ============================================================

MAX_REQUEST_BODY_BYTES = int(
    getattr(
        settings,
        "MAX_REQUEST_BODY_BYTES",
        10 * 1024 * 1024,
    )
)

MAX_REQUEST_BODY_BYTES = max(
    1024,
    MAX_REQUEST_BODY_BYTES,
)


# ============================================================
# APPLICATION STATE
# ============================================================

APP_START_TIME = time.monotonic()


# ============================================================
# LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(application: FastAPI):
    """
    Application startup/shutdown lifecycle.

    Startup:
        - initialize database
        - log configuration
        - perform basic service checks

    Shutdown:
        - close database resources if supported
        - release application resources
    """

    logger.info(
        "Starting %s v%s",
        APP_NAME,
        APP_VERSION,
    )

    logger.info(
        "Environment: %s",
        ENVIRONMENT,
    )

    # --------------------------------------------------------
    # DATABASE INITIALIZATION
    # --------------------------------------------------------

    try:
        initialize_database = getattr(
            database,
            "init_db",
            None,
        )

        if initialize_database is None:
            initialize_database = getattr(
                database,
                "initialize_database",
                None,
            )

        if initialize_database is not None:
            result = initialize_database()

            # Support both synchronous and asynchronous
            # initialization functions.
            if hasattr(
                result,
                "__await__",
            ):
                await result

            logger.info(
                "Database initialization completed."
            )

        else:
            logger.warning(
                "No database initialization function "
                "was found in database.py."
            )

    except Exception:
        logger.exception(
            "Database initialization failed."
        )

        # In development, failing fast is useful.
        # In production, configuration may choose whether
        # database failure should prevent startup.
        fail_on_db_error = bool(
            getattr(
                settings,
                "FAIL_ON_DATABASE_STARTUP_ERROR",
                True,
            )
        )

        if fail_on_db_error:
            raise

    # --------------------------------------------------------
    # STARTUP LOGGING
    # --------------------------------------------------------

    logger.info(
        "CORS origins configured: %s",
        CORS_ORIGINS,
    )

    logger.info(
        "Maximum request body size: %d bytes",
        MAX_REQUEST_BODY_BYTES,
    )

    logger.info(
        "CYBERGUARD X backend startup complete."
    )

    try:
        yield

    finally:
        # ----------------------------------------------------
        # DATABASE SHUTDOWN
        # ----------------------------------------------------

        try:
            close_database = getattr(
                database,
                "close_db",
                None,
            )

            if close_database is None:
                close_database = getattr(
                    database,
                    "close_database",
                    None,
                )

            if close_database is not None:
                result = close_database()

                if hasattr(
                    result,
                    "__await__",
                ):
                    await result

                logger.info(
                    "Database shutdown completed."
                )

        except Exception:
            logger.exception(
                "Error while shutting down database."
            )

        logger.info(
            "CYBERGUARD X backend shutdown complete."
        )


# ============================================================
# FASTAPI APPLICATION
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

allow_credentials = bool(
    getattr(
        settings,
        "CORS_ALLOW_CREDENTIALS",
        True,
    )
)

# Wildcard origins and credentials are incompatible in
# browsers. If "*" is explicitly configured, disable
# credentials unless the configuration explicitly uses
# concrete origins.
if "*" in CORS_ORIGINS:
    allow_credentials = False


app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# REQUEST ID + BASIC REQUEST LOGGING
# ============================================================

@app.middleware("http")
async def request_context_middleware(
    request: Request,
    call_next,
):
    """
    Attach a unique request ID to every request.

    The ID is returned in the response header:

        X-Request-ID

    It also appears in request logs.
    """

    request_id = request.headers.get(
        "X-Request-ID"
    )

    if not request_id:
        request_id = uuid.uuid4().hex

    request.state.request_id = request_id

    started = time.monotonic()

    try:
        response = await call_next(request)

    except Exception:
        elapsed = time.monotonic() - started

        logger.exception(
            "Unhandled request exception | "
            "request_id=%s | "
            "method=%s | "
            "path=%s | "
            "duration=%.3fs",
            request_id,
            request.method,
            request.url.path,
            elapsed,
        )

        raise

    elapsed = time.monotonic() - started

    response.headers[
        "X-Request-ID"
    ] = request_id

    response.headers[
        "X-Response-Time"
    ] = f"{elapsed:.4f}s"

    logger.info(
        "HTTP request | "
        "request_id=%s | "
        "method=%s | "
        "path=%s | "
        "status=%s | "
        "duration=%.3fs",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        elapsed,
    )

    return response


# ============================================================
# SECURITY HEADERS
# ============================================================

@app.middleware("http")
async def security_headers_middleware(
    request: Request,
    call_next,
):
    """
    Add defensive HTTP response headers.

    These headers do not replace authentication, authorization,
    SSRF protection, validation or rate limiting.
    """

    response = await call_next(request)

    response.headers.setdefault(
        "X-Content-Type-Options",
        "nosniff",
    )

    response.headers.setdefault(
        "X-Frame-Options",
        "DENY",
    )

    response.headers.setdefault(
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
    )

    response.headers.setdefault(
        "Permissions-Policy",
        (
            "camera=(), "
            "microphone=(), "
            "geolocation=()"
        ),
    )

    response.headers.setdefault(
        "Cross-Origin-Opener-Policy",
        "same-origin",
    )

    response.headers.setdefault(
        "Cross-Origin-Resource-Policy",
        "same-site",
    )

    # HSTS should only be enabled when the application is
    # actually served over HTTPS.
    enable_hsts = bool(
        getattr(
            settings,
            "ENABLE_HSTS",
            ENVIRONMENT == "production",
        )
    )

    if enable_hsts:
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )

    return response


# ============================================================
# REQUEST BODY SIZE PROTECTION
# ============================================================

@app.middleware("http")
async def request_size_middleware(
    request: Request,
    call_next,
):
    """
    Reject obviously oversized requests.

    Note:
        Multipart uploads may also have application-level
        limits in the scan router. This middleware provides
        a general upper bound for all requests.
    """

    content_length = request.headers.get(
        "content-length"
    )

    if content_length:
        try:
            content_length_value = int(
                content_length
            )

            if (
                content_length_value
                > MAX_REQUEST_BODY_BYTES
            ):
                request_id = getattr(
                    request.state,
                    "request_id",
                    uuid.uuid4().hex,
                )

                return JSONResponse(
                    status_code=413,
                    content={
                        "status": "error",
                        "error": "request_too_large",
                        "message": (
                            "Request body exceeds the "
                            "configured maximum size."
                        ),
                        "request_id": request_id,
                    },
                    headers={
                        "X-Request-ID": request_id,
                    },
                )

        except ValueError:
            pass

    return await call_next(request)


# ============================================================
# GLOBAL HTTP EXCEPTION HANDLER
# ============================================================

@app.exception_handler(
    StarletteHTTPException
)
async def http_exception_handler(
    request: Request,
    exc: StarletteHTTPException,
):
    """
    Return consistent API errors.
    """

    request_id = getattr(
        request.state,
        "request_id",
        uuid.uuid4().hex,
    )

    detail = exc.detail

    if isinstance(
        detail,
        dict,
    ):
        message = detail.get(
            "message",
            "Request failed.",
        )
        error_detail: Any = detail

    else:
        message = str(
            detail
            or "Request failed."
        )
        error_detail = detail

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "error": "http_error",
            "message": message,
            "detail": error_detail,
            "request_id": request_id,
        },
        headers={
            "X-Request-ID": request_id,
        },
    )


# ============================================================
# VALIDATION EXCEPTION HANDLER
# ============================================================

@app.exception_handler(
    RequestValidationError
)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
):
    """
    Return clean validation errors instead of exposing
    framework-specific response structures.
    """

    request_id = getattr(
        request.state,
        "request_id",
        uuid.uuid4().hex,
    )

    errors = []

    for error in exc.errors():
        location = [
            str(item)
            for item in error.get(
                "loc",
                [],
            )
        ]

        errors.append(
            {
                "location": location,
                "message": str(
                    error.get(
                        "msg",
                        "Invalid value.",
                    )
                ),
                "type": str(
                    error.get(
                        "type",
                        "validation_error",
                    )
                ),
            }
        )

    return JSONResponse(
        status_code=422,
        content={
            "status": "error",
            "error": "validation_error",
            "message": (
                "One or more request fields "
                "failed validation."
            ),
            "details": errors,
            "request_id": request_id,
        },
        headers={
            "X-Request-ID": request_id,
        },
    )


# ============================================================
# GLOBAL EXCEPTION HANDLER
# ============================================================

@app.exception_handler(
    Exception
)
async def global_exception_handler(
    request: Request,
    exc: Exception,
):
    """
    Last-resort exception handler.

    Detailed exception information is logged server-side but
    deliberately not returned to clients.
    """

    request_id = getattr(
        request.state,
        "request_id",
        uuid.uuid4().hex,
    )

    logger.exception(
        "Unhandled application error | "
        "request_id=%s | "
        "method=%s | "
        "path=%s",
        request_id,
        request.method,
        request.url.path,
    )

    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "error": "internal_server_error",
            "message": (
                "An unexpected internal error occurred."
            ),
            "request_id": request_id,
        },
        headers={
            "X-Request-ID": request_id,
        },
    )


# ============================================================
# ROUTER REGISTRATION
# ============================================================

API_PREFIX = str(
    getattr(
        settings,
        "API_PREFIX",
        "/api/v1",
    )
).rstrip("/")


# ------------------------------------------------------------
# AUTH
# ------------------------------------------------------------

app.include_router(
    auth_router,
    prefix=f"{API_PREFIX}/auth",
    tags=["Authentication"],
)


# ------------------------------------------------------------
# SCANNING
# ------------------------------------------------------------

app.include_router(
    scan_router,
    prefix=f"{API_PREFIX}/scan",
    tags=["Threat Scanning"],
)


# ------------------------------------------------------------
# HISTORY
# ------------------------------------------------------------

app.include_router(
    history_router,
    prefix=f"{API_PREFIX}/history",
    tags=["Scan History"],
)


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get(
    "/",
    tags=["System"],
)
async def root():
    """
    Public API information endpoint.
    """

    return {
        "status": "online",
        "service": APP_NAME,
        "version": APP_VERSION,
        "environment": ENVIRONMENT,
        "api_prefix": API_PREFIX,
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

@app.get(
    "/health",
    tags=["System"],
)
async def health():
    """
    Lightweight liveness endpoint.

    Liveness means:
        The FastAPI process is running.
    """

    uptime_seconds = (
        time.monotonic()
        - APP_START_TIME
    )

    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": APP_VERSION,
        "environment": ENVIRONMENT,
        "uptime_seconds": round(
            uptime_seconds,
            2,
        ),
    }


# ============================================================
# READINESS CHECK
# ============================================================

@app.get(
    "/ready",
    tags=["System"],
)
async def readiness():
    """
    Readiness endpoint.

    Attempts to determine whether required backend resources
    are available.

    This is intentionally defensive because database.py may
    expose different implementations depending on the project
    stage.
    """

    checks: dict[str, Any] = {}

    # --------------------------------------------------------
    # DATABASE
    # --------------------------------------------------------

    database_ready = True
    database_message = "available"

    try:
        health_check = getattr(
            database,
            "health_check",
            None,
        )

        if health_check is None:
            health_check = getattr(
                database,
                "check_database_health",
                None,
            )

        if health_check is not None:
            result = health_check()

            if hasattr(
                result,
                "__await__",
            ):
                result = await result

            if isinstance(
                result,
                dict,
            ):
                database_ready = bool(
                    result.get(
                        "healthy",
                        result.get(
                            "ready",
                            True,
                        ),
                    )
                )

                database_message = str(
                    result.get(
                        "message",
                        "available",
                    )
                )

            else:
                database_ready = bool(
                    result
                )

        else:
            database_message = (
                "database health-check function "
                "not implemented"
            )

    except Exception as exc:
        database_ready = False
        database_message = (
            "database health check failed"
        )

        logger.warning(
            "Database readiness check failed: %s",
            exc,
        )

    checks["database"] = {
        "ready": database_ready,
        "message": database_message,
    }

    # --------------------------------------------------------
    # RISK ENGINE
    # --------------------------------------------------------

    risk_engine_ready = True

    try:
        from ai.risk_engine import (
            CyberGuardRiskEngine,
        )

        # The actual engine is normally initialized by the
        # scan service. This check verifies that the module
        # can be imported and instantiated.
        engine = CyberGuardRiskEngine()

        risk_engine_ready = (
            engine is not None
        )

    except Exception as exc:
        risk_engine_ready = False

        logger.warning(
            "Risk engine readiness check failed: %s",
            exc,
        )

    checks["risk_engine"] = {
        "ready": risk_engine_ready,
    }

    # --------------------------------------------------------
    # OVERALL STATUS
    # --------------------------------------------------------

    overall_ready = all(
        bool(
            item.get(
                "ready",
                False,
            )
        )
        for item in checks.values()
    )

    return JSONResponse(
        status_code=(
            200
            if overall_ready
            else 503
        ),
        content={
            "status": (
                "ready"
                if overall_ready
                else "not_ready"
            ),
            "service": APP_NAME,
            "version": APP_VERSION,
            "checks": checks,
        },
    )


# ============================================================
# API STATUS ENDPOINT
# ============================================================

@app.get(
    f"{API_PREFIX}/status",
    tags=["System"],
)
async def api_status():
    """
    API-level status endpoint useful for frontend integration.
    """

    return {
        "status": "online",
        "api_version": API_PREFIX.split("/")[-1]
        if API_PREFIX
        else "v1",
        "service": APP_NAME,
        "backend_version": APP_VERSION,
        "environment": ENVIRONMENT,
        "routers": {
            "authentication": "enabled",
            "scanning": "enabled",
            "history": "enabled",
        },
    }


# ============================================================
# OPTIONAL DEVELOPMENT ENDPOINT
# ============================================================

if ENVIRONMENT == "development":

    @app.get(
        f"{API_PREFIX}/debug/config",
        tags=["Development"],
        include_in_schema=False,
    )
    async def debug_config():
        """
        Development-only configuration diagnostics.

        IMPORTANT:
            Never expose API keys, passwords, JWT secrets,
            database credentials or other sensitive values.
        """

        return {
            "environment": ENVIRONMENT,
            "app_name": APP_NAME,
            "app_version": APP_VERSION,
            "api_prefix": API_PREFIX,
            "cors_origins": CORS_ORIGINS,
            "max_request_body_bytes": (
                MAX_REQUEST_BODY_BYTES
            ),
            "database_configured": bool(
                getattr(
                    settings,
                    "DATABASE_URL",
                    None,
                )
            ),
            "virustotal_configured": bool(
                getattr(
                    settings,
                    "VIRUSTOTAL_API_KEY",
                    None,
                )
                or os.getenv(
                    "VIRUSTOTAL_API_KEY"
                )
            ),
        }


# ============================================================
# LOCAL DEVELOPMENT ENTRYPOINT
# ============================================================

if __name__ == "__main__":
    """
    Allows:

        python backend/main.py

    Recommended production/development command remains:

        uvicorn backend.main:app --reload
    """

    import uvicorn

    host = str(
        getattr(
            settings,
            "HOST",
            "127.0.0.1",
        )
    )

    port = int(
        getattr(
            settings,
            "PORT",
            8000,
        )
    )

    reload_enabled = (
        ENVIRONMENT == "development"
    )

    uvicorn.run(
        "backend.main:app",
        host=host,
        port=port,
        reload=reload_enabled,
    )
