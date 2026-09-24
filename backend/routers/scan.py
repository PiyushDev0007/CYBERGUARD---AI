"""
CYBERGUARD X — Scan API Router

Responsibilities:
    - Expose URL, text and QR/quishing scan endpoints.
    - Validate incoming requests through schemas.
    - Delegate scanning to scan_service.py.
    - Return stable API responses.
    - Handle expected application errors consistently.

Architecture:

    Client
       ↓
    routers/scan.py
       ↓
    schemas.py
       ↓
    security.py
       ↓
    scan_service.py
       ↓
    threat_intelligence.py
       ↓
    risk_engine.py
       ↓
    database.py

IMPORTANT:
    This module should NOT contain the actual threat-analysis logic.
    Keep detection, intelligence, scoring and persistence in their
    dedicated modules.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import (
    APIRouter,
    File,
    HTTPException,
    UploadFile,
    status,
)

# ============================================================
# PROJECT IMPORTS
# ============================================================

try:
    from ..schemas import (
        TextScanRequest,
        URLScanRequest,
    )
except ImportError:
    # Allows running the module in environments where backend
    # is placed directly on PYTHONPATH.
    from schemas import (
        TextScanRequest,
        URLScanRequest,
    )


try:
    from ..scan_service import (
        scan_quishing,
        scan_text,
        scan_url,
    )
except ImportError:
    from scan_service import (
        scan_quishing,
        scan_text,
        scan_url,
    )


# ============================================================
# LOGGER
# ============================================================

logger = logging.getLogger("cyberguard.scan_router")


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/scan",
    tags=["Scanning"],
)


# ============================================================
# INTERNAL HELPERS
# ============================================================

def generate_scan_id() -> str:
    """
    Generate a unique identifier for a scan.

    The service layer may already return a scan_id. This helper
    provides a fallback so every successful response can expose
    a stable identifier.
    """

    return str(uuid.uuid4())


def ensure_dict(
    result: Any,
    input_type: str,
) -> dict[str, Any]:
    """
    Normalize service output into a JSON-compatible dictionary.

    The service layer is expected to return dictionaries. This
    defensive wrapper prevents accidental None/non-dict values
    from reaching the frontend.
    """

    if isinstance(result, dict):
        normalized = dict(result)
    else:
        normalized = {
            "status": "success",
            "input_type": input_type,
            "result": result,
        }

    if not normalized.get("scan_id"):
        normalized["scan_id"] = generate_scan_id()

    if not normalized.get("input_type"):
        normalized["input_type"] = input_type

    if not normalized.get("status"):
        normalized["status"] = "success"

    return normalized


def service_error(
    exc: Exception,
    operation: str,
) -> HTTPException:
    """
    Convert known service exceptions into safe API errors.

    Internal exception details are deliberately not returned to
    clients because they can expose implementation information.
    """

    if isinstance(exc, HTTPException):
        return exc

    logger.exception(
        "Scan service failure during %s",
        operation,
    )

    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=(
            "The scan could not be completed. "
            "Please try again later."
        ),
    )


# ============================================================
# URL SCANNING
# ============================================================

@router.post(
    "/url",
    summary="Scan a URL for cyber threats",
    description=(
        "Analyzes an HTTP/HTTPS URL using the CyberGuard X "
        "multi-signal threat-analysis pipeline."
    ),
    status_code=status.HTTP_200_OK,
)
async def scan_url_endpoint(
    request: URLScanRequest,
) -> dict[str, Any]:
    """
    Scan a URL.

    Processing is delegated to scan_service.scan_url().

    Expected service responsibilities:
        - URL normalization
        - SSRF protection
        - DNS/network validation
        - redirect tracing
        - domain intelligence
        - typosquatting detection
        - URL obfuscation analysis
        - threat-intelligence lookup
        - risk-engine evaluation
        - persistence

    The router only handles HTTP/API concerns.
    """

    try:
        result = await scan_url(
            request.url
        )

        return ensure_dict(
            result,
            "url",
        )

    except HTTPException:
        raise

    except ValueError as exc:
        logger.warning(
            "Invalid URL scan request: %s",
            exc,
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise service_error(
            exc,
            "URL scan",
        ) from exc


# ============================================================
# TEXT / SMS / EMAIL SCANNING
# ============================================================

@router.post(
    "/text",
    summary="Scan text, SMS or email content",
    description=(
        "Analyzes text for phishing, social-engineering, "
        "urgency, brand impersonation and financial/UPI signals."
    ),
    status_code=status.HTTP_200_OK,
)
async def scan_text_endpoint(
    request: TextScanRequest,
) -> dict[str, Any]:
    """
    Scan text/SMS/email content.

    The actual NLP/security analysis is handled by scan_service.py.
    """

    try:
        result = await scan_text(
            request.text
        )

        return ensure_dict(
            result,
            "text/sms/email",
        )

    except HTTPException:
        raise

    except ValueError as exc:
        logger.warning(
            "Invalid text scan request: %s",
            exc,
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise service_error(
            exc,
            "text scan",
        ) from exc


# ============================================================
# QR / QUISHING SCANNING
# ============================================================

@router.post(
    "/quishing",
    summary="Scan a QR image for quishing threats",
    description=(
        "Decodes a QR image and analyzes URL, UPI or text "
        "payloads for suspicious behavior."
    ),
    status_code=status.HTTP_200_OK,
)
async def scan_quishing_endpoint(
    file: UploadFile = File(
        ...,
        description=(
            "QR image in PNG, JPEG or WEBP format."
        ),
    ),
) -> dict[str, Any]:
    """
    Scan a QR image.

    File validation and QR analysis are delegated to the service
    layer. The router handles only the API boundary.
    """

    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file was provided.",
        )

    try:
        result = await scan_quishing(
            file
        )

        return ensure_dict(
            result,
            "qr",
        )

    except HTTPException:
        raise

    except ValueError as exc:
        logger.warning(
            "Invalid QR scan request: %s",
            exc,
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise service_error(
            exc,
            "QR/quishing scan",
        ) from exc


# ============================================================
# GENERIC SCAN STATUS
# ============================================================

@router.get(
    "/capabilities",
    summary="Get available scanning capabilities",
)
async def scan_capabilities() -> dict[str, Any]:
    """
    Return the scan capabilities exposed by this API router.

    This is useful for the frontend so it can discover available
    scanning modes without hard-coding them.
    """

    return {
        "status": "success",
        "service": "CYBERGUARD X",
        "capabilities": {
            "url": {
                "enabled": True,
                "endpoint": "/scan/url",
                "method": "POST",
                "description": (
                    "URL threat and reputation analysis."
                ),
            },
            "text": {
                "enabled": True,
                "endpoint": "/scan/text",
                "method": "POST",
                "description": (
                    "SMS, email and text phishing analysis."
                ),
            },
            "quishing": {
                "enabled": True,
                "endpoint": "/scan/quishing",
                "method": "POST",
                "description": (
                    "QR-code payload and quishing analysis."
                ),
            },
        },
    }


# ============================================================
# ROUTER HEALTH
# ============================================================

@router.get(
    "/health",
    summary="Check scan router availability",
)
async def scan_router_health() -> dict[str, Any]:
    """
    Lightweight health endpoint for the scan API layer.

    This does not perform a real scan.
    """

    return {
        "status": "healthy",
        "service": "cyberguard-scan-router",
        "routes": {
            "url": True,
            "text": True,
            "quishing": True,
        },
    }


# ============================================================
# ERROR HANDLING NOTES
# ============================================================

"""
Expected HTTP behavior
----------------------

400
    Invalid input, unsupported file, unsafe target, etc.

413
    Payload/file too large.

422
    FastAPI/Pydantic validation error.

429
    Rate limit exceeded, when rate limiting is added.

500
    Unexpected internal service failure.

502
    External intelligence provider failure, if the service layer
    chooses to expose provider-specific failures.

503
    Required backend dependency temporarily unavailable.

The router intentionally avoids returning raw Python exception
messages for unexpected errors.
"""


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "router",
]
