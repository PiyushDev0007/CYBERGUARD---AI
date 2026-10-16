"""
CYBERGUARD X — Scan Router
===========================

API endpoints:
    POST /scan/url           → Analyze a URL
    POST /scan/text          → Analyze SMS/email/message
    POST /scan/quishing      → Analyze a QR image
    GET  /scan/capabilities  → List available scanners
    GET  /scan/health        → Router health check

Business logic lives in:
    backend/scan_service.py
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
    from schemas import (
        TextScanRequest,
        URLScanRequest,
    )
except ImportError:
    from backend.schemas import (
        TextScanRequest,
        URLScanRequest,
    )

try:
    from scan_service import (
        scan_quishing,
        scan_text,
        scan_url,
    )
except ImportError:
    from backend.scan_service import (
        scan_quishing,
        scan_text,
        scan_url,
    )


# ============================================================
# LOGGING
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
# HELPERS
# ============================================================

def generate_scan_id() -> str:
    """Generate a unique scan identifier."""
    return str(uuid.uuid4())


def ensure_dict(result: Any, input_type: str) -> dict[str, Any]:
    """
    Normalize service output into a JSON-compatible dict.

    Defensive wrapper so frontend always receives the expected
    shape, even if the service returns an unexpected value.
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


def service_error(exc: Exception, operation: str) -> HTTPException:
    """
    Convert unexpected service exceptions into safe API errors.

    Internal exception details are never returned to clients.
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
# POST /scan/url
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

    Delegates to scan_service.scan_url().
    """
    try:
        result = await scan_url(request.url)
        return ensure_dict(result, "url")

    except HTTPException:
        raise

    except ValueError as exc:
        logger.warning("Invalid URL scan request: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise service_error(exc, "URL scan") from exc


# ============================================================
# POST /scan/text
# ============================================================

@router.post(
    "/text",
    summary="Scan text, SMS or email content",
    description=(
        "Analyzes text for phishing, social-engineering, urgency, "
        "brand impersonation and financial/UPI signals."
    ),
    status_code=status.HTTP_200_OK,
)
async def scan_text_endpoint(
    request: TextScanRequest,
) -> dict[str, Any]:
    """
    Scan text/SMS/email content.

    Delegates to scan_service.scan_text().
    """
    try:
        result = await scan_text(request.text)
        return ensure_dict(result, "text/sms/email")

    except HTTPException:
        raise

    except ValueError as exc:
        logger.warning("Invalid text scan request: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise service_error(exc, "text scan") from exc


# ============================================================
# POST /scan/quishing
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
        description="QR image in PNG, JPEG or WEBP format.",
    ),
) -> dict[str, Any]:
    """
    Scan a QR image.

    Delegates to scan_service.scan_quishing().
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file was provided.",
        )

    try:
        result = await scan_quishing(file)
        return ensure_dict(result, "qr")

    except HTTPException:
        raise

    except ValueError as exc:
        logger.warning("Invalid QR scan request: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise service_error(exc, "QR/quishing scan") from exc


# ============================================================
# GET /scan/capabilities
# ============================================================

@router.get(
    "/capabilities",
    summary="Get available scanning capabilities",
)
async def scan_capabilities() -> dict[str, Any]:
    """
    Return the scan capabilities exposed by this router.
    """
    return {
        "status": "success",
        "service": "CYBERGUARD X",
        "capabilities": {
            "url": {
                "enabled": True,
                "endpoint": "/scan/url",
                "method": "POST",
                "description": "URL threat and reputation analysis.",
            },
            "text": {
                "enabled": True,
                "endpoint": "/scan/text",
                "method": "POST",
                "description": "SMS, email and text phishing analysis.",
            },
            "quishing": {
                "enabled": True,
                "endpoint": "/scan/quishing",
                "method": "POST",
                "description": "QR-code payload and quishing analysis.",
            },
        },
    }


# ============================================================
# GET /scan/health
# ============================================================

@router.get(
    "/health",
    summary="Check scan router availability",
)
async def scan_router_health() -> dict[str, Any]:
    """
    Lightweight health endpoint for the scan API layer.
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
