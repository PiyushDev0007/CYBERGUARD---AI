"""
CYBERGUARD X — Scan Service
============================

Orchestration layer between API routers and the detection engine.

Responsibilities:
    - URL scanning  → scan_url()
    - Text scanning → scan_text()
    - QR scanning   → scan_quishing()

Uses:
    - ai.risk_engine          → risk scoring
    - threat_intelligence     → VT / RDAP / DNS
    - database                → persistence
    - security                → SSRF protection

Exposes three simple async functions for routers/scan.py:

    await scan_url(url: str)
    await scan_text(text: str)
    await scan_quishing(file: UploadFile)
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import cv2
import numpy as np

from fastapi import HTTPException, UploadFile, status


# ============================================================
# PROJECT IMPORTS
# ============================================================

try:
    from ai.risk_engine import (
        CyberGuardRiskEngine,
        ThreatSignals,
    )
except ImportError:
    try:
        from backend.ai.risk_engine import (
            CyberGuardRiskEngine,
            ThreatSignals,
        )
    except ImportError:
        from risk_engine import (
            CyberGuardRiskEngine,
            ThreatSignals,
        )

try:
    from threat_intelligence import (
        get_threat_intelligence_service,
    )
except ImportError:
    try:
        from backend.threat_intelligence import (
            get_threat_intelligence_service,
        )
    except ImportError:
        get_threat_intelligence_service = None

try:
    from database import (
        database_session,
        create_scan,
    )
except ImportError:
    try:
        from backend.database import (
            database_session,
            create_scan,
        )
    except ImportError:
        database_session = None
        create_scan = None

try:
    from security import (
        validate_scan_url,
        validate_scan_text,
        sanitize_filename,
    )
except ImportError:
    try:
        from backend.security import (
            validate_scan_url,
            validate_scan_text,
            sanitize_filename,
        )
    except ImportError:
        # Fallbacks if security.py unavailable
        def validate_scan_url(url): return url
        def validate_scan_text(text): return text
        def sanitize_filename(name): return name or "upload"


# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger("cyberguard.scan_service")


# ============================================================
# CONSTANTS
# ============================================================

MAX_URL_LENGTH = 4096
MAX_TEXT_LENGTH = 50000
MAX_QR_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".zip", ".mov", ".click", ".work", ".live",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl",
    "ow.ly", "buff.ly", "cutt.ly", "shorturl.at",
}

URGENCY_KEYWORDS = [
    "urgent", "immediately", "verify now", "act now",
    "account blocked", "account suspended", "kyc",
    "otp", "refund", "winner", "prize", "claim now",
    "limited time", "last warning", "security alert",
]

BRAND_NAMES = [
    "sbi", "hdfc", "icici", "axis", "kotak",
    "paytm", "phonepe", "google", "microsoft", "apple",
    "amazon", "netflix", "paypal", "instagram", "facebook",
    "whatsapp", "telegram", "flipkart",
]

UPI_HANDLES = ["@ybl", "@okaxis", "@oksbi", "@okhdfcbank",
               "@paytm", "@ibl", "@axl"]


# ============================================================
# SHARED ENGINE INSTANCE
# ============================================================

_risk_engine: Optional[CyberGuardRiskEngine] = None


def get_risk_engine() -> CyberGuardRiskEngine:
    """Return shared risk engine instance."""
    global _risk_engine
    if _risk_engine is None:
        _risk_engine = CyberGuardRiskEngine()
    return _risk_engine


# ============================================================
# HELPERS
# ============================================================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_scan_id() -> str:
    return str(uuid.uuid4())


def get_hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def detect_urgency(text: str) -> tuple[float, list[str]]:
    """Rule-based urgency detection."""
    if not text:
        return 0.0, []

    lowered = text.lower()
    matches = [kw for kw in URGENCY_KEYWORDS if kw in lowered]
    score = min(len(matches) * 0.20, 1.0)
    return round(score, 3), matches


def detect_upi(text: str) -> tuple[int, list[str]]:
    """Detect UPI/ payment anomalies."""
    lowered = text.lower()
    findings = []

    if "upi://" in lowered:
        findings.append("UPI URI detected.")

    for handle in UPI_HANDLES:
        if handle in lowered:
            findings.append(f"UPI handle detected: {handle}")

    return (1 if findings else 0), findings


def detect_brands(text: str) -> list[str]:
    """Detect known brand mentions."""
    lowered = text.lower()
    return [b for b in BRAND_NAMES if b in lowered]


def is_suspicious_tld(domain: str) -> bool:
    return any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)


def is_url_shortener(domain: str) -> bool:
    return domain in URL_SHORTENERS


def simple_typosquat(domain: str) -> float:
    """
    Lightweight typosquat similarity.

    Returns 0.0-1.0 score.
    """
    if not domain:
        return 0.0

    labels = domain.split(".")
    main = labels[-2] if len(labels) >= 2 else labels[0]

    from difflib import SequenceMatcher

    best = 0.0
    for brand in BRAND_NAMES:
        if brand == main:
            continue
        ratio = SequenceMatcher(None, main, brand).ratio()
        if ratio > best:
            best = ratio

    return round(best if best >= 0.7 else 0.0, 3)


# ============================================================
# RISK ASSESSMENT NORMALIZATION
# ============================================================

def normalize_assessment(result: Any) -> dict[str, Any]:
    """Ensure assessment has consistent shape for frontend."""
    if not isinstance(result, dict):
        result = {}

    score = result.get("score", result.get("risk_score", 0.0))
    try:
        score = float(score)
    except (TypeError, ValueError):
        score = 0.0

    score = max(0.0, min(100.0, round(score, 2)))

    severity = str(result.get("severity", "LOW")).upper()
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        severity = "LOW"

    xai = result.get("xai") or result.get("xai_breakdown") or []
    if not isinstance(xai, list):
        xai = [str(xai)]

    return {
        **result,
        "score": score,
        "risk_score": score,
        "severity": severity,
        "explanation": str(
            result.get("explanation")
            or "Risk assessment completed."
        ),
        "xai": xai,
    }


# ============================================================
# PERSISTENCE HELPER
# ============================================================

def persist_scan(
    scan_id: str,
    scan_type: str,
    input_value: str,
    assessment: dict[str, Any],
    metadata: dict[str, Any],
    trace: Optional[dict[str, Any]] = None,
    threat_intelligence: Optional[dict[str, Any]] = None,
    original_url: Optional[str] = None,
    final_url: Optional[str] = None,
    domain: Optional[str] = None,
) -> None:
    """
    Save scan to database.

    Fails silently if database unavailable — the scan result
    is still returned to the user.
    """
    if database_session is None or create_scan is None:
        logger.debug("Database not available, skipping persistence.")
        return

    try:
        with database_session() as db:
            create_scan(
                db,
                scan_id=scan_id,
                scan_type=scan_type,
                input_value=input_value,
                assessment=assessment,
                metadata=metadata,
                trace=trace or {},
                threat_intelligence=threat_intelligence or {},
                original_url=original_url,
                final_url=final_url,
                domain=domain,
            )
    except Exception:
        logger.exception("Failed to persist scan %s", scan_id)


# ============================================================
# 1. URL SCAN
# ============================================================

async def scan_url(url: str) -> dict[str, Any]:
    """
    Scan a URL for threats.

    Returns dict matching frontend contract:
        {
          status, input_type, scan_id,
          assessment: { score, severity, explanation, xai },
          trace: { original_url, final_url, hops },
          metadata: { domain, ... }
        }
    """

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    url = str(url or "").strip()

    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL cannot be empty.",
        )

    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL is too long.",
        )

    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only HTTP/HTTPS URLs are supported.",
        )

    if not parsed.hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL must contain a valid hostname.",
        )

    # --------------------------------------------------------
    # Extract signals
    # --------------------------------------------------------

    domain = get_hostname(url)

    typosquat = simple_typosquat(domain)
    suspicious_tld = is_suspicious_tld(domain)
    shortener = is_url_shortener(domain)
    scheme = parsed.scheme.lower()
    is_http = scheme == "http"

    # Domain age (RDAP) via threat intelligence service
    domain_age_score = 0.10
    domain_age_days: Optional[int] = None
    registration_date: Optional[str] = None

    vt_result: dict[str, Any] = {}

    if get_threat_intelligence_service is not None:
        try:
            ti_service = get_threat_intelligence_service()

            rdap = await ti_service.get_rdap_domain(domain)

            if rdap.get("status") == "success":
                domain_age_days = rdap.get("age_days")
                registration_date = rdap.get("registration_date")

                if domain_age_days is not None:
                    if domain_age_days < 30:
                        domain_age_score = 0.90
                    elif domain_age_days < 90:
                        domain_age_score = 0.60
                    elif domain_age_days < 365:
                        domain_age_score = 0.30
                    else:
                        domain_age_score = 0.10

            # VirusTotal
            vt_result = await ti_service.check_virustotal_url(url)

        except Exception:
            logger.exception("Threat intel failed for %s", url)

    # Count external IOCs
    ioc_count = 0
    if suspicious_tld:
        ioc_count += 1
    if typosquat >= 0.78:
        ioc_count += 1
    if shortener:
        ioc_count += 1
    if vt_result.get("status") == "malicious":
        ioc_count += 1

    # --------------------------------------------------------
    # Build ThreatSignals
    # --------------------------------------------------------

    signals = ThreatSignals(
        domain_age_days=domain_age_score,
        redirect_hops=0,
        typosquat_similarity=typosquat,
        nlp_urgency_score=0.0,
        auth_failure_flag=int(is_http),
        visual_brand_spoof=typosquat,
        external_ioc_hits=min(ioc_count, 3),
        upi_anomaly_flag=0,
    )

    # --------------------------------------------------------
    # Evaluate risk
    # --------------------------------------------------------

    engine = get_risk_engine()
    assessment = normalize_assessment(engine.evaluate(signals))

    # Add extra XAI from URL heuristics
    extra_xai = list(assessment.get("xai", []))

    if suspicious_tld:
        extra_xai.append(f"Suspicious TLD detected: {domain}")

    if shortener:
        extra_xai.append("URL-shortening service detected.")

    if is_http:
        extra_xai.append("Unencrypted HTTP URL detected.")

    if domain_age_days is not None and domain_age_days < 90:
        extra_xai.append(
            f"Domain age is only ~{domain_age_days} days."
        )

    if vt_result.get("status") == "malicious":
        extra_xai.append(
            f"VirusTotal: {vt_result.get('malicious', 0)} malicious detections."
        )

    assessment["xai"] = list(dict.fromkeys(extra_xai))[:15]

    # --------------------------------------------------------
    # Build result
    # --------------------------------------------------------

    scan_id = new_scan_id()

    result = {
        "status": "success",
        "input_type": "url",
        "scan_id": scan_id,
        "scanned_at": utc_now_iso(),
        "assessment": assessment,
        "trace": {
            "original_url": url,
            "final_url": url,
            "hops": [],
        },
        "metadata": {
            "domain": domain,
            "scheme": scheme,
            "suspicious_tld": suspicious_tld,
            "url_shortener": shortener,
            "domain_age_days": domain_age_days,
            "registration_date": registration_date,
            "typosquat_similarity": typosquat,
            "ioc_indicator_count": ioc_count,
            "virustotal": vt_result,
        },
    }

    # --------------------------------------------------------
    # Persist
    # --------------------------------------------------------

    persist_scan(
        scan_id=scan_id,
        scan_type="url",
        input_value=url,
        assessment=assessment,
        metadata=result["metadata"],
        trace=result["trace"],
        threat_intelligence=vt_result,
        original_url=url,
        final_url=url,
        domain=domain,
    )

    return result


# ============================================================
# 2. TEXT SCAN
# ============================================================

async def scan_text(text: str) -> dict[str, Any]:
    """
    Scan SMS/email/message text for scam indicators.
    """

    text = str(text or "").strip()

    if not text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Text cannot be empty.",
        )

    if len(text) > MAX_TEXT_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Text is too long.",
        )

    # --------------------------------------------------------
    # Extract signals
    # --------------------------------------------------------

    urgency_score, urgency_matches = detect_urgency(text)
    upi_flag, upi_findings = detect_upi(text)
    brand_mentions = detect_brands(text)

    # Find URLs in the text
    import re
    url_pattern = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
    extracted_urls = url_pattern.findall(text)[:10]

    # --------------------------------------------------------
    # Build signals
    # --------------------------------------------------------

    signals = ThreatSignals(
        domain_age_days=0.0,
        redirect_hops=0,
        typosquat_similarity=0.75 if brand_mentions else 0.0,
        nlp_urgency_score=urgency_score,
        auth_failure_flag=0,
        visual_brand_spoof=0.0,
        external_ioc_hits=min(len(extracted_urls), 3),
        upi_anomaly_flag=upi_flag,
    )

    # --------------------------------------------------------
    # Evaluate
    # --------------------------------------------------------

    engine = get_risk_engine()
    assessment = normalize_assessment(engine.evaluate(signals))

    # Extra XAI
    extra_xai = list(assessment.get("xai", []))

    if urgency_matches:
        extra_xai.append(
            "Urgency language: " + ", ".join(urgency_matches[:5])
        )

    if brand_mentions:
        extra_xai.append(
            "Brand mentioned: " + ", ".join(brand_mentions[:5])
        )

    if extracted_urls:
        extra_xai.append(
            f"{len(extracted_urls)} URL(s) found in message."
        )

    extra_xai.extend(upi_findings)

    assessment["xai"] = list(dict.fromkeys(extra_xai))[:15]

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    scan_id = new_scan_id()

    result = {
        "status": "success",
        "input_type": "text/sms/email",
        "scan_id": scan_id,
        "scanned_at": utc_now_iso(),
        "assessment": assessment,
        "trace": {},
        "metadata": {
            "urgency_score": urgency_score,
            "urgency_matches": urgency_matches,
            "brand_mentions": brand_mentions,
            "upi_signal": bool(upi_flag),
            "upi_findings": upi_findings,
            "extracted_urls": extracted_urls,
            "url_count": len(extracted_urls),
            "char_count": len(text),
        },
    }

    # --------------------------------------------------------
    # Persist
    # --------------------------------------------------------

    persist_scan(
        scan_id=scan_id,
        scan_type="text",
        input_value=text[:4000],
        assessment=assessment,
        metadata=result["metadata"],
    )

    return result


# ============================================================
# 3. QR SCAN
# ============================================================

def decode_qr_image(image_bytes: bytes) -> Optional[str]:
    """Decode QR code from image bytes."""
    try:
        np_array = np.frombuffer(image_bytes, dtype=np.uint8)
        image = cv2.imdecode(np_array, cv2.IMREAD_COLOR)

        if image is None:
            return None

        detector = cv2.QRCodeDetector()

        # Single QR
        decoded, _, _ = detector.detectAndDecode(image)
        if decoded:
            return decoded.strip()

        # Multi QR
        try:
            results, _, _ = detector.detectAndDecodeMulti(image)
            if results:
                for value in results:
                    if value and value.strip():
                        return value.strip()
        except Exception:
            pass

        return None

    except Exception:
        logger.exception("QR decode failed")
        return None


async def scan_quishing(file: UploadFile) -> dict[str, Any]:
    """
    Scan QR image for quishing threats.
    """

    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file was provided.",
        )

    # Validate content type
    content_type = (file.content_type or "").lower()
    allowed = {"image/png", "image/jpeg", "image/webp"}

    if content_type not in allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported image type. Use PNG, JPEG, or WEBP.",
        )

    # Read with size limit
    try:
        contents = await file.read()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not read uploaded file.",
        )

    if not contents:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    if len(contents) > MAX_QR_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="QR image is too large. Max 5 MB.",
        )

    # Decode QR
    payload = decode_qr_image(contents)

    scan_id = new_scan_id()
    filename = sanitize_filename(file.filename)

    # --------------------------------------------------------
    # No QR detected
    # --------------------------------------------------------

    if not payload:
        assessment = {
            "score": 0.0,
            "risk_score": 0.0,
            "severity": "LOW",
            "explanation": "QR image processed but no QR code detected.",
            "xai": [
                "Image decoding completed.",
                "No readable QR payload found.",
            ],
        }

        result = {
            "status": "error",
            "input_type": "qr",
            "scan_id": scan_id,
            "scanned_at": utc_now_iso(),
            "message": "No valid QR code detected.",
            "assessment": assessment,
            "trace": {},
            "metadata": {
                "filename": filename,
                "file_size": len(contents),
                "decoded": False,
            },
        }

        persist_scan(
            scan_id=scan_id,
            scan_type="qr",
            input_value=filename,
            assessment=assessment,
            metadata=result["metadata"],
            status="error",
        )

        return result

    payload = payload.strip()

    # --------------------------------------------------------
    # Plain text QR
    # --------------------------------------------------------

    is_url = payload.lower().startswith(("http://", "https://"))
    is_upi = payload.lower().startswith("upi://")

    if not is_url and not is_upi:
        assessment = {
            "score": 0.0,
            "risk_score": 0.0,
            "severity": "LOW",
            "explanation": "QR payload decoded but is not a URL or UPI URI.",
            "xai": [
                "QR decoded successfully.",
                "Payload classified as plain text.",
            ],
        }

        result = {
            "status": "success",
            "input_type": "qr",
            "scan_id": scan_id,
            "scanned_at": utc_now_iso(),
            "payload_type": "text",
            "extracted_payload": payload,
            "assessment": assessment,
            "trace": {},
            "metadata": {
                "filename": filename,
                "file_size": len(contents),
                "decoded": True,
            },
        }

        persist_scan(
            scan_id=scan_id,
            scan_type="qr",
            input_value=payload[:500],
            assessment=assessment,
            metadata=result["metadata"],
        )

        return result

    # --------------------------------------------------------
    # UPI QR
    # --------------------------------------------------------

    if is_upi:
        signals = ThreatSignals(
            domain_age_days=0.0,
            redirect_hops=0,
            typosquat_similarity=0.0,
            nlp_urgency_score=0.2,
            auth_failure_flag=0,
            visual_brand_spoof=0.0,
            external_ioc_hits=0,
            upi_anomaly_flag=1,
        )

        engine = get_risk_engine()
        assessment = normalize_assessment(engine.evaluate(signals))

        assessment["xai"] = list(
            set(assessment.get("xai", []) + ["QR contains UPI URI."])
        )[:15]

        result = {
            "status": "success",
            "input_type": "qr",
            "scan_id": scan_id,
            "scanned_at": utc_now_iso(),
            "payload_type": "upi",
            "extracted_payload": payload,
            "assessment": assessment,
            "trace": {},
            "metadata": {
                "filename": filename,
                "file_size": len(contents),
                "decoded": True,
                "upi": True,
            },
        }

        persist_scan(
            scan_id=scan_id,
            scan_type="qr",
            input_value=payload[:500],
            assessment=assessment,
            metadata=result["metadata"],
        )

        return result

    # --------------------------------------------------------
    # URL in QR — run full URL scan
    # --------------------------------------------------------

    url_result = await scan_url(payload)

    # Override with QR-specific metadata
    url_result["scan_id"] = scan_id
    url_result["input_type"] = "qr"
    url_result["payload_type"] = "url"
    url_result["extracted_payload"] = payload
    url_result["metadata"]["filename"] = filename
    url_result["metadata"]["file_size"] = len(contents)
    url_result["metadata"]["decoded"] = True

    return url_result
