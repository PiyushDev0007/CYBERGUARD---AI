"""
CYBERGUARD X — Scan History Service

Responsibilities:
    - Persist completed scan results.
    - Retrieve scans by scan_id.
    - Retrieve paginated scan history.
    - Filter history by scan type and severity.
    - Provide basic history statistics.
    - Delete individual scan records.
    - Keep database access outside routers and scan logic.

Architecture:

    routers/history.py
             |
             v
    history_service.py
             |
             v
        database.py

Design goals:
    - Async-friendly API
    - Defensive input handling
    - Stable return structures
    - Minimal sensitive-data retention
    - Compatible with SQLite/SQLAlchemy-style database layers
    - Easy integration with scan_service.py
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional


# ============================================================
# LOGGER
# ============================================================

logger = logging.getLogger("cyberguard.history_service")


# ============================================================
# DATABASE IMPORT
# ============================================================

try:
    from ..database import (
        ScanRecord,
        get_database_session,
    )
except ImportError:
    try:
        from database import (
            ScanRecord,
            get_database_session,
        )
    except ImportError:
        ScanRecord = None
        get_database_session = None


# ============================================================
# CONSTANTS
# ============================================================

ALLOWED_SCAN_TYPES = {
    "url",
    "text",
    "text/sms/email",
    "qr",
    "quishing",
}

ALLOWED_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100

MAX_TEXT_LENGTH = 10000
MAX_XAI_ITEMS = 50
MAX_METADATA_SIZE = 50000


# ============================================================
# EXCEPTIONS
# ============================================================

class HistoryServiceError(Exception):
    """Base exception for history-service failures."""


class HistoryValidationError(HistoryServiceError):
    """Raised when history input is invalid."""


class HistoryNotFoundError(HistoryServiceError):
    """Raised when a requested scan does not exist."""


class HistoryDatabaseError(HistoryServiceError):
    """Raised when database operations fail."""


# ============================================================
# BASIC HELPERS
# ============================================================

def _utc_now() -> datetime:
    """
    Return a timezone-aware UTC datetime.
    """

    return datetime.now(timezone.utc)


def _clean_string(
    value: Any,
    maximum_length: int | None = None,
) -> str:
    """
    Convert a value to a clean string.

    None becomes an empty string.
    """

    if value is None:
        return ""

    result = str(value).strip()

    if maximum_length is not None:
        result = result[:maximum_length]

    return result


def _normalize_scan_type(
    scan_type: Any,
) -> str:
    """
    Normalize scan type into the supported representation.
    """

    value = _clean_string(
        scan_type,
        100,
    ).lower()

    aliases = {
        "text": "text",
        "sms": "text/sms/email",
        "email": "text/sms/email",
        "text/sms/email": "text/sms/email",
        "qr": "qr",
        "quishing": "quishing",
        "url": "url",
    }

    normalized = aliases.get(
        value,
        value,
    )

    if normalized not in ALLOWED_SCAN_TYPES:
        raise HistoryValidationError(
            f"Unsupported scan type: {scan_type}"
        )

    return normalized


def _normalize_severity(
    severity: Any,
) -> str:
    """
    Normalize severity to uppercase.
    """

    value = _clean_string(
        severity,
        20,
    ).upper()

    if value not in ALLOWED_SEVERITIES:
        raise HistoryValidationError(
            f"Unsupported severity: {severity}"
        )

    return value


def _normalize_score(
    score: Any,
) -> float:
    """
    Normalize risk score into 0-100.
    """

    try:
        numeric = float(score)
    except (
        TypeError,
        ValueError,
    ):
        numeric = 0.0

    if numeric != numeric:
        numeric = 0.0

    return round(
        max(
            0.0,
            min(
                numeric,
                100.0,
            ),
        ),
        1,
    )


def _normalize_page(
    page: Any,
) -> int:
    """
    Normalize pagination page.
    """

    try:
        value = int(page)
    except (
        TypeError,
        ValueError,
    ):
        value = DEFAULT_PAGE

    return max(
        DEFAULT_PAGE,
        value,
    )


def _normalize_page_size(
    page_size: Any,
) -> int:
    """
    Normalize pagination page size.
    """

    try:
        value = int(page_size)
    except (
        TypeError,
        ValueError,
    ):
        value = DEFAULT_PAGE_SIZE

    return max(
        1,
        min(
            value,
            MAX_PAGE_SIZE,
        ),
    )


# ============================================================
# JSON HELPERS
# ============================================================

def _safe_json_dumps(
    value: Any,
) -> str:
    """
    Serialize arbitrary metadata safely.

    This prevents database writes from failing because a metadata
    object contains a non-JSON-native value.
    """

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            default=str,
        )
    except Exception:
        return "{}"


def _safe_json_loads(
    value: Any,
    fallback: Any,
) -> Any:
    """
    Safely decode JSON database fields.
    """

    if value is None:
        return fallback

    if isinstance(value, (dict, list)):
        return value

    try:
        return json.loads(str(value))
    except Exception:
        return fallback


# ============================================================
# SENSITIVE INPUT SANITIZATION
# ============================================================

def _sanitize_input(
    scan_type: str,
    input_value: Any,
) -> str:
    """
    Sanitize stored scan input.

    The database should not become a second copy of unlimited
    user content.

    URL:
        Store the URL, truncated to a reasonable length.

    Text:
        Store a limited preview rather than unlimited message
        content.

    QR:
        Store a limited payload preview.
    """

    value = _clean_string(
        input_value,
        MAX_TEXT_LENGTH,
    )

    if not value:
        return ""

    if scan_type in {
        "text",
        "text/sms/email",
    }:
        # Keep enough information for history display while
        # limiting unnecessary retention of potentially sensitive
        # message content.
        return value[:4000]

    if scan_type in {
        "qr",
        "quishing",
    }:
        return value[:4096]

    return value[:4096]


# ============================================================
# XAI SANITIZATION
# ============================================================

def _sanitize_xai(
    xai: Any,
) -> list[str]:
    """
    Normalize XAI findings into a bounded list of strings.
    """

    if xai is None:
        return []

    if isinstance(
        xai,
        str,
    ):
        values = [xai]

    elif isinstance(
        xai,
        list,
    ):
        values = xai

    else:
        values = [str(xai)]

    cleaned: list[str] = []

    for item in values[:MAX_XAI_ITEMS]:
        text = _clean_string(
            item,
            1000,
        )

        if text and text not in cleaned:
            cleaned.append(text)

    return cleaned


# ============================================================
# RESULT NORMALIZATION
# ============================================================

def normalize_scan_result(
    result: dict[str, Any],
) -> dict[str, Any]:
    """
    Convert a scan-service response into the canonical structure
    used by the history service.
    """

    if not isinstance(
        result,
        dict,
    ):
        raise HistoryValidationError(
            "Scan result must be a dictionary."
        )

    scan_id = _clean_string(
        result.get("scan_id"),
        100,
    )

    if not scan_id:
        raise HistoryValidationError(
            "Scan result does not contain scan_id."
        )

    input_type = result.get(
        "input_type",
        result.get("scan_type"),
    )

    scan_type = _normalize_scan_type(
        input_type
    )

    assessment = result.get(
        "assessment"
    )

    if not isinstance(
        assessment,
        dict,
    ):
        assessment = {}

    score = _normalize_score(
        assessment.get(
            "risk_score",
            assessment.get(
                "score",
                0,
            ),
        )
    )

    severity = assessment.get(
        "severity",
        "LOW",
    )

    try:
        severity = _normalize_severity(
            severity
        )
    except HistoryValidationError:
        severity = "LOW"

    explanation = _clean_string(
        assessment.get(
            "explanation",
            "Risk assessment completed.",
        ),
        5000,
    )

    xai = assessment.get(
        "xai",
        assessment.get(
            "xai_breakdown",
            [],
        ),
    )

    xai = _sanitize_xai(
        xai
    )

    metadata = result.get(
        "metadata",
        {},
    )

    if not isinstance(
        metadata,
        dict,
    ):
        metadata = {
            "value": str(metadata)
        }

    metadata_json = _safe_json_dumps(
        metadata
    )

    if len(metadata_json) > MAX_METADATA_SIZE:
        metadata_json = metadata_json[
            :MAX_METADATA_SIZE
        ]

    return {
        "scan_id": scan_id,
        "scan_type": scan_type,
        "input_value": _sanitize_input(
            scan_type,
            result.get(
                "input",
                result.get(
                    "extracted_payload",
                    result.get(
                        "url",
                        result.get(
                            "text",
                            result.get(
                                "trace",
                                {},
                            )
                        ),
                    ),
                ),
            ),
        ),
        "risk_score": score,
        "severity": severity,
        "explanation": explanation,
        "xai": xai,
        "metadata": metadata,
        "metadata_json": metadata_json,
        "status": _clean_string(
            result.get(
                "status",
                "success",
            ),
            50,
        ),
        "created_at": result.get(
            "created_at",
            _utc_now(),
        ),
    }


# ============================================================
# DATABASE AVAILABILITY
# ============================================================

def _require_database() -> None:
    """
    Ensure database dependencies are available.
    """

    if (
        ScanRecord is None
        or get_database_session is None
    ):
        raise HistoryDatabaseError(
            "Database layer is unavailable. "
            "Check backend/database.py."
        )


# ============================================================
# MODEL SERIALIZATION
# ============================================================

def _record_to_dict(
    record: Any,
) -> dict[str, Any]:
    """
    Convert a database record into a frontend-safe dictionary.

    Supports common SQLAlchemy model attributes.
    """

    if record is None:
        raise HistoryNotFoundError(
            "Scan record was not found."
        )

    scan_id = _clean_string(
        getattr(
            record,
            "scan_id",
            "",
        ),
        100,
    )

    scan_type = _clean_string(
        getattr(
            record,
            "scan_type",
            "",
        ),
        100,
    )

    risk_score = _normalize_score(
        getattr(
            record,
            "risk_score",
            0,
        )
    )

    severity = _clean_string(
        getattr(
            record,
            "severity",
            "LOW",
        ),
        20,
    ).upper()

    explanation = _clean_string(
        getattr(
            record,
            "explanation",
            "",
        ),
        5000,
    )

    xai_raw = getattr(
        record,
        "xai",
        getattr(
            record,
            "xai_breakdown",
            "[]",
        ),
    )

    xai = _safe_json_loads(
        xai_raw,
        [],
    )

    if not isinstance(
        xai,
        list,
    ):
        xai = _sanitize_xai(
            xai
        )

    metadata_raw = getattr(
        record,
        "metadata",
        getattr(
            record,
            "metadata_json",
            "{}",
        ),
    )

    metadata = _safe_json_loads(
        metadata_raw,
        {},
    )

    if not isinstance(
        metadata,
        dict,
    ):
        metadata = {}

    created_at = getattr(
        record,
        "created_at",
        None,
    )

    if isinstance(
        created_at,
        datetime,
    ):
        created_at_value = created_at.isoformat()
    elif created_at is not None:
        created_at_value = str(
            created_at
        )
    else:
        created_at_value = None

    return {
        "scan_id": scan_id,
        "scan_type": scan_type,
        "risk_score": risk_score,
        "score": risk_score,
        "severity": severity,
        "explanation": explanation,
        "xai": xai,
        "metadata": metadata,
        "created_at": created_at_value,
    }


# ============================================================
# SAVE SCAN
# ============================================================

async def save_scan_result(
    result: dict[str, Any],
) -> dict[str, Any]:
    """
    Persist a completed scan result.

    Parameters:
        result:
            Dictionary returned by scan_service.py.

    Returns:
        Canonical history record.
    """

    _require_database()

    normalized = normalize_scan_result(
        result
    )

    session = None

    try:
        session = get_database_session()

        record = ScanRecord(
            scan_id=normalized["scan_id"],
            scan_type=normalized["scan_type"],
            input_value=normalized["input_value"],
            risk_score=normalized["risk_score"],
            severity=normalized["severity"],
            explanation=normalized["explanation"],
            xai=_safe_json_dumps(
                normalized["xai"]
            ),
            metadata=_safe_json_dumps(
                normalized["metadata"]
            ),
            status=normalized["status"],
            created_at=normalized["created_at"],
        )

        session.add(
            record
        )

        commit_result = session.commit()

        # Some async/sync database adapters return a value from
        # commit(), while normal SQLAlchemy sessions return None.
        _ = commit_result

        try:
            session.refresh(
                record
            )
        except Exception:
            # Refresh is useful but not mandatory for all adapters.
            pass

        return _record_to_dict(
            record
        )

    except HistoryServiceError:
        raise

    except Exception as exc:
        if session is not None:
            try:
                session.rollback()
            except Exception:
                pass

        logger.exception(
            "Failed to save scan result: %s",
            normalized["scan_id"],
        )

        raise HistoryDatabaseError(
            "Could not save scan result."
        ) from exc

    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                pass


# ============================================================
# GET SCAN BY ID
# ============================================================

async def get_scan_by_id(
    scan_id: str,
) -> dict[str, Any]:
    """
    Retrieve one scan using its scan_id.
    """

    _require_database()

    scan_id = _clean_string(
        scan_id,
        100,
    )

    if not scan_id:
        raise HistoryValidationError(
            "scan_id cannot be empty."
        )

    session = None

    try:
        session = get_database_session()

        record = (
            session.query(
                ScanRecord
            )
            .filter(
                ScanRecord.scan_id == scan_id
            )
            .first()
        )

        if record is None:
            raise HistoryNotFoundError(
                f"Scan '{scan_id}' was not found."
            )

        return _record_to_dict(
            record
        )

    except HistoryServiceError:
        raise

    except Exception as exc:
        logger.exception(
            "Failed to retrieve scan: %s",
            scan_id,
        )

        raise HistoryDatabaseError(
            "Could not retrieve scan history."
        ) from exc

    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                pass


# ============================================================
# LIST SCAN HISTORY
# ============================================================

async def list_scan_history(
    page: int = DEFAULT_PAGE,
    page_size: int = DEFAULT_PAGE_SIZE,
    scan_type: Optional[str] = None,
    severity: Optional[str] = None,
) -> dict[str, Any]:
    """
    Retrieve paginated scan history.

    Supports:

        page
        page_size
        scan_type
        severity

    Results are returned newest-first.
    """

    _require_database()

    page = _normalize_page(
        page
    )

    page_size = _normalize_page_size(
        page_size
    )

    normalized_scan_type = None

    if scan_type:
        normalized_scan_type = _normalize_scan_type(
            scan_type
        )

    normalized_severity = None

    if severity:
        normalized_severity = _normalize_severity(
            severity
        )

    offset = (
        page - 1
    ) * page_size

    session = None

    try:
        session = get_database_session()

        query = session.query(
            ScanRecord
        )

        if normalized_scan_type:
            query = query.filter(
                ScanRecord.scan_type
                == normalized_scan_type
            )

        if normalized_severity:
            query = query.filter(
                ScanRecord.severity
                == normalized_severity
            )

        total = query.count()

        query = query.order_by(
            ScanRecord.created_at.desc()
        )

        records = (
            query
            .offset(offset)
            .limit(page_size)
            .all()
        )

        items = [
            _record_to_dict(
                record
            )
            for record in records
        ]

        total_pages = (
            (total + page_size - 1)
            // page_size
            if total > 0
            else 0
        )

        return {
            "status": "success",
            "items": items,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "total_pages": total_pages,
                "has_next": (
                    page < total_pages
                ),
                "has_previous": (
                    page > 1
                    and total > 0
                ),
            },
            "filters": {
                "scan_type": normalized_scan_type,
                "severity": normalized_severity,
            },
        }

    except HistoryServiceError:
        raise

    except Exception as exc:
        logger.exception(
            "Failed to list scan history."
        )

        raise HistoryDatabaseError(
            "Could not retrieve scan history."
        ) from exc

    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                pass


# ============================================================
# RECENT SCANS
# ============================================================

async def get_recent_scans(
    limit: int = 10,
) -> list[dict[str, Any]]:
    """
    Retrieve the most recent scans.

    Convenience wrapper around list_scan_history().
    """

    limit = max(
        1,
        min(
            int(limit),
            MAX_PAGE_SIZE,
        ),
    )

    result = await list_scan_history(
        page=1,
        page_size=limit,
    )

    return result["items"]


# ============================================================
# HISTORY STATISTICS
# ============================================================

async def get_history_statistics() -> dict[str, Any]:
    """
    Calculate basic scan-history statistics.

    Returns:
        total scans
        severity counts
        scan-type counts
        average risk score
        high-risk count
        critical count
    """

    _require_database()

    session = None

    try:
        session = get_database_session()

        records = (
            session.query(
                ScanRecord
            )
            .all()
        )

        total = len(
            records
        )

        severity_counts = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }

        type_counts: dict[str, int] = {}

        score_total = 0.0

        for record in records:
            severity = _clean_string(
                getattr(
                    record,
                    "severity",
                    "LOW",
                ),
                20,
            ).upper()

            if severity not in severity_counts:
                severity_counts[severity] = 0

            severity_counts[severity] += 1

            scan_type = _clean_string(
                getattr(
                    record,
                    "scan_type",
                    "unknown",
                ),
                100,
            )

            type_counts[scan_type] = (
                type_counts.get(
                    scan_type,
                    0,
                )
                + 1
            )

            score_total += _normalize_score(
                getattr(
                    record,
                    "risk_score",
                    0,
                )
            )

        average_score = (
            score_total / total
            if total
            else 0.0
        )

        high_risk_count = (
            severity_counts.get(
                "HIGH",
                0,
            )
            + severity_counts.get(
                "CRITICAL",
                0,
            )
        )

        return {
            "status": "success",
            "statistics": {
                "total_scans": total,
                "average_risk_score": round(
                    average_score,
                    1,
                ),
                "high_risk_scans": high_risk_count,
                "critical_scans": severity_counts.get(
                    "CRITICAL",
                    0,
                ),
                "severity_counts": severity_counts,
                "scan_type_counts": type_counts,
            },
        }

    except Exception as exc:
        logger.exception(
            "Failed to calculate history statistics."
        )

        raise HistoryDatabaseError(
            "Could not calculate scan-history statistics."
        ) from exc

    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                pass


# ============================================================
# DELETE SCAN
# ============================================================

async def delete_scan(
    scan_id: str,
) -> dict[str, Any]:
    """
    Delete a scan history record by scan_id.
    """

    _require_database()

    scan_id = _clean_string(
        scan_id,
        100,
    )

    if not scan_id:
        raise HistoryValidationError(
            "scan_id cannot be empty."
        )

    session = None

    try:
        session = get_database_session()

        record = (
            session.query(
                ScanRecord
            )
            .filter(
                ScanRecord.scan_id == scan_id
            )
            .first()
        )

        if record is None:
            raise HistoryNotFoundError(
                f"Scan '{scan_id}' was not found."
            )

        session.delete(
            record
        )

        session.commit()

        return {
            "status": "success",
            "scan_id": scan_id,
            "deleted": True,
        }

    except HistoryServiceError:
        raise

    except Exception as exc:
        if session is not None:
            try:
                session.rollback()
            except Exception:
                pass

        logger.exception(
            "Failed to delete scan: %s",
            scan_id,
        )

        raise HistoryDatabaseError(
            "Could not delete scan history."
        ) from exc

    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                pass


# ============================================================
# CLEAR HISTORY
# ============================================================

async def clear_history() -> dict[str, Any]:
    """
    Delete all stored scan-history records.

    This should normally be protected by an administrative or
    authenticated endpoint. Do not expose this directly to an
    unauthenticated public API.
    """

    _require_database()

    session = None

    try:
        session = get_database_session()

        deleted_count = (
            session.query(
                ScanRecord
            )
            .delete(
                synchronize_session=False
            )
        )

        session.commit()

        return {
            "status": "success",
            "deleted": True,
            "deleted_count": int(
                deleted_count
            ),
        }

    except Exception as exc:
        if session is not None:
            try:
                session.rollback()
            except Exception:
                pass

        logger.exception(
            "Failed to clear scan history."
        )

        raise HistoryDatabaseError(
            "Could not clear scan history."
        ) from exc

    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                pass


# ============================================================
# AUTOMATIC HISTORY PERSISTENCE
# ============================================================

async def persist_scan_if_successful(
    result: dict[str, Any],
) -> dict[str, Any]:
    """
    Convenience function for scan_service.py.

    Only successful/completed scan results should normally be
    persisted.

    Usage:

        result = await perform_scan(...)
        await persist_scan_if_successful(result)

    The original result is returned so callers can continue using
    the normal scan response.
    """

    if not isinstance(
        result,
        dict,
    ):
        return result

    status_value = _clean_string(
        result.get(
            "status",
            "",
        ),
        50,
    ).lower()

    if status_value not in {
        "success",
        "completed",
    }:
        return result

    try:
        await save_scan_result(
            result
        )

    except HistoryServiceError:
        # Scanning should not necessarily fail simply because
        # history persistence failed. The failure is logged and
        # the scan result remains available to the caller.
        logger.exception(
            "Scan completed but history persistence failed."
        )

    return result


# ============================================================
# SERVICE INFORMATION
# ============================================================

def get_history_service_info() -> dict[str, Any]:
    """
    Return service capability information.
    """

    return {
        "service": "cyberguard-history-service",
        "status": "available",
        "features": [
            "scan persistence",
            "scan lookup",
            "paginated history",
            "scan-type filtering",
            "severity filtering",
            "recent scans",
            "history statistics",
            "individual deletion",
            "history clearing",
            "bounded data retention",
            "XAI persistence",
            "metadata persistence",
        ],
        "limits": {
            "max_page_size": MAX_PAGE_SIZE,
            "max_text_length": MAX_TEXT_LENGTH,
            "max_xai_items": MAX_XAI_ITEMS,
            "max_metadata_size": MAX_METADATA_SIZE,
        },
    }


# ============================================================
# PUBLIC EXPORTS
# ============================================================

__all__ = [
    "HistoryServiceError",
    "HistoryValidationError",
    "HistoryNotFoundError",
    "HistoryDatabaseError",
    "save_scan_result",
    "get_scan_by_id",
    "list_scan_history",
    "get_recent_scans",
    "get_history_statistics",
    "delete_scan",
    "clear_history",
    "persist_scan_if_successful",
    "normalize_scan_result",
    "get_history_service_info",
]
