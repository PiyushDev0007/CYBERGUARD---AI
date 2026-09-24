"""
CYBERGUARD X — Scan History Router

Responsibilities:
    - Expose scan-history REST endpoints
    - Pagination
    - Search
    - Scan-type filtering
    - Severity filtering
    - Single scan lookup
    - Delete individual scan records
    - Clear scan history
    - Consistent HTTP error handling

Expected service:
    backend/history_service.py

The router intentionally delegates persistence/business logic to
history_service.py instead of accessing the database directly.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, status

# ------------------------------------------------------------------
# Import history service
# ------------------------------------------------------------------

try:
    from ..history_service import (
        HistoryService,
        get_history_service,
    )
except ImportError:
    # Allows direct/local execution in some project layouts.
    from history_service import (
        HistoryService,
        get_history_service,
    )


# ================================================================
# ROUTER
# ================================================================

router = APIRouter(
    prefix="/history",
    tags=["History"],
)


# ================================================================
# SERVICE
# ================================================================

history_service: HistoryService = get_history_service()


# ================================================================
# HELPERS
# ================================================================

def _serialize_item(item: Any) -> Any:
    """
    Convert service/database objects into JSON-compatible data.

    Supports:
        - dict
        - Pydantic models
        - dataclasses
        - ORM-like objects
    """

    if item is None:
        return None

    if isinstance(item, dict):
        return item

    # Pydantic v2
    model_dump = getattr(item, "model_dump", None)

    if callable(model_dump):
        return model_dump()

    # Pydantic v1
    dict_method = getattr(item, "dict", None)

    if callable(dict_method):
        return dict_method()

    # Dataclass / normal object
    if hasattr(item, "__dict__"):
        return {
            key: value
            for key, value in vars(item).items()
            if not key.startswith("_")
        }

    return item


def _serialize_many(items: Any) -> list[Any]:
    """
    Serialize a collection of history records.
    """

    if items is None:
        return []

    if isinstance(items, dict):
        return [_serialize_item(items)]

    try:
        return [
            _serialize_item(item)
            for item in items
        ]
    except TypeError:
        return [_serialize_item(items)]


def _call_service(
    method_name: str,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """
    Safely call a history-service method.

    This adapter supports both synchronous and asynchronous
    service implementations.

    NOTE:
        Router endpoints are async, therefore awaitable results
        are detected automatically.
    """

    method = getattr(history_service, method_name, None)

    if method is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                f"History service method '{method_name}' "
                "is not implemented."
            ),
        )

    try:
        return method(*args, **kwargs)

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="History service operation failed.",
        ) from exc


async def _await_if_needed(value: Any) -> Any:
    """
    Await a result if the service method is asynchronous.
    """

    if hasattr(value, "__await__"):
        return await value

    return value


def _extract_total(result: Any) -> int | None:
    """
    Extract total-count metadata from common service responses.
    """

    if not isinstance(result, dict):
        return None

    for key in (
        "total",
        "total_count",
        "count",
    ):
        value = result.get(key)

        if value is None:
            continue

        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            continue

    return None


def _extract_items(result: Any) -> list[Any]:
    """
    Extract history records from common service response shapes.
    """

    if isinstance(result, dict):

        for key in (
            "items",
            "results",
            "records",
            "history",
            "data",
        ):
            if key in result:
                return _serialize_many(
                    result[key]
                )

        return []

    return _serialize_many(result)


# ================================================================
# LIST HISTORY
# ================================================================

@router.get(
    "",
    summary="Get scan history",
    description=(
        "Return paginated CyberGuard X scan history with optional "
        "search, scan-type and severity filters."
    ),
)
async def get_history(
    page: int = Query(
        default=1,
        ge=1,
        description="Page number starting from 1.",
    ),
    page_size: int = Query(
        default=20,
        ge=1,
        le=100,
        description="Number of records returned per page.",
    ),
    scan_type: str | None = Query(
        default=None,
        min_length=1,
        max_length=50,
        description=(
            "Optional scan type, e.g. url, text, qr, quishing."
        ),
    ),
    severity: str | None = Query(
        default=None,
        min_length=1,
        max_length=20,
        description=(
            "Optional severity filter: LOW, MEDIUM, HIGH or CRITICAL."
        ),
    ),
    search: str | None = Query(
        default=None,
        min_length=1,
        max_length=200,
        description=(
            "Search scan history by URL, payload, text or identifier."
        ),
    ),
):
    """
    Retrieve scan history.

    Supports service implementations exposing either:

        list_history(...)

    or:

        get_history(...)
    """

    normalized_scan_type = (
        scan_type.strip().lower()
        if scan_type
        else None
    )

    normalized_severity = (
        severity.strip().upper()
        if severity
        else None
    )

    normalized_search = (
        search.strip()
        if search
        else None
    )

    valid_severities = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    if (
        normalized_severity
        and normalized_severity not in valid_severities
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid severity. Use LOW, MEDIUM, HIGH or CRITICAL."
            ),
        )

    offset = (
        page - 1
    ) * page_size

    # ------------------------------------------------------------
    # Prefer list_history()
    # ------------------------------------------------------------

    method_name = None

    if hasattr(
        history_service,
        "list_history",
    ):
        method_name = "list_history"

    elif hasattr(
        history_service,
        "get_history",
    ):
        method_name = "get_history"

    if method_name is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "History service does not provide a history-listing method."
            ),
        )

    # ------------------------------------------------------------
    # Try modern pagination arguments first.
    # ------------------------------------------------------------

    try:
        result = _call_service(
            method_name,
            page=page,
            page_size=page_size,
            offset=offset,
            scan_type=normalized_scan_type,
            severity=normalized_severity,
            search=normalized_search,
        )

        result = await _await_if_needed(result)

    except HTTPException:
        raise

    except TypeError:
        # --------------------------------------------------------
        # Compatibility fallback for simpler service signatures.
        # --------------------------------------------------------

        try:
            result = _call_service(
                method_name,
                page=page,
                page_size=page_size,
            )

            result = await _await_if_needed(result)

        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to retrieve scan history.",
            ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to retrieve scan history.",
        ) from exc

    items = _extract_items(result)
    total = _extract_total(result)

    # ------------------------------------------------------------
    # If service returned a plain list, filtering/pagination may
    # need to be applied at router level as a compatibility fallback.
    # ------------------------------------------------------------

    if isinstance(result, (list, tuple)):

        filtered_items = items

        if normalized_scan_type:
            filtered_items = [
                item
                for item in filtered_items
                if str(
                    item.get("input_type")
                    or item.get("scan_type")
                    or item.get("type")
                    or ""
                ).lower()
                == normalized_scan_type
            ]

        if normalized_severity:
            filtered_items = [
                item
                for item in filtered_items
                if str(
                    item.get("severity")
                    or item.get("risk_severity")
                    or ""
                ).upper()
                == normalized_severity
            ]

        if normalized_search:
            needle = normalized_search.lower()

            filtered_items = [
                item
                for item in filtered_items
                if needle
                in str(item).lower()
            ]

        total = len(filtered_items)

        start = offset
        end = start + page_size

        items = filtered_items[start:end]

    if total is None:
        total = len(items)

    total_pages = (
        (total + page_size - 1) // page_size
        if total > 0
        else 0
    )

    return {
        "status": "success",
        "data": items,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
            "has_next": (
                page < total_pages
            ),
            "has_previous": (
                page > 1 and total > 0
            ),
        },
        "filters": {
            "scan_type": normalized_scan_type,
            "severity": normalized_severity,
            "search": normalized_search,
        },
    }


# ================================================================
# HISTORY SUMMARY
# ================================================================

@router.get(
    "/summary",
    summary="Get history summary",
    description=(
        "Return aggregate scan-history statistics such as total "
        "scans and severity distribution."
    ),
)
async def get_history_summary():
    """
    Return aggregate history statistics.

    Preferred service methods:

        get_summary()
        history_summary()
        get_history_summary()
    """

    method_name = None

    for candidate in (
        "get_summary",
        "history_summary",
        "get_history_summary",
    ):
        if hasattr(
            history_service,
            candidate,
        ):
            method_name = candidate
            break

    if method_name is None:
        # --------------------------------------------------------
        # Graceful fallback.
        # --------------------------------------------------------

        return {
            "status": "success",
            "data": {
                "total_scans": 0,
                "low": 0,
                "medium": 0,
                "high": 0,
                "critical": 0,
            },
            "message": (
                "History summary is not available from the "
                "current service implementation."
            ),
        }

    try:
        result = _call_service(
            method_name
        )

        result = await _await_if_needed(result)

        return {
            "status": "success",
            "data": _serialize_item(result),
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to retrieve history summary.",
        ) from exc


# ================================================================
# GET SINGLE SCAN
# ================================================================

@router.get(
    "/{scan_id}",
    summary="Get scan history record",
    description=(
        "Retrieve one historical scan by its scan ID."
    ),
)
async def get_history_item(
    scan_id: str,
):
    """
    Retrieve a single scan-history record.
    """

    scan_id = scan_id.strip()

    if not scan_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scan_id cannot be empty.",
        )

    if len(scan_id) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan_id.",
        )

    method_name = None

    for candidate in (
        "get_by_scan_id",
        "get_scan",
        "get_history_item",
        "get_by_id",
    ):
        if hasattr(
            history_service,
            candidate,
        ):
            method_name = candidate
            break

    if method_name is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "History service does not provide a single-record lookup."
            ),
        )

    try:
        result = _call_service(
            method_name,
            scan_id,
        )

        result = await _await_if_needed(result)

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to retrieve scan history record.",
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan history record not found.",
        )

    return {
        "status": "success",
        "data": _serialize_item(result),
    }


# ================================================================
# DELETE SINGLE RECORD
# ================================================================

@router.delete(
    "/{scan_id}",
    summary="Delete scan history record",
    description=(
        "Delete one scan-history record using its scan ID."
    ),
)
async def delete_history_item(
    scan_id: str,
):
    """
    Delete a single scan-history record.
    """

    scan_id = scan_id.strip()

    if not scan_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scan_id cannot be empty.",
        )

    method_name = None

    for candidate in (
        "delete_by_scan_id",
        "delete_scan",
        "delete_history_item",
        "delete",
    ):
        if hasattr(
            history_service,
            candidate,
        ):
            method_name = candidate
            break

    if method_name is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "History service does not provide a delete method."
            ),
        )

    try:
        result = _call_service(
            method_name,
            scan_id,
        )

        result = await _await_if_needed(result)

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to delete scan history record.",
        ) from exc

    # ------------------------------------------------------------
    # Handle common service return values.
    # ------------------------------------------------------------

    if result is False:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan history record not found.",
        )

    return {
        "status": "success",
        "message": "Scan history record deleted successfully.",
        "scan_id": scan_id,
    }


# ================================================================
# CLEAR HISTORY
# ================================================================

@router.delete(
    "",
    summary="Clear scan history",
    description=(
        "Delete scan history. Optional filters can restrict the "
        "operation to a scan type or severity."
    ),
)
async def clear_history(
    scan_type: str | None = Query(
        default=None,
        min_length=1,
        max_length=50,
    ),
    severity: str | None = Query(
        default=None,
        min_length=1,
        max_length=20,
    ),
):
    """
    Delete scan history.

    This supports both:

        clear_history()

    and filtered deletion where the service supports it.
    """

    normalized_scan_type = (
        scan_type.strip().lower()
        if scan_type
        else None
    )

    normalized_severity = (
        severity.strip().upper()
        if severity
        else None
    )

    valid_severities = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    if (
        normalized_severity
        and normalized_severity not in valid_severities
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid severity. Use LOW, MEDIUM, HIGH or CRITICAL."
            ),
        )

    method_name = None

    for candidate in (
        "clear_history",
        "clear",
        "delete_all",
    ):
        if hasattr(
            history_service,
            candidate,
        ):
            method_name = candidate
            break

    if method_name is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "History service does not provide a history-clear method."
            ),
        )

    try:
        try:
            result = _call_service(
                method_name,
                scan_type=normalized_scan_type,
                severity=normalized_severity,
            )

            result = await _await_if_needed(result)

        except TypeError:
            # Compatibility with clear_history() without filters.
            if (
                normalized_scan_type
                or normalized_severity
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "The current history service does not support "
                        "filtered history deletion."
                    ),
                )

            result = _call_service(
                method_name
            )

            result = await _await_if_needed(result)

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to clear scan history.",
        ) from exc

    deleted_count = None

    if isinstance(result, dict):
        for key in (
            "deleted",
            "deleted_count",
            "count",
        ):
            if key in result:
                try:
                    deleted_count = int(
                        result[key]
                    )
                except (
                    TypeError,
                    ValueError,
                ):
                    pass
                break

    elif isinstance(result, int):
        deleted_count = result

    response = {
        "status": "success",
        "message": "Scan history cleared successfully.",
        "filters": {
            "scan_type": normalized_scan_type,
            "severity": normalized_severity,
        },
    }

    if deleted_count is not None:
        response["deleted_count"] = max(
            0,
            deleted_count,
        )

    return response
