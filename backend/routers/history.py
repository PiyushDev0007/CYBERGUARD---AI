"""
CYBERGUARD X — History Service
===============================

Provides:
    - HistoryService class (used by routers/history.py)
    - get_history_service() singleton
    - Scan history retrieval
    - Scan lookup by ID
    - Statistics
    - Delete operations

Uses:
    - database.py (SQLAlchemy models)

Architecture:
    routers/history.py
           ↓
    history_service.py
           ↓
    database.py
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError


# ============================================================
# PROJECT IMPORTS
# ============================================================

try:
    from database import (
        ScanRecord,
        SessionLocal,
        database_session,
        get_database_session,
    )
except ImportError:
    try:
        from backend.database import (
            ScanRecord,
            SessionLocal,
            database_session,
            get_database_session,
        )
    except ImportError:
        raise ImportError(
            "Could not import database module. "
            "Ensure database.py exists."
        )


# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger("cyberguard.history_service")


# ============================================================
# CONSTANTS
# ============================================================

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

VALID_SCAN_TYPES = {
    "url",
    "text",
    "text/sms/email",
    "qr",
    "quishing",
}


# ============================================================
# HELPERS
# ============================================================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_severity(value: Any) -> Optional[str]:
    """Normalize severity to uppercase."""
    if not value:
        return None
    normalized = str(value).strip().upper()
    return normalized if normalized in VALID_SEVERITIES else None


def normalize_scan_type(value: Any) -> Optional[str]:
    """Normalize scan type."""
    if not value:
        return None
    normalized = str(value).strip().lower()
    return normalized if normalized in VALID_SCAN_TYPES else None


def normalize_page(value: Any, default: int = 1) -> int:
    """Normalize page number."""
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


def normalize_page_size(value: Any, default: int = DEFAULT_PAGE_SIZE) -> int:
    """Normalize page size."""
    try:
        return max(1, min(int(value), MAX_PAGE_SIZE))
    except (TypeError, ValueError):
        return default


def record_to_dict(record: Any) -> dict[str, Any]:
    """Convert a ScanRecord to API-friendly dict."""

    if record is None:
        return {}

    if hasattr(record, "to_dict"):
        return record.to_dict()

    # Fallback for dicts
    if isinstance(record, dict):
        return record

    # Fallback for objects
    return {
        "scan_id": getattr(record, "scan_id", None),
        "scan_type": getattr(record, "scan_type", None),
        "input_type": getattr(record, "scan_type", None),
        "input_value": getattr(record, "input_value", None),
        "risk_score": getattr(record, "risk_score", 0.0),
        "score": getattr(record, "risk_score", 0.0),
        "severity": getattr(record, "severity", "LOW"),
        "explanation": getattr(record, "explanation", ""),
        "xai": [],
        "metadata": {},
        "status": getattr(record, "status", "success"),
        "created_at": (
            record.created_at.isoformat()
            if getattr(record, "created_at", None)
            else None
        ),
    }


# ============================================================
# HISTORY SERVICE CLASS
# ============================================================

class HistoryService:
    """
    Service class for scan history operations.

    Used by routers/history.py.

    All methods are async and return JSON-compatible data.
    """

    # ========================================================
    # LIST HISTORY
    # ========================================================

    async def list_history(
        self,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
        scan_type: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Return paginated scan history.

        Compatible with routers/history.py.
        """
        page = normalize_page(page)
        page_size = normalize_page_size(page_size)
        scan_type = normalize_scan_type(scan_type)
        severity = normalize_severity(severity)

        try:
            with database_session() as db:
                conditions = []

                if scan_type:
                    conditions.append(ScanRecord.scan_type == scan_type)

                if severity:
                    conditions.append(ScanRecord.severity == severity)

                if search:
                    search_value = f"%{search.strip()}%"
                    conditions.append(
                        ScanRecord.scan_id.ilike(search_value)
                        | ScanRecord.domain.ilike(search_value)
                        | ScanRecord.original_url.ilike(search_value)
                        | ScanRecord.final_url.ilike(search_value)
                    )

                # Total count
                count_stmt = select(func.count()).select_from(ScanRecord)
                if conditions:
                    count_stmt = count_stmt.where(*conditions)

                total = int(db.scalar(count_stmt) or 0)

                # Records
                offset = (page - 1) * page_size

                stmt = select(ScanRecord)
                if conditions:
                    stmt = stmt.where(*conditions)

                stmt = (
                    stmt.order_by(ScanRecord.created_at.desc())
                    .offset(offset)
                    .limit(page_size)
                )

                records = list(db.scalars(stmt))

                total_pages = (
                    (total + page_size - 1) // page_size if total else 0
                )

                return {
                    "items": [record_to_dict(r) for r in records],
                    "total": total,
                    "page": page,
                    "page_size": page_size,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_previous": page > 1,
                }

        except SQLAlchemyError as exc:
            logger.exception("Failed to list history")
            raise RuntimeError(
                "Could not retrieve scan history."
            ) from exc

    # ========================================================
    # GET SINGLE SCAN
    # ========================================================

    async def get_by_scan_id(
        self,
        scan_id: str,
    ) -> Optional[dict[str, Any]]:
        """
        Return a single scan record by scan_id.

        Returns None if not found.
        """
        if not scan_id:
            return None

        try:
            with database_session() as db:
                stmt = select(ScanRecord).where(
                    ScanRecord.scan_id == scan_id.strip()
                )
                record = db.scalar(stmt)

                if record is None:
                    return None

                return record_to_dict(record)

        except SQLAlchemyError as exc:
            logger.exception("Failed to get scan %s", scan_id)
            raise RuntimeError(
                "Could not retrieve scan."
            ) from exc

    # Alias
    async def get_scan(self, scan_id: str) -> Optional[dict[str, Any]]:
        return await self.get_by_scan_id(scan_id)

    # ========================================================
    # GET STATISTICS
    # ========================================================

    async def get_summary(self) -> dict[str, Any]:
        """
        Return aggregate statistics.

        Compatible with routers/history.py summary endpoint.
        """
        try:
            with database_session() as db:
                total = int(
                    db.scalar(
                        select(func.count()).select_from(ScanRecord)
                    ) or 0
                )

                # Severity counts
                severity_rows = db.execute(
                    select(
                        ScanRecord.severity,
                        func.count(ScanRecord.id),
                    ).group_by(ScanRecord.severity)
                ).all()

                severity_counts = {
                    str(sev).upper(): int(cnt)
                    for sev, cnt in severity_rows
                }

                # Scan type counts
                type_rows = db.execute(
                    select(
                        ScanRecord.scan_type,
                        func.count(ScanRecord.id),
                    ).group_by(ScanRecord.scan_type)
                ).all()

                type_counts = {
                    str(t): int(c) for t, c in type_rows
                }

                # Average risk
                avg = db.scalar(select(func.avg(ScanRecord.risk_score)))

                return {
                    "total_scans": total,
                    "average_risk_score": round(float(avg or 0.0), 2),
                    "severity_counts": severity_counts,
                    "scan_type_counts": type_counts,
                    "low": severity_counts.get("LOW", 0),
                    "medium": severity_counts.get("MEDIUM", 0),
                    "high": severity_counts.get("HIGH", 0),
                    "critical": severity_counts.get("CRITICAL", 0),
                }

        except SQLAlchemyError as exc:
            logger.exception("Failed to get statistics")
            raise RuntimeError(
                "Could not retrieve statistics."
            ) from exc

    # Aliases
    async def history_summary(self) -> dict[str, Any]:
        return await self.get_summary()

    async def get_history_summary(self) -> dict[str, Any]:
        return await self.get_summary()

    # ========================================================
    # DELETE SINGLE SCAN
    # ========================================================

    async def delete_by_scan_id(self, scan_id: str) -> bool:
        """
        Delete one scan record.

        Returns True if deleted, False if not found.
        """
        if not scan_id:
            return False

        try:
            with database_session() as db:
                stmt = select(ScanRecord).where(
                    ScanRecord.scan_id == scan_id.strip()
                )
                record = db.scalar(stmt)

                if record is None:
                    return False

                db.delete(record)
                return True

        except SQLAlchemyError as exc:
            logger.exception("Failed to delete scan %s", scan_id)
            raise RuntimeError(
                "Could not delete scan."
            ) from exc

    # Aliases
    async def delete_scan(self, scan_id: str) -> bool:
        return await self.delete_by_scan_id(scan_id)

    async def delete_history_item(self, scan_id: str) -> bool:
        return await self.delete_by_scan_id(scan_id)

    # ========================================================
    # CLEAR HISTORY
    # ========================================================

    async def clear_history(
        self,
        scan_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Delete all scan records (optionally filtered).

        Returns:
            {"deleted_count": int}
        """
        scan_type = normalize_scan_type(scan_type)
        severity = normalize_severity(severity)

        try:
            with database_session() as db:
                stmt = select(ScanRecord)

                if scan_type:
                    stmt = stmt.where(ScanRecord.scan_type == scan_type)

                if severity:
                    stmt = stmt.where(ScanRecord.severity == severity)

                records = list(db.scalars(stmt))

                deleted_count = 0
                for record in records:
                    db.delete(record)
                    deleted_count += 1

                return {"deleted_count": deleted_count}

        except SQLAlchemyError as exc:
            logger.exception("Failed to clear history")
            raise RuntimeError(
                "Could not clear scan history."
            ) from exc

    # Alias
    async def clear(self, **kwargs: Any) -> dict[str, Any]:
        return await self.clear_history(**kwargs)


# ============================================================
# SINGLETON
# ============================================================

_history_service_instance: Optional[HistoryService] = None


def get_history_service() -> HistoryService:
    """
    Return shared HistoryService instance.

    Used by routers/history.py.
    """
    global _history_service_instance

    if _history_service_instance is None:
        _history_service_instance = HistoryService()

    return _history_service_instance


# ============================================================
# SELF TEST
# ============================================================

if __name__ == "__main__":
    import asyncio

    logging.basicConfig(level=logging.INFO)

    print()
    print("=" * 60)
    print("CYBERGUARD X — History Service Test")
    print("=" * 60)
    print()

    async def test():
        service = get_history_service()

        # Test list
        result = await service.list_history(page=1, page_size=5)
        print(f"List history: {result.get('total', 0)} total scans")
        print(f"Items returned: {len(result.get('items', []))}")

        # Test summary
        summary = await service.get_summary()
        print(f"Summary: {summary}")

        print()
        print("=" * 60)
        print("History service test completed.")
        print("=" * 60)

    asyncio.run(test())
