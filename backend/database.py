"""
CYBERGUARD X — Database / Scan History Layer

Responsibilities:
    - Database configuration
    - Scan-result persistence
    - Scan history retrieval
    - Scan lookup by scan_id
    - Scan deletion
    - Pagination
    - Search/filter support
    - JSON metadata/XAI/intelligence storage
    - Database health checking
    - SQLite development support
    - PostgreSQL-ready configuration

The scanner/risk engine should NOT contain database logic.
app_upgraded-5.py should call this module after a scan completes.

Environment variables:

    DATABASE_URL=
        Optional database URL.

    Example SQLite:
        sqlite:///./cyberguard.db

    Example PostgreSQL:
        postgresql+psycopg://user:password@localhost/cyberguard

Default:
    sqlite:///./cyberguard.db
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional

from sqlalchemy import (
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    delete,
    func,
    select,
    text,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)

# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger("cyberguard.database")

# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ============================================================
# DATABASE CONFIGURATION
# ============================================================

DEFAULT_DATABASE_URL = (
    f"sqlite:///{PROJECT_ROOT / 'cyberguard.db'}"
)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    DEFAULT_DATABASE_URL,
).strip()

# SQLite needs this option when FastAPI requests use separate
# worker threads.
connect_args: dict[str, Any] = {}

if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

# ============================================================
# SQLALCHEMY ENGINE
# ============================================================

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)

# ============================================================
# BASE MODEL
# ============================================================


class Base(DeclarativeBase):
    """Base class for all CYBERGUARD X database models."""


# ============================================================
# UTILITY FUNCTIONS
# ============================================================


def utc_now() -> datetime:
    """
    Return timezone-aware UTC datetime.
    """
    return datetime.now(timezone.utc)


def json_dumps(value: Any) -> str:
    """
    Safely serialize Python data into JSON text.

    Database columns use TEXT rather than database-specific JSON
    types so SQLite and PostgreSQL can both use the same model.
    """

    if value is None:
        return "{}"

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
    except (TypeError, ValueError):
        return "{}"


def json_loads(value: Optional[str]) -> Any:
    """
    Safely deserialize JSON text.
    """

    if not value:
        return {}

    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}


def normalize_string(
    value: Any,
    maximum_length: int = 10000,
) -> str:
    """
    Convert arbitrary input to a safe bounded string.
    """

    if value is None:
        return ""

    result = str(value).strip()

    if len(result) > maximum_length:
        result = result[:maximum_length]

    return result


# ============================================================
# SCAN MODEL
# ============================================================


class ScanRecord(Base):
    """
    Persistent CYBERGUARD X scan record.

    One row represents one completed scan.

    Sensitive/raw input should only be stored when the application
    explicitly chooses to retain it.
    """

    __tablename__ = "scan_records"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    scan_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )

    input_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    # Original user-submitted input.
    # This can contain a URL, message, or QR payload.
    input_value: Mapped[str] = mapped_column(
        Text,
        nullable=True,
    )

    # URL-specific information.
    original_url: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    final_url: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    domain: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    # ========================================================
    # RISK RESULT
    # ========================================================

    score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="LOW",
        index=True,
    )

    explanation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )

    # ========================================================
    # MODEL / ENGINE DATA
    # ========================================================

    model_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )

    rule_adjusted: Mapped[bool] = mapped_column(
        nullable=False,
        default=False,
    )

    # ========================================================
    # JSON DATA
    # ========================================================

    xai_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="[]",
    )

    features_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="{}",
    )

    metadata_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="{}",
    )

    threat_intelligence_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="{}",
    )

    trace_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="{}",
    )

    # ========================================================
    # TIMESTAMP
    # ========================================================

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    __table_args__ = (
        Index(
            "ix_scan_records_created_severity",
            "created_at",
            "severity",
        ),
        Index(
            "ix_scan_records_type_created",
            "input_type",
            "created_at",
        ),
    )


# ============================================================
# DATABASE INITIALIZATION
# ============================================================


def init_db() -> None:
    """
    Create database tables if they do not already exist.
    """

    try:
        Base.metadata.create_all(
            bind=engine,
        )

        logger.info(
            "CYBERGUARD X database initialized."
        )

    except SQLAlchemyError as exc:
        logger.exception(
            "Database initialization failed."
        )
        raise RuntimeError(
            "Could not initialize CYBERGUARD X database."
        ) from exc


# ============================================================
# SESSION MANAGEMENT
# ============================================================


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency for database sessions.

    Example:

        @app.get("/history")
        def history(db: Session = Depends(get_db)):
            ...
    """

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()


@contextmanager
def database_session() -> Generator[Session, None, None]:
    """
    Context-manager style database session.

    Useful outside FastAPI dependency injection.
    """

    db = SessionLocal()

    try:
        yield db
        db.commit()

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


# ============================================================
# SERIALIZATION
# ============================================================


def scan_record_to_dict(
    record: ScanRecord,
    include_input: bool = True,
) -> dict[str, Any]:
    """
    Convert ScanRecord into API-friendly JSON-compatible data.
    """

    result: dict[str, Any] = {
        "scan_id": record.scan_id,
        "input_type": record.input_type,
        "score": round(float(record.score or 0.0), 2),
        "risk_score": round(float(record.score or 0.0), 2),
        "severity": record.severity,
        "explanation": record.explanation,
        "model_score": round(
            float(record.model_score or 0.0),
            2,
        ),
        "rule_adjusted": bool(record.rule_adjusted),
        "xai": json_loads(record.xai_json),
        "features": json_loads(record.features_json),
        "metadata": json_loads(record.metadata_json),
        "threat_intelligence": json_loads(
            record.threat_intelligence_json
        ),
        "trace": json_loads(record.trace_json),
        "created_at": (
            record.created_at.isoformat()
            if record.created_at
            else None
        ),
        "updated_at": (
            record.updated_at.isoformat()
            if record.updated_at
            else None
        ),
    }

    if include_input:
        result["input"] = record.input_value

        if record.original_url:
            result["original_url"] = record.original_url

        if record.final_url:
            result["final_url"] = record.final_url

        if record.domain:
            result["domain"] = record.domain

    return result


# ============================================================
# CREATE SCAN
# ============================================================


def create_scan(
    db: Session,
    *,
    scan_id: Optional[str] = None,
    input_type: str,
    input_value: Optional[str] = None,
    assessment: Optional[dict[str, Any]] = None,
    metadata: Optional[dict[str, Any]] = None,
    trace: Optional[dict[str, Any]] = None,
    threat_intelligence: Optional[dict[str, Any]] = None,
    original_url: Optional[str] = None,
    final_url: Optional[str] = None,
    domain: Optional[str] = None,
) -> ScanRecord:
    """
    Persist a completed scan.

    The assessment object is expected to come from risk_engine.py.

    Example:

        record = create_scan(
            db,
            input_type="url",
            input_value=url,
            assessment=assessment,
            metadata=metadata,
            trace=trace,
            threat_intelligence=vt_result,
        )
    """

    assessment = assessment or {}
    metadata = metadata or {}
    trace = trace or {}
    threat_intelligence = threat_intelligence or {}

    scan_id = (
        normalize_string(scan_id, 64)
        or str(uuid.uuid4())
    )

    score = float(
        assessment.get(
            "score",
            assessment.get("risk_score", 0.0),
        ) or 0.0
    )

    model_score = float(
        assessment.get(
            "model_score",
            score,
        ) or 0.0
    )

    severity = normalize_string(
        assessment.get(
            "severity",
            "LOW",
        ),
        20,
    ).upper()

    explanation = normalize_string(
        assessment.get(
            "explanation",
            "",
        ),
        10000,
    )

    record = ScanRecord(
        scan_id=scan_id,
        input_type=normalize_string(
            input_type,
            50,
        ),
        input_value=normalize_string(
            input_value,
            50000,
        ),
        original_url=normalize_string(
            original_url,
            4096,
        ) or None,
        final_url=normalize_string(
            final_url,
            4096,
        ) or None,
        domain=normalize_string(
            domain,
            255,
        ).lower() or None,
        score=max(
            0.0,
            min(score, 100.0),
        ),
        severity=severity,
        explanation=explanation,
        model_score=max(
            0.0,
            min(model_score, 100.0),
        ),
        rule_adjusted=bool(
            assessment.get(
                "rule_adjusted",
                False,
            )
        ),
        xai_json=json_dumps(
            assessment.get(
                "xai",
                assessment.get(
                    "xai_breakdown",
                    [],
                ),
            )
        ),
        features_json=json_dumps(
            assessment.get(
                "features",
                {},
            )
        ),
        metadata_json=json_dumps(
            metadata,
        ),
        threat_intelligence_json=json_dumps(
            threat_intelligence,
        ),
        trace_json=json_dumps(
            trace,
        ),
        created_at=utc_now(),
        updated_at=utc_now(),
    )

    try:
        db.add(record)
        db.commit()
        db.refresh(record)

        return record

    except SQLAlchemyError as exc:
        db.rollback()

        logger.exception(
            "Could not persist scan %s.",
            scan_id,
        )

        raise RuntimeError(
            "Could not save scan result."
        ) from exc


# ============================================================
# GET SCAN BY ID
# ============================================================


def get_scan_by_id(
    db: Session,
    scan_id: str,
) -> Optional[ScanRecord]:
    """
    Retrieve one scan by its public scan_id.
    """

    scan_id = normalize_string(
        scan_id,
        64,
    )

    if not scan_id:
        return None

    statement = select(
        ScanRecord
    ).where(
        ScanRecord.scan_id == scan_id
    )

    return db.scalar(statement)


# ============================================================
# GET SCAN RESULT
# ============================================================


def get_scan_result(
    db: Session,
    scan_id: str,
    *,
    include_input: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Retrieve a serialized scan result.
    """

    record = get_scan_by_id(
        db,
        scan_id,
    )

    if record is None:
        return None

    return scan_record_to_dict(
        record,
        include_input=include_input,
    )


# ============================================================
# SCAN HISTORY
# ============================================================


def list_scans(
    db: Session,
    *,
    page: int = 1,
    page_size: int = 20,
    input_type: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    include_input: bool = False,
) -> dict[str, Any]:
    """
    Paginated scan history.

    Supported filters:

        input_type
        severity
        search

    Search currently checks:
        scan_id
        domain
        original_url
        final_url
    """

    page = max(
        1,
        int(page),
    )

    page_size = max(
        1,
        min(
            int(page_size),
            100,
        ),
    )

    conditions = []

    if input_type:
        conditions.append(
            ScanRecord.input_type
            == normalize_string(
                input_type,
                50,
            )
        )

    if severity:
        conditions.append(
            ScanRecord.severity
            == normalize_string(
                severity,
                20,
            ).upper()
        )

    if search:
        search_value = (
            f"%{normalize_string(search, 255)}%"
        )

        conditions.append(
            (
                ScanRecord.scan_id.ilike(
                    search_value
                )
                | ScanRecord.domain.ilike(
                    search_value
                )
                | ScanRecord.original_url.ilike(
                    search_value
                )
                | ScanRecord.final_url.ilike(
                    search_value
                )
            )
        )

    # --------------------------------------------------------
    # Total count
    # --------------------------------------------------------

    count_statement = select(
        func.count()
    ).select_from(
        ScanRecord
    )

    if conditions:
        count_statement = count_statement.where(
            *conditions
        )

    total = int(
        db.scalar(count_statement) or 0
    )

    # --------------------------------------------------------
    # Records
    # --------------------------------------------------------

    offset = (
        page - 1
    ) * page_size

    statement = (
        select(ScanRecord)
        .where(*conditions)
        .order_by(
            ScanRecord.created_at.desc()
        )
        .offset(offset)
        .limit(page_size)
    )

    records = list(
        db.scalars(statement)
    )

    total_pages = (
        (total + page_size - 1)
        // page_size
        if total
        else 0
    )

    return {
        "items": [
            scan_record_to_dict(
                record,
                include_input=include_input,
            )
            for record in records
        ],
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_previous": page > 1,
        },
    }


# ============================================================
# DELETE ONE SCAN
# ============================================================


def delete_scan(
    db: Session,
    scan_id: str,
) -> bool:
    """
    Delete one scan.

    Returns:
        True  -> deleted
        False -> scan did not exist
    """

    record = get_scan_by_id(
        db,
        scan_id,
    )

    if record is None:
        return False

    try:
        db.delete(record)
        db.commit()
        return True

    except SQLAlchemyError as exc:
        db.rollback()

        logger.exception(
            "Could not delete scan %s.",
            scan_id,
        )

        raise RuntimeError(
            "Could not delete scan."
        ) from exc


# ============================================================
# DELETE OLD SCANS
# ============================================================


def delete_scans_before(
    db: Session,
    cutoff: datetime,
) -> int:
    """
    Delete scans older than the supplied UTC timestamp.

    Useful for retention policies.
    """

    try:
        statement = delete(
            ScanRecord
        ).where(
            ScanRecord.created_at < cutoff
        )

        result = db.execute(statement)
        db.commit()

        return int(
            result.rowcount or 0
        )

    except SQLAlchemyError as exc:
        db.rollback()

        logger.exception(
            "Could not delete old scan records."
        )

        raise RuntimeError(
            "Could not delete old scans."
        ) from exc


# ============================================================
# DATABASE STATISTICS
# ============================================================


def get_scan_statistics(
    db: Session,
) -> dict[str, Any]:
    """
    Return dashboard-friendly scan statistics.
    """

    total = int(
        db.scalar(
            select(
                func.count()
            ).select_from(
                ScanRecord
            )
        )
        or 0
    )

    # --------------------------------------------------------
    # Severity counts
    # --------------------------------------------------------

    severity_rows = db.execute(
        select(
            ScanRecord.severity,
            func.count(ScanRecord.id),
        )
        .group_by(
            ScanRecord.severity
        )
    ).all()

    severity_counts = {
        str(severity).upper(): int(count)
        for severity, count in severity_rows
    }

    # --------------------------------------------------------
    # Input type counts
    # --------------------------------------------------------

    type_rows = db.execute(
        select(
            ScanRecord.input_type,
            func.count(ScanRecord.id),
        )
        .group_by(
            ScanRecord.input_type
        )
    ).all()

    type_counts = {
        str(input_type): int(count)
        for input_type, count in type_rows
    }

    # --------------------------------------------------------
    # Average risk
    # --------------------------------------------------------

    average_score = db.scalar(
        select(
            func.avg(
                ScanRecord.score
            )
        )
    )

    return {
        "total_scans": total,
        "average_risk_score": round(
            float(
                average_score or 0.0
            ),
            2,
        ),
        "severity_counts": severity_counts,
        "input_type_counts": type_counts,
    }


# ============================================================
# DATABASE HEALTH
# ============================================================


def database_health() -> dict[str, Any]:
    """
    Check whether the database is reachable.
    """

    try:
        with engine.connect() as connection:
            connection.execute(
                text("SELECT 1")
            )

        return {
            "status": "healthy",
            "database": "available",
            "database_url_type": (
                "sqlite"
                if DATABASE_URL.startswith("sqlite")
                else "external"
            ),
        }

    except SQLAlchemyError as exc:
        logger.exception(
            "Database health check failed."
        )

        return {
            "status": "unhealthy",
            "database": "unavailable",
            "error": str(exc),
        }


# ============================================================
# STARTUP
# ============================================================


def startup_database() -> None:
    """
    Application startup helper.

    app_upgraded-5.py can call:

        startup_database()

    during FastAPI startup.
    """

    init_db()


# ============================================================
# SHUTDOWN
# ============================================================


def shutdown_database() -> None:
    """
    Dispose the SQLAlchemy connection pool.
    """

    try:
        engine.dispose()

    except Exception:
        logger.exception(
            "Database engine shutdown encountered an error."
        )


# ============================================================
# LOCAL SELF-TEST
# ============================================================


def _self_test() -> None:
    """
    Basic local database test.

    Run:

        python database.py
    """

    logging.basicConfig(
        level=logging.INFO,
    )

    print(
        "\nCYBERGUARD X Database Self-Test"
    )
    print(
        "================================"
    )

    startup_database()

    with database_session() as db:

        record = create_scan(
            db,
            input_type="url",
            input_value="https://example.com",
            original_url="https://example.com",
            final_url="https://example.com",
            domain="example.com",
            assessment={
                "score": 12.5,
                "risk_score": 12.5,
                "severity": "LOW",
                "explanation": (
                    "No major high-confidence risk indicators "
                    "were identified."
                ),
                "model_score": 12.5,
                "rule_adjusted": False,
                "xai": [
                    "Test scan created successfully."
                ],
                "features": {
                    "domain_novelty": 0.1,
                    "redirect_chain_depth": 0.0,
                },
            },
            metadata={
                "self_test": True
            },
            trace={
                "original_url": "https://example.com",
                "final_url": "https://example.com",
                "hops": [],
            },
            threat_intelligence={
                "scanned": False,
                "reason": "self_test",
            },
        )

        print(
            f"Created scan: {record.scan_id}"
        )

        result = get_scan_result(
            db,
            record.scan_id,
        )

        print(
            "Retrieved:"
        )
        print(
            json.dumps(
                result,
                indent=2,
                default=str,
            )
        )

        statistics = get_scan_statistics(
            db
        )

        print(
            "\nStatistics:"
        )
        print(
            json.dumps(
                statistics,
                indent=2,
            )
        )

        deleted = delete_scan(
            db,
            record.scan_id,
        )

        print(
            f"\nDeleted test scan: {deleted}"
        )

    print(
        "\nDatabase self-test completed."
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    _self_test()
