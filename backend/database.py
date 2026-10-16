"""
CYBERGUARD X — Database Layer
==============================

Provides:
    - SQLAlchemy engine & session
    - ScanRecord model (scan history)
    - User model (authentication)
    - Database initialization
    - Health check
    - CRUD helpers

Compatible with:
    - history_service.py
    - auth_service.py
    - scan_service.py
    - main.py
"""

from __future__ import annotations

import json
import logging
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
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
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_DB_PATH = PROJECT_ROOT / "cyberguard.db"

import os

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{DEFAULT_DB_PATH}",
).strip()

# SQLite needs this for FastAPI multithreading
connect_args: dict[str, Any] = {}

if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False


# ============================================================
# ENGINE + SESSION
# ============================================================

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    echo=False,
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
    """Base class for all CyberGuard X models."""
    pass


# ============================================================
# HELPERS
# ============================================================

def utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def json_dumps(value: Any) -> str:
    """Safely serialize to JSON text."""
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
    """Safely deserialize JSON text."""
    if not value:
        return {}
    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}


def normalize_string(value: Any, max_len: int = 10000) -> str:
    """Convert to safe bounded string."""
    if value is None:
        return ""
    result = str(value).strip()
    if len(result) > max_len:
        result = result[:max_len]
    return result


# ============================================================
# SCAN RECORD MODEL (for history_service.py)
# ============================================================

class ScanRecord(Base):
    """
    Persistent scan history record.

    Matches the fields expected by history_service.py:
        - scan_id
        - scan_type
        - input_value
        - risk_score
        - severity
        - explanation
        - xai (JSON text)
        - metadata (JSON text)
        - status
        - created_at
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

    scan_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    input_value: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # URL-specific
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

    # Risk result
    risk_score: Mapped[float] = mapped_column(
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

    # Engine metadata
    model_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )

    rule_adjusted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    # JSON text fields
    xai: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="[]",
    )

    features: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="{}",
    )

    metadata_json: Mapped[str] = mapped_column(
        "metadata",
        Text,
        nullable=False,
        default="{}",
    )

    threat_intelligence: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="{}",
    )

    trace: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="{}",
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="success",
    )

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

    def to_dict(self) -> dict[str, Any]:
        """Convert to API-friendly dict."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "scan_type": self.scan_type,
            "input_type": self.scan_type,
            "input_value": self.input_value,
            "risk_score": self.risk_score,
            "score": self.risk_score,
            "severity": self.severity,
            "explanation": self.explanation,
            "model_score": self.model_score,
            "rule_adjusted": self.rule_adjusted,
            "xai": json_loads(self.xai),
            "features": json_loads(self.features),
            "metadata": json_loads(self.metadata_json),
            "threat_intelligence": json_loads(self.threat_intelligence),
            "trace": json_loads(self.trace),
            "status": self.status,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at else None
            ),
            "updated_at": (
                self.updated_at.isoformat()
                if self.updated_at else None
            ),
        }


# ============================================================
# USER MODEL (for auth_service.py)
# ============================================================

class User(Base):
    """
    CyberGuard X user account.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    email: Mapped[str] = mapped_column(
        String(320),
        unique=True,
        nullable=False,
        index=True,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    name: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def to_dict(self) -> dict[str, Any]:
        """Safe dict (no password_hash)."""
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "is_active": self.is_active,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at else None
            ),
            "last_login_at": (
                self.last_login_at.isoformat()
                if self.last_login_at else None
            ),
        }


# ============================================================
# INITIALIZATION
# ============================================================

def init_db() -> None:
    """Create tables if not exist."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully.")
    except SQLAlchemyError as exc:
        logger.exception("Database initialization failed.")
        raise RuntimeError(
            "Could not initialize database."
        ) from exc


# Alias for main.py compatibility
initialize_database = init_db


def close_db() -> None:
    """Dispose engine connection pool."""
    try:
        engine.dispose()
        logger.info("Database engine disposed.")
    except Exception:
        logger.exception("Error disposing database engine.")


# Alias for main.py compatibility
close_database = close_db


# ============================================================
# SESSION MANAGEMENT
# ============================================================

def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency for database sessions.

    Usage:
        def route(db: Session = Depends(get_db)):
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
    Context-manager style session with auto-commit/rollback.
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


def get_database_session() -> Session:
    """
    Return a new database session.

    Used by history_service.py.

    IMPORTANT:
        Caller is responsible for commit/rollback/close.
    """
    return SessionLocal()


# ============================================================
# HEALTH CHECK
# ============================================================

def health_check() -> dict[str, Any]:
    """
    Check database connectivity.

    Used by main.py readiness endpoint.
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))

        return {
            "healthy": True,
            "ready": True,
            "message": "Database is available.",
            "database_url_type": (
                "sqlite"
                if DATABASE_URL.startswith("sqlite")
                else "external"
            ),
        }
    except SQLAlchemyError as exc:
        logger.exception("Database health check failed.")
        return {
            "healthy": False,
            "ready": False,
            "message": f"Database unavailable: {exc}",
        }


# Alias for main.py
check_database_health = health_check


# ============================================================
# SCAN CRUD HELPERS
# ============================================================

def create_scan(
    db: Session,
    *,
    scan_id: Optional[str] = None,
    scan_type: str,
    input_value: Optional[str] = None,
    assessment: Optional[dict[str, Any]] = None,
    metadata: Optional[dict[str, Any]] = None,
    trace: Optional[dict[str, Any]] = None,
    threat_intelligence: Optional[dict[str, Any]] = None,
    original_url: Optional[str] = None,
    final_url: Optional[str] = None,
    domain: Optional[str] = None,
    status: str = "success",
) -> ScanRecord:
    """
    Persist a completed scan.

    Used by history_service.py and scan_service.py.
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
        assessment.get("model_score", score) or 0.0
    )

    severity = normalize_string(
        assessment.get("severity", "LOW"),
        20,
    ).upper()

    explanation = normalize_string(
        assessment.get("explanation", ""),
        10000,
    )

    record = ScanRecord(
        scan_id=scan_id,
        scan_type=normalize_string(scan_type, 50),
        input_value=normalize_string(input_value, 50000) or None,
        original_url=normalize_string(original_url, 4096) or None,
        final_url=normalize_string(final_url, 4096) or None,
        domain=normalize_string(domain, 255).lower() or None,
        risk_score=max(0.0, min(score, 100.0)),
        severity=severity,
        explanation=explanation,
        model_score=max(0.0, min(model_score, 100.0)),
        rule_adjusted=bool(assessment.get("rule_adjusted", False)),
        xai=json_dumps(
            assessment.get("xai")
            or assessment.get("xai_breakdown")
            or []
        ),
        features=json_dumps(assessment.get("features", {})),
        metadata_json=json_dumps(metadata),
        threat_intelligence=json_dumps(threat_intelligence),
        trace=json_dumps(trace),
        status=normalize_string(status, 50),
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
        logger.exception("Could not persist scan %s.", scan_id)
        raise RuntimeError(
            "Could not save scan result."
        ) from exc


def get_scan_by_id(
    db: Session,
    scan_id: str,
) -> Optional[ScanRecord]:
    """Retrieve one scan by scan_id."""
    scan_id = normalize_string(scan_id, 64)
    if not scan_id:
        return None

    stmt = select(ScanRecord).where(
        ScanRecord.scan_id == scan_id
    )
    return db.scalar(stmt)


def list_scans(
    db: Session,
    *,
    page: int = 1,
    page_size: int = 20,
    scan_type: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
) -> dict[str, Any]:
    """Paginated scan history."""
    page = max(1, int(page))
    page_size = max(1, min(int(page_size), 100))

    conditions = []

    if scan_type:
        conditions.append(
            ScanRecord.scan_type == normalize_string(scan_type, 50)
        )

    if severity:
        conditions.append(
            ScanRecord.severity == normalize_string(severity, 20).upper()
        )

    if search:
        search_value = f"%{normalize_string(search, 255)}%"
        conditions.append(
            ScanRecord.scan_id.ilike(search_value)
            | ScanRecord.domain.ilike(search_value)
            | ScanRecord.original_url.ilike(search_value)
            | ScanRecord.final_url.ilike(search_value)
        )

    # Count
    count_stmt = select(func.count()).select_from(ScanRecord)
    if conditions:
        count_stmt = count_stmt.where(*conditions)
    total = int(db.scalar(count_stmt) or 0)

    # Records
    offset = (page - 1) * page_size
    stmt = (
        select(ScanRecord)
        .where(*conditions)
        .order_by(ScanRecord.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    records = list(db.scalars(stmt))

    total_pages = (
        (total + page_size - 1) // page_size if total else 0
    )

    return {
        "items": [r.to_dict() for r in records],
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_previous": page > 1,
        },
    }


def delete_scan(
    db: Session,
    scan_id: str,
) -> bool:
    """Delete one scan record."""
    record = get_scan_by_id(db, scan_id)
    if record is None:
        return False

    try:
        db.delete(record)
        db.commit()
        return True
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Could not delete scan %s.", scan_id)
        raise RuntimeError("Could not delete scan.") from exc


def get_scan_statistics(
    db: Session,
) -> dict[str, Any]:
    """Dashboard statistics."""
    total = int(
        db.scalar(select(func.count()).select_from(ScanRecord)) or 0
    )

    severity_rows = db.execute(
        select(ScanRecord.severity, func.count(ScanRecord.id))
        .group_by(ScanRecord.severity)
    ).all()

    severity_counts = {
        str(sev).upper(): int(cnt)
        for sev, cnt in severity_rows
    }

    type_rows = db.execute(
        select(ScanRecord.scan_type, func.count(ScanRecord.id))
        .group_by(ScanRecord.scan_type)
    ).all()

    type_counts = {
        str(t): int(c) for t, c in type_rows
    }

    avg = db.scalar(select(func.avg(ScanRecord.risk_score)))

    return {
        "total_scans": total,
        "average_risk_score": round(float(avg or 0.0), 2),
        "severity_counts": severity_counts,
        "scan_type_counts": type_counts,
    }


# ============================================================
# STARTUP
# ============================================================

def startup_database() -> None:
    """Called during FastAPI startup."""
    init_db()


def shutdown_database() -> None:
    """Called during FastAPI shutdown."""
    close_db()


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print()
    print("=" * 60)
    print("CYBERGUARD X — Database Test")
    print("=" * 60)
    print()

    startup_database()

    health = health_check()
    print(f"Health: {health}")
    print()

    with database_session() as db:
        record = create_scan(
            db,
            scan_type="url",
            input_value="https://example.com",
            original_url="https://example.com",
            final_url="https://example.com",
            domain="example.com",
            assessment={
                "score": 12.5,
                "severity": "LOW",
                "explanation": "Test scan",
                "xai": ["Test"],
            },
            metadata={"test": True},
        )

        print(f"Created scan: {record.scan_id}")

        stats = get_scan_statistics(db)
        print(f"Stats: {stats}")

    print()
    print("=" * 60)
    print("Database test completed.")
    print("=" * 60)
