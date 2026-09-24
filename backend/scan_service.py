"""
CYBERGUARD X — Scan Service Layer

Responsibilities
----------------
- Orchestrate URL / text / QR scan persistence.
- Connect the API layer with the risk engine and threat intelligence.
- Normalize scan results into a stable internal representation.
- Persist scan lifecycle/status information.
- Persist risk/XAI/threat-intelligence metadata when supported.
- Provide scan-history/detail/statistics helpers.
- Keep database logic out of app_upgraded-5.py.

Architecture
------------

    FastAPI
       |
       v
    ScanService
       |
       +----> Risk Engine
       |
       +----> Threat Intelligence
       |
       +----> Database Repository
       |
       v
    Scan Result

The service intentionally does not own HTTP concerns.
HTTPException should remain in app_upgraded-5.py.

The service also does not make security decisions itself.
Risk scoring remains the responsibility of risk_engine.py.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Mapping, Protocol, Sequence


# ============================================================
# LOGGER
# ============================================================

logger = logging.getLogger("cyberguard.scan_service")


# ============================================================
# ENUMS
# ============================================================

class ScanType(str, Enum):
    URL = "url"
    TEXT = "text"
    SMS = "sms"
    EMAIL = "email"
    QR = "qr"
    QUISHING = "qr"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


# ============================================================
# INTERNAL DATA MODELS
# ============================================================

@dataclass(slots=True)
class ScanRecord:
    """
    Stable internal representation of a scan.

    This object is deliberately independent of SQLAlchemy or any
    specific database ORM.
    """

    scan_id: str
    scan_type: str
    status: str

    input_value: str | None = None
    input_hash: str | None = None

    risk_score: float | None = None
    severity: str | None = None
    explanation: str | None = None

    model_score: float | None = None
    rule_adjusted: bool = False

    features: dict[str, Any] = field(default_factory=dict)
    xai: list[str] = field(default_factory=list)

    threat_intelligence: dict[str, Any] = field(
        default_factory=dict
    )

    trace: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    error: str | None = None

    created_at: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    completed_at: str | None = None


@dataclass(slots=True)
class ScanSummary:
    """
    Lightweight scan-history representation.
    """

    scan_id: str
    scan_type: str
    status: str
    risk_score: float | None
    severity: str | None
    created_at: str
    completed_at: str | None = None


# ============================================================
# DATABASE REPOSITORY PROTOCOL
# ============================================================

class ScanRepository(Protocol):
    """
    Optional repository interface.

    database.py can implement these methods directly.

    The service uses capability detection as well, so an existing
    database implementation with slightly different method names
    can still be integrated during the final backend pass.
    """

    async def create_scan(
        self,
        scan: Mapping[str, Any],
    ) -> Any:
        ...

    async def update_scan(
        self,
        scan_id: str,
        values: Mapping[str, Any],
    ) -> Any:
        ...

    async def get_scan(
        self,
        scan_id: str,
    ) -> Any:
        ...

    async def list_scans(
        self,
        **filters: Any,
    ) -> Sequence[Any]:
        ...


# ============================================================
# CALLBACK TYPES
# ============================================================

RiskEvaluator = Callable[
    [Any],
    Any,
]

ThreatIntelligenceChecker = Callable[
    [str],
    Any,
]


# ============================================================
# SERVICE
# ============================================================

class ScanService:
    """
    CYBERGUARD X scan orchestration service.

    The service is intentionally dependency-injected.

    Example:

        service = ScanService(
            repository=repository,
            risk_evaluator=risk_engine.evaluate,
            threat_intelligence_checker=check_virustotal_url,
        )

    The service can therefore be unit-tested without running
    FastAPI or connecting to a real database.
    """

    MAX_HISTORY_LIMIT = 100
    DEFAULT_HISTORY_LIMIT = 20

    MAX_INPUT_LENGTH = 50000

    VALID_SEVERITIES = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    def __init__(
        self,
        repository: Any | None = None,
        risk_evaluator: RiskEvaluator | None = None,
        threat_intelligence_checker: (
            ThreatIntelligenceChecker | None
        ) = None,
    ) -> None:

        self.repository = repository
        self.risk_evaluator = risk_evaluator
        self.threat_intelligence_checker = (
            threat_intelligence_checker
        )

    # ========================================================
    # GENERAL HELPERS
    # ========================================================

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(
            timezone.utc
        ).isoformat()

    @staticmethod
    def _generate_scan_id() -> str:
        return str(uuid.uuid4())

    @staticmethod
    def _hash_input(value: str) -> str:
        return hashlib.sha256(
            value.encode(
                "utf-8",
                errors="replace",
            )
        ).hexdigest()

    @classmethod
    def _normalize_input(
        cls,
        value: Any,
    ) -> str:

        if value is None:
            raise ValueError(
                "Scan input cannot be null."
            )

        normalized = str(value).strip()

        if not normalized:
            raise ValueError(
                "Scan input cannot be empty."
            )

        if len(normalized) > cls.MAX_INPUT_LENGTH:
            raise ValueError(
                "Scan input exceeds the maximum allowed length."
            )

        return normalized

    @staticmethod
    def _normalize_score(
        value: Any,
    ) -> float | None:

        if value is None:
            return None

        try:
            score = float(value)
        except (
            TypeError,
            ValueError,
        ):
            return None

        if score != score:
            return None

        return round(
            max(
                0.0,
                min(
                    score,
                    100.0,
                ),
            ),
            2,
        )

    @classmethod
    def _normalize_severity(
        cls,
        value: Any,
    ) -> str | None:

        if value is None:
            return None

        severity = str(
            value
        ).strip().upper()

        if severity not in cls.VALID_SEVERITIES:
            return None

        return severity

    @staticmethod
    def _ensure_list(
        value: Any,
    ) -> list[Any]:

        if value is None:
            return []

        if isinstance(
            value,
            list,
        ):
            return value

        if isinstance(
            value,
            tuple,
        ):
            return list(value)

        if isinstance(
            value,
            set,
        ):
            return list(value)

        return [value]

    @staticmethod
    def _ensure_dict(
        value: Any,
    ) -> dict[str, Any]:

        if value is None:
            return {}

        if isinstance(
            value,
            dict,
        ):
            return dict(value)

        if isinstance(
            value,
            Mapping,
        ):
            return dict(value)

        return {
            "value": value,
        }

    @staticmethod
    def _safe_json_value(
        value: Any,
    ) -> Any:
        """
        Convert common non-JSON-native values into JSON-safe values.
        """

        if value is None:
            return None

        if isinstance(
            value,
            (
                str,
                int,
                float,
                bool,
            ),
        ):
            return value

        if isinstance(
            value,
            datetime,
        ):
            return value.isoformat()

        if isinstance(
            value,
            Enum,
        ):
            return value.value

        if isinstance(
            value,
            Mapping,
        ):
            return {
                str(key): ScanService._safe_json_value(
                    item
                )
                for key, item in value.items()
            }

        if isinstance(
            value,
            (list, tuple, set),
        ):
            return [
                ScanService._safe_json_value(
                    item
                )
                for item in value
            ]

        if hasattr(
            value,
            "model_dump",
        ):
            try:
                return ScanService._safe_json_value(
                    value.model_dump()
                )
            except Exception:
                pass

        if hasattr(
            value,
            "dict",
        ):
            try:
                return ScanService._safe_json_value(
                    value.dict()
                )
            except Exception:
                pass

        if hasattr(
            value,
            "__dict__",
        ):
            try:
                return ScanService._safe_json_value(
                    vars(value)
                )
            except Exception:
                pass

        return str(value)

    # ========================================================
    # ASYNC CALL HELPER
    # ========================================================

    @staticmethod
    async def _maybe_await(
        result: Any,
    ) -> Any:

        if inspect.isawaitable(result):
            return await result

        return result

    # ========================================================
    # REPOSITORY ADAPTER
    # ========================================================

    async def _repository_call(
        self,
        method_names: Sequence[str],
        *args: Any,
        **kwargs: Any,
    ) -> Any:

        if self.repository is None:
            return None

        for method_name in method_names:

            method = getattr(
                self.repository,
                method_name,
                None,
            )

            if method is None:
                continue

            try:
                result = method(
                    *args,
                    **kwargs,
                )

                return await self._maybe_await(
                    result
                )

            except TypeError as exc:
                logger.debug(
                    "Repository method %s rejected arguments: %s",
                    method_name,
                    exc,
                )
                continue

        return None

    # ========================================================
    # SCAN CREATION
    # ========================================================

    async def create_scan(
        self,
        scan_type: str | ScanType,
        input_value: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> ScanRecord:

        if isinstance(
            scan_type,
            ScanType,
        ):
            scan_type = scan_type.value

        scan_type = str(
            scan_type
        ).strip().lower()

        allowed_types = {
            item.value
            for item in ScanType
        }

        if scan_type not in allowed_types:
            raise ValueError(
                f"Unsupported scan type: {scan_type}"
            )

        normalized_input = None

        if input_value is not None:
            normalized_input = self._normalize_input(
                input_value
            )

        scan = ScanRecord(
            scan_id=self._generate_scan_id(),
            scan_type=scan_type,
            status=ScanStatus.QUEUED.value,
            input_value=normalized_input,
            input_hash=(
                self._hash_input(normalized_input)
                if normalized_input
                else None
            ),
            metadata=self._ensure_dict(
                metadata
            ),
        )

        await self._persist_created_scan(
            scan
        )

        return scan

    async def _persist_created_scan(
        self,
        scan: ScanRecord,
    ) -> None:

        payload = self._scan_to_dict(
            scan
        )

        try:
            await self._repository_call(
                (
                    "create_scan",
                    "insert_scan",
                    "save_scan",
                ),
                payload,
            )
        except Exception:
            logger.exception(
                "Failed to persist scan %s",
                scan.scan_id,
            )
            raise

    # ========================================================
    # STATUS MANAGEMENT
    # ========================================================

    async def mark_processing(
        self,
        scan: ScanRecord,
    ) -> ScanRecord:

        scan.status = (
            ScanStatus.PROCESSING.value
        )

        await self._persist_update(
            scan
        )

        return scan

    async def mark_completed(
        self,
        scan: ScanRecord,
    ) -> ScanRecord:

        scan.status = (
            ScanStatus.COMPLETED.value
        )

        scan.completed_at = (
            self._utc_now()
        )

        await self._persist_update(
            scan
        )

        return scan

    async def mark_failed(
        self,
        scan: ScanRecord,
        error: Any,
    ) -> ScanRecord:

        scan.status = (
            ScanStatus.FAILED.value
        )

        scan.error = self._sanitize_error(
            error
        )

        scan.completed_at = (
            self._utc_now()
        )

        await self._persist_update(
            scan
        )

        return scan

    @staticmethod
    def _sanitize_error(
        error: Any,
    ) -> str:

        message = str(
            error
        ).strip()

        if not message:
            return "Unknown scan error."

        # Avoid accidentally storing enormous exception messages.
        return message[:2000]

    async def _persist_update(
        self,
        scan: ScanRecord,
    ) -> None:

        payload = self._scan_to_dict(
            scan
        )

        await self._repository_call(
            (
                "update_scan",
                "save_scan",
                "upsert_scan",
            ),
            scan.scan_id,
            payload,
        )

    # ========================================================
    # RISK ENGINE
    # ========================================================

    async def evaluate_risk(
        self,
        signals: Any,
    ) -> dict[str, Any]:

        if self.risk_evaluator is None:
            raise RuntimeError(
                "Risk evaluator is not configured."
            )

        try:
            raw_result = self.risk_evaluator(
                signals
            )

            raw_result = await self._maybe_await(
                raw_result
            )

        except Exception as exc:
            logger.exception(
                "Risk engine evaluation failed."
            )
            raise RuntimeError(
                "Risk engine evaluation failed."
            ) from exc

        return self._normalize_assessment(
            raw_result
        )

    # ========================================================
    # ASSESSMENT NORMALIZATION
    # ========================================================

    def _normalize_assessment(
        self,
        assessment: Any,
    ) -> dict[str, Any]:

        if assessment is None:
            assessment = {}

        if hasattr(
            assessment,
            "model_dump",
        ):
            try:
                assessment = assessment.model_dump()
            except Exception:
                pass

        elif hasattr(
            assessment,
            "dict",
        ):
            try:
                assessment = assessment.dict()
            except Exception:
                pass

        if not isinstance(
            assessment,
            Mapping,
        ):
            assessment = {}

        assessment = dict(
            assessment
        )

        score = self._normalize_score(
            assessment.get(
                "score",
                assessment.get(
                    "risk_score"
                ),
            )
        )

        severity = self._normalize_severity(
            assessment.get(
                "severity"
            )
        )

        explanation = str(
            assessment.get(
                "explanation"
            )
            or "Risk assessment completed."
        )

        xai = self._ensure_list(
            assessment.get(
                "xai",
                assessment.get(
                    "xai_breakdown",
                    []
                ),
            )
        )

        features = self._ensure_dict(
            assessment.get(
                "features"
            )
        )

        model_score = self._normalize_score(
            assessment.get(
                "model_score"
            )
        )

        normalized = {
            **assessment,
            "score": (
                score
                if score is not None
                else 0.0
            ),
            "risk_score": (
                score
                if score is not None
                else 0.0
            ),
            "severity": (
                severity
                if severity
                else "LOW"
            ),
            "explanation": explanation,
            "xai": [
                str(item)
                for item in xai
                if str(item).strip()
            ][:20],
            "xai_breakdown": [
                str(item)
                for item in xai
                if str(item).strip()
            ][:20],
            "features": features,
            "model_score": model_score,
            "rule_adjusted": bool(
                assessment.get(
                    "rule_adjusted",
                    False
                )
            ),
        }

        return normalized

    # ========================================================
    # APPLY ASSESSMENT TO SCAN
    # ========================================================

    def attach_assessment(
        self,
        scan: ScanRecord,
        assessment: Mapping[str, Any],
    ) -> ScanRecord:

        normalized = self._normalize_assessment(
            assessment
        )

        scan.risk_score = normalized[
            "risk_score"
        ]

        scan.severity = normalized[
            "severity"
        ]

        scan.explanation = normalized[
            "explanation"
        ]

        scan.model_score = normalized.get(
            "model_score"
        )

        scan.rule_adjusted = bool(
            normalized.get(
                "rule_adjusted",
                False,
            )
        )

        scan.features = self._ensure_dict(
            normalized.get(
                "features"
            )
        )

        scan.xai = [
            str(item)
            for item in self._ensure_list(
                normalized.get(
                    "xai"
                )
            )
        ][:20]

        return scan

    # ========================================================
    # THREAT INTELLIGENCE
    # ========================================================

    async def check_threat_intelligence(
        self,
        target: str,
    ) -> dict[str, Any]:

        target = self._normalize_input(
            target
        )

        if (
            self.threat_intelligence_checker
            is None
        ):
            return {
                "scanned": False,
                "malicious_votes": 0,
                "reason": (
                    "Threat-intelligence provider "
                    "is not configured."
                ),
            }

        try:
            result = (
                self.threat_intelligence_checker(
                    target
                )
            )

            result = await self._maybe_await(
                result
            )

            return self._normalize_threat_intelligence(
                result
            )

        except Exception as exc:
            logger.exception(
                "Threat-intelligence lookup failed."
            )

            return {
                "scanned": False,
                "malicious_votes": 0,
                "error": self._sanitize_error(
                    exc
                ),
            }

    def _normalize_threat_intelligence(
        self,
        result: Any,
    ) -> dict[str, Any]:

        if result is None:
            return {
                "scanned": False,
                "malicious_votes": 0,
            }

        if hasattr(
            result,
            "model_dump",
        ):
            try:
                result = result.model_dump()
            except Exception:
                pass

        elif hasattr(
            result,
            "dict",
        ):
            try:
                result = result.dict()
            except Exception:
                pass

        if not isinstance(
            result,
            Mapping,
        ):
            return {
                "scanned": False,
                "malicious_votes": 0,
                "raw_result": str(
                    result
                ),
            }

        normalized = dict(
            result
        )

        malicious_votes = 0

        try:
            malicious_votes = int(
                normalized.get(
                    "malicious_votes",
                    normalized.get(
                        "malicious",
                        0,
                    ),
                )
            )
        except (
            TypeError,
            ValueError,
        ):
            malicious_votes = 0

        normalized[
            "malicious_votes"
        ] = max(
            0,
            malicious_votes,
        )

        normalized[
            "scanned"
        ] = bool(
            normalized.get(
                "scanned",
                False,
            )
        )

        return self._safe_json_value(
            normalized
        )

    # ========================================================
    # THREAT INTELLIGENCE → RISK
    # ========================================================

    @staticmethod
    def enrich_assessment_with_intelligence(
        assessment: Mapping[str, Any],
        intelligence: Mapping[str, Any],
    ) -> dict[str, Any]:

        result = dict(
            assessment
        )

        malicious_votes = 0

        try:
            malicious_votes = max(
                0,
                int(
                    intelligence.get(
                        "malicious_votes",
                        0,
                    )
                ),
            )
        except (
            TypeError,
            ValueError,
        ):
            malicious_votes = 0

        xai = list(
            result.get(
                "xai",
                []
            )
            or []
        )

        if malicious_votes > 0:
            xai.append(
                "External threat-intelligence provider "
                f"reported {malicious_votes} malicious vote(s)."
            )

        elif intelligence.get(
            "scanned"
        ):
            xai.append(
                "External threat-intelligence lookup completed "
                "without malicious votes in the returned result."
            )

        # Do not silently replace the calibrated risk-engine score.
        # Intelligence is stored as evidence unless a future
        # explicitly calibrated fusion model is introduced.

        result[
            "xai"
        ] = list(
            dict.fromkeys(
                str(item)
                for item in xai
                if str(item).strip()
            )
        )[:20]

        result[
            "threat_intelligence"
        ] = dict(
            intelligence
        )

        return result

    # ========================================================
    # COMPLETE SCAN LIFECYCLE
    # ========================================================

    async def run_scan(
        self,
        scan_type: str | ScanType,
        input_value: str | None,
        signals: Any,
        *,
        metadata: Mapping[str, Any] | None = None,
        threat_intelligence_target: str | None = None,
        trace: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:

        scan = await self.create_scan(
            scan_type=scan_type,
            input_value=input_value,
            metadata=metadata,
        )

        try:

            await self.mark_processing(
                scan
            )

            # ----------------------------------------------
            # Risk evaluation
            # ----------------------------------------------

            assessment = await self.evaluate_risk(
                signals
            )

            # ----------------------------------------------
            # Optional external intelligence
            # ----------------------------------------------

            intelligence = {}

            if threat_intelligence_target:
                intelligence = (
                    await self.check_threat_intelligence(
                        threat_intelligence_target
                    )
                )

                assessment = (
                    self.enrich_assessment_with_intelligence(
                        assessment,
                        intelligence,
                    )
                )

            scan = self.attach_assessment(
                scan,
                assessment,
            )

            scan.threat_intelligence = (
                self._ensure_dict(
                    intelligence
                )
            )

            scan.trace = self._ensure_dict(
                trace
            )

            # ----------------------------------------------
            # Complete
            # ----------------------------------------------

            await self.mark_completed(
                scan
            )

            return self.to_public_result(
                scan
            )

        except Exception as exc:

            await self.mark_failed(
                scan,
                exc,
            )

            raise

    # ========================================================
    # URL SCAN ORCHESTRATION
    # ========================================================

    async def run_url_scan(
        self,
        url: str,
        signals: Any,
        *,
        metadata: Mapping[str, Any] | None = None,
        trace: Mapping[str, Any] | None = None,
        threat_intelligence: bool = True,
    ) -> dict[str, Any]:

        normalized_url = self._normalize_input(
            url
        )

        intelligence_target = (
            normalized_url
            if threat_intelligence
            else None
        )

        return await self.run_scan(
            ScanType.URL,
            normalized_url,
            signals,
            metadata=metadata,
            trace=trace,
            threat_intelligence_target=(
                intelligence_target
            ),
        )

    # ========================================================
    # TEXT SCAN ORCHESTRATION
    # ========================================================

    async def run_text_scan(
        self,
        text: str,
        signals: Any,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:

        normalized_text = self._normalize_input(
            text
        )

        return await self.run_scan(
            ScanType.TEXT,
            normalized_text,
            signals,
            metadata=metadata,
        )

    # ========================================================
    # QR SCAN ORCHESTRATION
    # ========================================================

    async def run_qr_scan(
        self,
        payload: str,
        signals: Any,
        *,
        payload_type: str = "unknown",
        metadata: Mapping[str, Any] | None = None,
        trace: Mapping[str, Any] | None = None,
        threat_intelligence: bool = False,
    ) -> dict[str, Any]:

        normalized_payload = self._normalize_input(
            payload
        )

        merged_metadata = self._ensure_dict(
            metadata
        )

        merged_metadata[
            "payload_type"
        ] = payload_type

        intelligence_target = (
            normalized_payload
            if threat_intelligence
            else None
        )

        return await self.run_scan(
            ScanType.QR,
            normalized_payload,
            signals,
            metadata=merged_metadata,
            trace=trace,
            threat_intelligence_target=(
                intelligence_target
            ),
        )

    # ========================================================
    # HISTORY
    # ========================================================

    async def get_scan(
        self,
        scan_id: str,
    ) -> dict[str, Any] | None:

        scan_id = str(
            scan_id
        ).strip()

        if not scan_id:
            raise ValueError(
                "scan_id cannot be empty."
            )

        result = await self._repository_call(
            (
                "get_scan",
                "find_scan",
                "fetch_scan",
            ),
            scan_id,
        )

        if result is None:
            return None

        return self._record_to_public(
            result
        )

    async def list_history(
        self,
        *,
        limit: int = DEFAULT_HISTORY_LIMIT,
        offset: int = 0,
        scan_type: str | None = None,
        severity: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:

        limit = max(
            1,
            min(
                int(limit),
                self.MAX_HISTORY_LIMIT,
            ),
        )

        offset = max(
            0,
            int(offset),
        )

        filters: dict[str, Any] = {
            "limit": limit,
            "offset": offset,
        }

        if scan_type:
            filters[
                "scan_type"
            ] = str(
                scan_type
            ).lower()

        if severity:
            normalized_severity = (
                self._normalize_severity(
                    severity
                )
            )

            if normalized_severity:
                filters[
                    "severity"
                ] = normalized_severity

        if status:
            filters[
                "status"
            ] = str(
                status
            ).lower()

        result = await self._repository_call(
            (
                "list_scans",
                "get_scan_history",
                "fetch_scans",
            ),
            **filters,
        )

        if result is None:
            return []

        if isinstance(
            result,
            Mapping,
        ):
            result = result.get(
                "items",
                []
            )

        return [
            self._record_to_public(
                item
            )
            for item in result
        ]

    # ========================================================
    # STATISTICS
    # ========================================================

    async def get_statistics(self) -> dict[str, Any]:

        result = await self._repository_call(
            (
                "get_scan_statistics",
                "scan_statistics",
                "statistics",
            )
        )

        if result is not None:
            return self._safe_json_value(
                result
            )

        # Graceful fallback when database.py does not yet
        # expose aggregate statistics.
        history = await self.list_history(
            limit=self.MAX_HISTORY_LIMIT
        )

        total = len(
            history
        )

        completed = sum(
            1
            for item in history
            if item.get(
                "status"
            )
            == ScanStatus.COMPLETED.value
        )

        failed = sum(
            1
            for item in history
            if item.get(
                "status"
            )
            == ScanStatus.FAILED.value
        )

        severity_counts = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }

        scan_type_counts: dict[str, int] = {}

        for item in history:

            severity = item.get(
                "severity"
            )

            if severity in severity_counts:
                severity_counts[
                    severity
                ] += 1

            scan_type = str(
                item.get(
                    "scan_type",
                    "unknown",
                )
            )

            scan_type_counts[
                scan_type
            ] = (
                scan_type_counts.get(
                    scan_type,
                    0,
                )
                + 1
            )

        scores = [
            float(
                item["risk_score"]
            )
            for item in history
            if item.get(
                "risk_score"
            ) is not None
        ]

        average_score = (
            round(
                sum(scores)
                / len(scores),
                2,
            )
            if scores
            else 0.0
        )

        return {
            "total_scans": total,
            "completed_scans": completed,
            "failed_scans": failed,
            "average_risk_score": average_score,
            "severity_counts": severity_counts,
            "scan_type_counts": scan_type_counts,
        }

    # ========================================================
    # DELETE / RETENTION
    # ========================================================

    async def delete_scan(
        self,
        scan_id: str,
    ) -> bool:

        scan_id = str(
            scan_id
        ).strip()

        if not scan_id:
            return False

        result = await self._repository_call(
            (
                "delete_scan",
                "remove_scan",
            ),
            scan_id,
        )

        if result is None:
            return False

        return bool(
            result
        )

    async def delete_before(
        self,
        before: datetime,
    ) -> int:

        if before.tzinfo is None:
            before = before.replace(
                tzinfo=timezone.utc
            )

        result = await self._repository_call(
            (
                "delete_scans_before",
                "delete_before",
                "purge_scans_before",
            ),
            before,
        )

        if result is None:
            return 0

        try:
            return max(
                0,
                int(result),
            )
        except (
            TypeError,
            ValueError,
        ):
            return 0

    # ========================================================
    # PUBLIC SERIALIZATION
    # ========================================================

    def to_public_result(
        self,
        scan: ScanRecord,
    ) -> dict[str, Any]:

        return {
            "status": (
                "success"
                if scan.status
                == ScanStatus.COMPLETED.value
                else scan.status
            ),
            "input_type": scan.scan_type,
            "scan_id": scan.scan_id,
            "assessment": {
                "score": scan.risk_score or 0.0,
                "risk_score": scan.risk_score or 0.0,
                "severity": scan.severity or "LOW",
                "explanation": (
                    scan.explanation
                    or "Risk assessment completed."
                ),
                "xai": list(
                    scan.xai
                ),
                "xai_breakdown": list(
                    scan.xai
                ),
                "model_score": scan.model_score,
                "rule_adjusted": scan.rule_adjusted,
                "features": dict(
                    scan.features
                ),
            },
            "threat_intelligence": dict(
                scan.threat_intelligence
            ),
            "trace": dict(
                scan.trace
            ),
            "metadata": dict(
                scan.metadata
            ),
            "created_at": scan.created_at,
            "completed_at": scan.completed_at,
        }

    # ========================================================
    # DATABASE RECORD CONVERSION
    # ========================================================

    def _record_to_public(
        self,
        record: Any,
    ) -> dict[str, Any]:

        if isinstance(
            record,
            ScanRecord,
        ):
            return self.to_public_result(
                record
            )

        if hasattr(
            record,
            "model_dump",
        ):
            try:
                record = record.model_dump()
            except Exception:
                pass

        elif hasattr(
            record,
            "dict",
        ):
            try:
                record = record.dict()
            except Exception:
                pass

        elif hasattr(
            record,
            "__dict__",
        ):
            try:
                record = vars(record)
            except Exception:
                pass

        if not isinstance(
            record,
            Mapping,
        ):
            return {
                "scan_id": str(
                    record
                )
            }

        data = dict(
            record
        )

        # Accommodate common database column names.
        scan_id = data.get(
            "scan_id",
            data.get(
                "id"
            ),
        )

        scan_type = data.get(
            "scan_type",
            data.get(
                "input_type",
                "unknown",
            ),
        )

        risk_score = self._normalize_score(
            data.get(
                "risk_score",
                data.get(
                    "score"
                ),
            )
        )

        severity = self._normalize_severity(
            data.get(
                "severity"
            )
        )

        xai = self._ensure_list(
            data.get(
                "xai",
                data.get(
                    "xai_breakdown",
                    []
                ),
            )
        )

        features = self._ensure_dict(
            data.get(
                "features"
            )
        )

        threat_intelligence = (
            self._ensure_dict(
                data.get(
                    "threat_intelligence",
                    data.get(
                        "intelligence"
                    ),
                )
            )
        )

        trace = self._ensure_dict(
            data.get(
                "trace"
            )
        )

        metadata = self._ensure_dict(
            data.get(
                "metadata"
            )
        )

        return {
            "status": data.get(
                "status",
                "unknown",
            ),
            "input_type": scan_type,
            "scan_id": (
                str(scan_id)
                if scan_id is not None
                else None
            ),
            "assessment": {
                "score": (
                    risk_score
                    if risk_score is not None
                    else 0.0
                ),
                "risk_score": (
                    risk_score
                    if risk_score is not None
                    else 0.0
                ),
                "severity": (
                    severity
                    or "LOW"
                ),
                "explanation": str(
                    data.get(
                        "explanation",
                        "Risk assessment completed.",
                    )
                ),
                "xai": [
                    str(item)
                    for item in xai
                ][:20],
                "xai_breakdown": [
                    str(item)
                    for item in xai
                ][:20],
                "model_score": (
                    self._normalize_score(
                        data.get(
                            "model_score"
                        )
                    )
                ),
                "rule_adjusted": bool(
                    data.get(
                        "rule_adjusted",
                        False,
                    )
                ),
                "features": features,
            },
            "threat_intelligence": (
                threat_intelligence
            ),
            "trace": trace,
            "metadata": metadata,
            "created_at": data.get(
                "created_at"
            ),
            "completed_at": data.get(
                "completed_at"
            ),
        }

    def _scan_to_dict(
        self,
        scan: ScanRecord,
    ) -> dict[str, Any]:

        data = asdict(
            scan
        )

        return self._safe_json_value(
            data
        )

    # ========================================================
    # EXPORT
    # ========================================================

    async def export_scan(
        self,
        scan_id: str,
    ) -> dict[str, Any] | None:

        scan = await self.get_scan(
            scan_id
        )

        if scan is None:
            return None

        return {
            "export_version": "1.0",
            "exported_at": self._utc_now(),
            "scan": scan,
        }

    async def export_scan_json(
        self,
        scan_id: str,
    ) -> str | None:

        data = await self.export_scan(
            scan_id
        )

        if data is None:
            return None

        return json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            default=str,
        )


# ============================================================
# FACTORY
# ============================================================

def create_scan_service(
    *,
    repository: Any | None = None,
    risk_engine: Any | None = None,
    threat_intelligence_checker: (
        ThreatIntelligenceChecker | None
    ) = None,
) -> ScanService:
    """
    Convenience factory for app_upgraded-5.py.

    Example:

        scan_service = create_scan_service(
            repository=db,
            risk_engine=risk_engine,
            threat_intelligence_checker=check_virustotal_url,
        )
    """

    evaluator = None

    if risk_engine is not None:

        evaluator = getattr(
            risk_engine,
            "evaluate",
            None,
        )

        if evaluator is None:
            raise ValueError(
                "risk_engine must expose an evaluate() method."
            )

    return ScanService(
        repository=repository,
        risk_evaluator=evaluator,
        threat_intelligence_checker=(
            threat_intelligence_checker
        ),
    )


# ============================================================
# LOCAL SELF-TEST REPOSITORY
# ============================================================

class InMemoryScanRepository:
    """
    Small development/test repository.

    This is NOT intended as production storage.

    It lets you test scan_service.py independently before
    connecting the real database.py.
    """

    def __init__(self) -> None:
        self.scans: dict[
            str,
            dict[str, Any],
        ] = {}

    async def create_scan(
        self,
        scan: Mapping[str, Any],
    ) -> dict[str, Any]:

        data = dict(
            scan
        )

        scan_id = str(
            data["scan_id"]
        )

        self.scans[
            scan_id
        ] = data

        return data

    async def update_scan(
        self,
        scan_id: str,
        values: Mapping[str, Any],
    ) -> dict[str, Any]:

        if scan_id not in self.scans:
            self.scans[
                scan_id
            ] = {
                "scan_id": scan_id
            }

        self.scans[
            scan_id
        ].update(
            dict(
                values
            )
        )

        return self.scans[
            scan_id
        ]

    async def get_scan(
        self,
        scan_id: str,
    ) -> dict[str, Any] | None:

        return self.scans.get(
            scan_id
        )

    async def list_scans(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        scan_type: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        **_: Any,
    ) -> list[dict[str, Any]]:

        records = list(
            self.scans.values()
        )

        if scan_type:
            records = [
                item
                for item in records
                if item.get(
                    "scan_type"
                )
                == scan_type
            ]

        if severity:
            records = [
                item
                for item in records
                if str(
                    item.get(
                        "severity"
                    )
                ).upper()
                == str(
                    severity
                ).upper()
            ]

        if status:
            records = [
                item
                for item in records
                if item.get(
                    "status"
                )
                == status
            ]

        return records[
            offset : offset + limit
        ]

    async def delete_scan(
        self,
        scan_id: str,
    ) -> bool:

        if scan_id not in self.scans:
            return False

        del self.scans[
            scan_id
        ]

        return True


# ============================================================
# OPTIONAL SELF-TEST
# ============================================================

if __name__ == "__main__":

    import asyncio

    @dataclass
    class DemoSignals:
        domain_age_days: float = 0.8
        redirect_hops: int = 2
        typosquat_similarity: float = 0.82
        nlp_urgency_score: float = 0.75
        auth_failure_flag: int = 1
        visual_brand_spoof: float = 0.80
        external_ioc_hits: int = 1
        upi_anomaly_flag: int = 0

    async def demo():

        async def demo_risk_evaluator(
            signals: Any,
        ) -> dict[str, Any]:

            return {
                "score": 76.5,
                "risk_score": 76.5,
                "severity": "HIGH",
                "explanation": (
                    "High-risk indicators were identified."
                ),
                "xai": [
                    "High domain-novelty signal detected.",
                    "High similarity to a monitored brand/domain.",
                ],
                "features": {
                    "domain_novelty": 0.8,
                    "redirect_chain_depth": 0.4,
                },
                "model_score": 72.1,
                "rule_adjusted": True,
            }

        async def demo_intelligence(
            target: str,
        ) -> dict[str, Any]:

            return {
                "scanned": True,
                "malicious_votes": 2,
                "stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "harmless": 70,
                },
            }

        repository = (
            InMemoryScanRepository()
        )

        service = ScanService(
            repository=repository,
            risk_evaluator=demo_risk_evaluator,
            threat_intelligence_checker=(
                demo_intelligence
            ),
        )

        result = await service.run_url_scan(
            "https://example.com",
            DemoSignals(),
            metadata={
                "test": True
            },
            trace={
                "original_url": (
                    "https://example.com"
                ),
                "final_url": (
                    "https://example.com"
                ),
                "hops": [],
            },
            threat_intelligence=True,
        )

        print(
            "\nCYBERGUARD X Scan Service Test"
        )
        print(
            "=============================="
        )
        print(
            json.dumps(
                result,
                indent=2,
                default=str,
            )
        )

        print(
            "\nHistory:"
        )

        history = (
            await service.list_history()
        )

        print(
            json.dumps(
                history,
                indent=2,
                default=str,
            )
        )

        print(
            "\nStatistics:"
        )

        statistics = (
            await service.get_statistics()
        )

        print(
            json.dumps(
                statistics,
                indent=2,
                default=str,
            )
        )

    asyncio.run(
        demo()
    )
