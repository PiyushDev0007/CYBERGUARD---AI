"""
CYBERGUARD X — API Schemas
===========================

Centralized Pydantic models for the CYBERGUARD X backend.

Responsibilities:
    - Validate incoming API requests
    - Standardize API responses
    - Define risk-assessment structures
    - Define threat-intelligence structures
    - Define URL/redirect/domain metadata
    - Define QR/text scan responses
    - Define database-facing scan summaries
    - Keep app_upgraded-5.py thin and maintainable

This module contains DATA CONTRACTS only.

It should not:
    - Perform network requests
    - Run Playwright
    - Call VirusTotal
    - Query RDAP
    - Run the risk engine
    - Access the database
    - Perform filesystem operations
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


# ============================================================
# ENUMS
# ============================================================


class InputType(str, Enum):
    URL = "url"
    TEXT = "text"
    SMS = "sms"
    EMAIL = "email"
    QR = "qr"
    UNKNOWN = "unknown"


class PayloadType(str, Enum):
    URL = "url"
    UPI = "upi"
    TEXT = "text"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScanStatus(str, Enum):
    SUCCESS = "success"
    ERROR = "error"
    PARTIAL = "partial"
    PENDING = "pending"


class ThreatIntelStatus(str, Enum):
    SCANNED = "scanned"
    NOT_SCANNED = "not_scanned"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class Verdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


# ============================================================
# BASE MODEL
# ============================================================


class CyberGuardBaseModel(BaseModel):
    """
    Base model used throughout the API.

    extra="ignore" keeps the API tolerant of harmless extra
    fields coming from older frontend versions.
    """

    model_config = ConfigDict(
        extra="ignore",
        validate_assignment=True,
        use_enum_values=True,
    )


# ============================================================
# COMMON ERROR SCHEMA
# ============================================================


class ErrorResponse(CyberGuardBaseModel):
    status: str = Field(
        default="error",
        description="API operation status.",
    )

    error: str = Field(
        ...,
        description="Short machine-readable error name.",
    )

    message: str = Field(
        ...,
        description="Human-readable error description.",
    )

    code: Optional[str] = Field(
        default=None,
        description="Optional application error code.",
    )

    scan_id: Optional[str] = Field(
        default=None,
        description="Associated scan identifier, when available.",
    )

    details: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional structured error details.",
    )


# ============================================================
# REQUEST SCHEMAS
# ============================================================


class URLScanRequest(CyberGuardBaseModel):
    """
    Request body for URL scanning.
    """

    url: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="HTTP or HTTPS URL to analyze.",
    )

    @field_validator("url")
    @classmethod
    def validate_url_input(cls, value: str) -> str:
        value = str(value).strip()

        if not value:
            raise ValueError("URL cannot be empty.")

        return value


class TextScanRequest(CyberGuardBaseModel):
    """
    Request body for SMS/email/text analysis.
    """

    text: str = Field(
        ...,
        min_length=1,
        max_length=50000,
        description="Text content to analyze.",
    )

    input_type: InputType = Field(
        default=InputType.TEXT,
        description="Optional classification of the text input.",
    )

    @field_validator("text")
    @classmethod
    def validate_text_input(cls, value: str) -> str:
        value = str(value).strip()

        if not value:
            raise ValueError("Text content cannot be empty.")

        return value


class QRScanOptions(CyberGuardBaseModel):
    """
    Optional configuration for QR scanning.
    """

    analyze_redirects: bool = Field(
        default=True,
        description="Whether decoded URL redirects should be analyzed.",
    )

    check_threat_intelligence: bool = Field(
        default=True,
        description="Whether external threat intelligence should be queried.",
    )


# ============================================================
# BASIC RISK SCHEMAS
# ============================================================


class RiskFeatureValues(CyberGuardBaseModel):
    """
    Normalized feature values generated by risk_engine.py.
    """

    domain_novelty: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    redirect_chain_depth: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    typosquat_index: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    semantic_urgency: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    auth_protocol_failure: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    brand_spoof_similarity: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    threat_feed_reputation: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    financial_upi_tampering: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )


class XAIContribution(CyberGuardBaseModel):
    """
    Structured explainability item.

    This allows the frontend to display XAI as structured data
    rather than relying only on strings.
    """

    feature: str = Field(
        ...,
        description="Internal feature name.",
    )

    label: str = Field(
        ...,
        description="Human-readable feature name.",
    )

    contribution: float = Field(
        default=0.0,
        description="Model contribution.",
    )

    direction: str = Field(
        default="neutral",
        description="positive, negative or neutral.",
    )

    explanation: Optional[str] = None


class RiskAssessment(CyberGuardBaseModel):
    """
    Unified risk-engine result.
    """

    score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
    )

    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
    )

    severity: Severity = Field(
        ...,
    )

    verdict: Verdict = Field(
        default=Verdict.UNKNOWN,
    )

    explanation: str = Field(
        default="Risk assessment completed.",
    )

    xai: List[str] = Field(
        default_factory=list,
    )

    xai_breakdown: List[str] = Field(
        default_factory=list,
    )

    model_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    rule_adjusted: bool = False

    features: Dict[str, float] = Field(
        default_factory=dict,
    )

    model_version: Optional[str] = None

    @model_validator(mode="after")
    def synchronize_scores(self) -> "RiskAssessment":
        """
        Keep score and risk_score consistent for frontend
        compatibility.
        """

        if self.score != self.risk_score:
            self.risk_score = self.score

        return self


# ============================================================
# REDIRECT SCHEMAS
# ============================================================


class RedirectHop(CyberGuardBaseModel):
    """
    Individual redirect observed during URL navigation.
    """

    url: str = Field(
        ...,
        max_length=4096,
    )

    status: Optional[int] = Field(
        default=None,
        ge=100,
        le=599,
    )

    location: Optional[str] = Field(
        default=None,
        max_length=4096,
    )

    hostname: Optional[str] = None


class URLTrace(CyberGuardBaseModel):
    """
    Complete URL navigation trace.
    """

    original_url: str = Field(
        ...,
        max_length=4096,
    )

    final_url: str = Field(
        ...,
        max_length=4096,
    )

    hops: List[RedirectHop] = Field(
        default_factory=list,
    )

    hop_count: int = Field(
        default=0,
        ge=0,
    )

    @model_validator(mode="after")
    def calculate_hop_count(self) -> "URLTrace":
        self.hop_count = len(self.hops)
        return self


# ============================================================
# URL INTELLIGENCE SCHEMAS
# ============================================================


class TyposquatAnalysis(CyberGuardBaseModel):
    score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    matched_brand: Optional[str] = None

    technique: Optional[str] = None

    signals: List[str] = Field(
        default_factory=list,
    )


class URLObfuscationAnalysis(CyberGuardBaseModel):
    score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    findings: List[str] = Field(
        default_factory=list,
    )


class DomainIntelligence(CyberGuardBaseModel):
    domain: Optional[str] = None

    registration_date: Optional[str] = None

    domain_age_days: Optional[int] = Field(
        default=None,
        ge=0,
    )

    age_source: Optional[str] = None

    registrar: Optional[str] = None

    nameservers: List[str] = Field(
        default_factory=list,
    )

    status: List[str] = Field(
        default_factory=list,
    )


class URLMetadata(CyberGuardBaseModel):
    domain: Optional[str] = None

    scheme: Optional[str] = None

    port: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535,
    )

    domain_age_days: Optional[int] = Field(
        default=None,
        ge=0,
    )

    registration_date: Optional[str] = None

    age_source: Optional[str] = None

    typosquat_similarity: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    typosquat: Optional[TyposquatAnalysis] = None

    suspicious_tld: bool = False

    obfuscation: Optional[URLObfuscationAnalysis] = None

    redirect_hops: int = Field(
        default=0,
        ge=0,
    )

    ioc_indicator_count: int = Field(
        default=0,
        ge=0,
    )

    ip_addresses: List[str] = Field(
        default_factory=list,
    )

    hostname_is_ip: bool = False

    https_enabled: bool = False


# ============================================================
# THREAT INTELLIGENCE SCHEMAS
# ============================================================


class ThreatIntelProviderResult(CyberGuardBaseModel):
    """
    Result returned by an individual intelligence provider.

    Examples:
        VirusTotal
        Google Safe Browsing
        URLhaus
        AbuseIPDB
        custom internal feed
    """

    provider: str

    status: ThreatIntelStatus = ThreatIntelStatus.NOT_SCANNED

    available: bool = True

    scanned: bool = False

    malicious: bool = False

    suspicious: bool = False

    malicious_votes: int = Field(
        default=0,
        ge=0,
    )

    suspicious_votes: int = Field(
        default=0,
        ge=0,
    )

    harmless_votes: int = Field(
        default=0,
        ge=0,
    )

    undetected_votes: int = Field(
        default=0,
        ge=0,
    )

    reputation_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
    )

    categories: List[str] = Field(
        default_factory=list,
    )

    tags: List[str] = Field(
        default_factory=list,
    )

    details: Dict[str, Any] = Field(
        default_factory=dict,
    )

    error: Optional[str] = None

    note: Optional[str] = None


class ThreatIntelligenceResult(CyberGuardBaseModel):
    """
    Aggregated threat-intelligence result.
    """

    status: ThreatIntelStatus = ThreatIntelStatus.NOT_SCANNED

    scanned: bool = False

    malicious: bool = False

    suspicious: bool = False

    indicator_count: int = Field(
        default=0,
        ge=0,
    )

    reputation_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
    )

    providers: List[ThreatIntelProviderResult] = Field(
        default_factory=list,
    )

    findings: List[str] = Field(
        default_factory=list,
    )

    errors: List[str] = Field(
        default_factory=list,
    )


# ============================================================
# TEXT INTELLIGENCE
# ============================================================


class TextAnalysisMetadata(CyberGuardBaseModel):
    character_count: int = Field(
        default=0,
        ge=0,
    )

    word_count: int = Field(
        default=0,
        ge=0,
    )

    url_count: int = Field(
        default=0,
        ge=0,
    )

    urgency_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    urgency_matches: List[str] = Field(
        default_factory=list,
    )

    brand_mentions: List[str] = Field(
        default_factory=list,
    )

    upi_signal: bool = False

    extracted_urls: List[str] = Field(
        default_factory=list,
    )


# ============================================================
# UPI SCHEMAS
# ============================================================


class UPIAnalysis(CyberGuardBaseModel):
    detected: bool = False

    payload: Optional[str] = None

    handle: Optional[str] = None

    merchant_name: Optional[str] = None

    amount: Optional[float] = Field(
        default=None,
        ge=0,
    )

    currency: Optional[str] = None

    findings: List[str] = Field(
        default_factory=list,
    )


# ============================================================
# QR SCHEMAS
# ============================================================


class QRMetadata(CyberGuardBaseModel):
    filename: Optional[str] = None

    content_type: Optional[str] = None

    decoded: bool = False

    payload_type: PayloadType = PayloadType.UNKNOWN

    detector: str = "OpenCV QRCodeDetector"


# ============================================================
# COMPLETE SCAN RESPONSE
# ============================================================


class ScanResponse(CyberGuardBaseModel):
    """
    Standard response used by URL, text and QR scanners.
    """

    status: ScanStatus = ScanStatus.SUCCESS

    input_type: InputType

    scan_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
    )

    created_at: datetime = Field(
        default_factory=datetime.utcnow,
    )

    verdict: Verdict = Verdict.UNKNOWN

    assessment: Optional[RiskAssessment] = None

    trace: Optional[URLTrace] = None

    metadata: Dict[str, Any] = Field(
        default_factory=dict,
    )

    threat_intelligence: Optional[ThreatIntelligenceResult] = None

    message: Optional[str] = None

    warnings: List[str] = Field(
        default_factory=list,
    )

    errors: List[str] = Field(
        default_factory=list,
    )

    @model_validator(mode="after")
    def derive_verdict(self) -> "ScanResponse":
        """
        Derive a stable verdict from severity when a caller
        did not explicitly provide one.
        """

        if self.assessment is not None:
            severity = self.assessment.severity

            if severity == Severity.CRITICAL:
                self.verdict = Verdict.MALICIOUS

            elif severity == Severity.HIGH:
                self.verdict = Verdict.MALICIOUS

            elif severity == Severity.MEDIUM:
                self.verdict = Verdict.SUSPICIOUS

            elif severity == Severity.LOW:
                self.verdict = Verdict.SAFE

        return self


# ============================================================
# URL SCAN RESPONSE
# ============================================================


class URLScanResponse(ScanResponse):
    input_type: InputType = InputType.URL

    trace: Optional[URLTrace] = None

    metadata: Dict[str, Any] = Field(
        default_factory=dict,
    )


# ============================================================
# TEXT SCAN RESPONSE
# ============================================================


class TextScanResponse(ScanResponse):
    input_type: InputType = InputType.TEXT

    text_analysis: Optional[TextAnalysisMetadata] = None

    extracted_urls: List[str] = Field(
        default_factory=list,
    )


# ============================================================
# QR SCAN RESPONSE
# ============================================================


class QRScanResponse(ScanResponse):
    input_type: InputType = InputType.QR

    payload_type: PayloadType = PayloadType.UNKNOWN

    extracted_payload: Optional[str] = None

    qr_metadata: Optional[QRMetadata] = None

    upi_analysis: Optional[UPIAnalysis] = None


# ============================================================
# GENERIC SCAN RECORD
# ============================================================


class ScanRecord(CyberGuardBaseModel):
    """
    Database/API representation of a completed scan.

    This intentionally avoids storing raw uploaded files.
    """

    scan_id: str

    input_type: InputType

    status: ScanStatus

    verdict: Verdict

    severity: Optional[Severity] = None

    risk_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
    )

    target: Optional[str] = None

    domain: Optional[str] = None

    created_at: datetime = Field(
        default_factory=datetime.utcnow,
    )

    completed_at: Optional[datetime] = None

    processing_time_ms: Optional[float] = Field(
        default=None,
        ge=0,
    )

    threat_indicator_count: int = Field(
        default=0,
        ge=0,
    )

    summary: Optional[str] = None


# ============================================================
# HEALTH / SYSTEM STATUS
# ============================================================


class ComponentHealth(CyberGuardBaseModel):
    name: str

    status: str

    version: Optional[str] = None

    latency_ms: Optional[float] = Field(
        default=None,
        ge=0,
    )

    details: Dict[str, Any] = Field(
        default_factory=dict,
    )


class HealthResponse(CyberGuardBaseModel):
    status: str

    service: str

    version: Optional[str] = None

    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
    )

    components: List[ComponentHealth] = Field(
        default_factory=list,
    )


# ============================================================
# ROOT RESPONSE
# ============================================================


class RootResponse(CyberGuardBaseModel):
    status: str

    service: str

    version: str

    engine: str

    features: List[str] = Field(
        default_factory=list,
    )


# ============================================================
# PAGINATION
# ============================================================


class PaginationRequest(CyberGuardBaseModel):
    page: int = Field(
        default=1,
        ge=1,
        le=100000,
    )

    page_size: int = Field(
        default=20,
        ge=1,
        le=100,
    )


class PaginationResponse(CyberGuardBaseModel):
    page: int

    page_size: int

    total: int = Field(
        default=0,
        ge=0,
    )

    total_pages: int = Field(
        default=0,
        ge=0,
    )

    has_next: bool = False

    has_previous: bool = False


# ============================================================
# SCAN HISTORY
# ============================================================


class ScanHistoryResponse(CyberGuardBaseModel):
    status: str = "success"

    items: List[ScanRecord] = Field(
        default_factory=list,
    )

    pagination: PaginationResponse


# ============================================================
# STATISTICS / DASHBOARD
# ============================================================


class RiskDistribution(CyberGuardBaseModel):
    low: int = Field(default=0, ge=0)

    medium: int = Field(default=0, ge=0)

    high: int = Field(default=0, ge=0)

    critical: int = Field(default=0, ge=0)


class ScanStatistics(CyberGuardBaseModel):
    total_scans: int = Field(
        default=0,
        ge=0,
    )

    successful_scans: int = Field(
        default=0,
        ge=0,
    )

    failed_scans: int = Field(
        default=0,
        ge=0,
    )

    malicious_scans: int = Field(
        default=0,
        ge=0,
    )

    suspicious_scans: int = Field(
        default=0,
        ge=0,
    )

    safe_scans: int = Field(
        default=0,
        ge=0,
    )

    risk_distribution: RiskDistribution = Field(
        default_factory=RiskDistribution,
    )

    average_risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )


class DashboardResponse(CyberGuardBaseModel):
    status: str = "success"

    generated_at: datetime = Field(
        default_factory=datetime.utcnow,
    )

    statistics: ScanStatistics

    recent_scans: List[ScanRecord] = Field(
        default_factory=list,
    )


# ============================================================
# BATCH SCANNING
# ============================================================


class BatchURLScanRequest(CyberGuardBaseModel):
    urls: List[str] = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    check_threat_intelligence: bool = True

    follow_redirects: bool = True

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, values: List[str]) -> List[str]:
        cleaned: List[str] = []

        for value in values:
            value = str(value).strip()

            if not value:
                continue

            if len(value) > 4096:
                raise ValueError(
                    "Individual URL cannot exceed 4096 characters."
                )

            cleaned.append(value)

        if not cleaned:
            raise ValueError(
                "At least one valid URL value is required."
            )

        return cleaned


class BatchScanItem(CyberGuardBaseModel):
    index: int = Field(
        ...,
        ge=0,
    )

    target: str

    status: ScanStatus

    result: Optional[ScanResponse] = None

    error: Optional[str] = None


class BatchScanResponse(CyberGuardBaseModel):
    status: ScanStatus

    batch_id: str

    total: int = Field(
        default=0,
        ge=0,
    )

    completed: int = Field(
        default=0,
        ge=0,
    )

    failed: int = Field(
        default=0,
        ge=0,
    )

    items: List[BatchScanItem] = Field(
        default_factory=list,
    )


# ============================================================
# ASYNC JOB SCHEMAS
# ============================================================


class ScanJobStatus(CyberGuardBaseModel):
    job_id: str

    status: str

    progress: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    message: Optional[str] = None

    scan_id: Optional[str] = None

    created_at: datetime = Field(
        default_factory=datetime.utcnow,
    )

    completed_at: Optional[datetime] = None

    result: Optional[ScanResponse] = None

    error: Optional[str] = None


# ============================================================
# API VERSION / CAPABILITIES
# ============================================================


class CapabilityResponse(CyberGuardBaseModel):
    service: str

    version: str

    capabilities: Dict[str, bool] = Field(
        default_factory=dict,
    )

    providers: List[str] = Field(
        default_factory=list,
    )


# ============================================================
# INTERNAL NORMALIZATION HELPERS
# ============================================================


def assessment_from_dict(
    data: Dict[str, Any],
) -> RiskAssessment:
    """
    Safely convert an existing risk_engine dictionary into the
    standardized RiskAssessment model.

    Useful while migrating the existing backend.
    """

    payload = dict(data or {})

    score = payload.get(
        "score",
        payload.get("risk_score", 0.0),
    )

    payload["score"] = score
    payload["risk_score"] = score

    severity = str(
        payload.get(
            "severity",
            "LOW",
        )
    ).upper()

    if severity not in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }:
        severity = "LOW"

    payload["severity"] = severity

    if "xai" not in payload:
        payload["xai"] = payload.get(
            "xai_breakdown",
            [],
        )

    if "xai_breakdown" not in payload:
        payload["xai_breakdown"] = payload.get(
            "xai",
            [],
        )

    return RiskAssessment.model_validate(
        payload
    )


def threat_intelligence_from_dict(
    data: Dict[str, Any],
) -> ThreatIntelligenceResult:
    """
    Convert a threat_intelligence.py result dictionary into the
    standardized API schema.
    """

    payload = dict(data or {})

    providers = payload.get(
        "providers",
        [],
    )

    normalized_providers: List[Dict[str, Any]] = []

    if isinstance(providers, dict):
        for provider_name, provider_data in providers.items():
            provider_payload = dict(
                provider_data
                if isinstance(provider_data, dict)
                else {}
            )

            provider_payload.setdefault(
                "provider",
                provider_name,
            )

            normalized_providers.append(
                provider_payload
            )

    elif isinstance(providers, list):
        normalized_providers = providers

    payload["providers"] = normalized_providers

    return ThreatIntelligenceResult.model_validate(
        payload
    )


# ============================================================
# SCHEMA EXPORTS
# ============================================================


__all__ = [
    # Enums
    "InputType",
    "PayloadType",
    "Severity",
    "ScanStatus",
    "ThreatIntelStatus",
    "Verdict",

    # Requests
    "URLScanRequest",
    "TextScanRequest",
    "QRScanOptions",
    "BatchURLScanRequest",

    # Risk
    "RiskFeatureValues",
    "XAIContribution",
    "RiskAssessment",

    # URL intelligence
    "RedirectHop",
    "URLTrace",
    "TyposquatAnalysis",
    "URLObfuscationAnalysis",
    "DomainIntelligence",
    "URLMetadata",

    # Threat intelligence
    "ThreatIntelProviderResult",
    "ThreatIntelligenceResult",

    # Text / UPI / QR
    "TextAnalysisMetadata",
    "UPIAnalysis",
    "QRMetadata",

    # Responses
    "ScanResponse",
    "URLScanResponse",
    "TextScanResponse",
    "QRScanResponse",
    "ErrorResponse",

    # Database/history
    "ScanRecord",
    "ScanHistoryResponse",

    # Health
    "ComponentHealth",
    "HealthResponse",
    "RootResponse",
    "CapabilityResponse",

    # Pagination/dashboard
    "PaginationRequest",
    "PaginationResponse",
    "ScanStatistics",
    "RiskDistribution",
    "DashboardResponse",

    # Batch/jobs
    "BatchScanItem",
    "BatchScanResponse",
    "ScanJobStatus",

    # Helpers
    "assessment_from_dict",
    "threat_intelligence_from_dict",
]
