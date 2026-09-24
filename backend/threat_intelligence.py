"""
CYBERGUARD X — Threat Intelligence Layer
=========================================

Purpose
-------
Centralized external and network intelligence service for CyberGuard X.

Responsibilities
----------------
- VirusTotal URL reputation
- VirusTotal URL submission
- VirusTotal analysis polling
- RDAP domain intelligence
- Domain registration age
- Registrar information
- Nameservers
- Domain status/events
- DNS resolution
- IP/network classification
- IOC normalization
- Provider health/status
- TTL caching
- Async-safe network operations
- Retry and timeout handling
- Structured provenance
- Graceful provider failure

Architecture
------------

    app_upgraded-5.py
            |
            v
    ThreatIntelligenceService
            |
       +----+---------+
       |              |
       v              v
    VirusTotal       RDAP
       |              |
       +------+-------+
              |
              v
       Unified intelligence
              |
              v
         risk_engine.py


IMPORTANT
---------
External intelligence is evidence, not an absolute verdict.

A VirusTotal result depends on the engines and data available to
VirusTotal at the time of the query.

RDAP data may be unavailable or incomplete for some domains.

This module therefore never treats provider failure as a malicious
result.


Environment variables
---------------------

CYBERGUARD_VT_API_KEY
    VirusTotal API key.

CYBERGUARD_VT_BASE_URL
    Optional VirusTotal API base URL.
    Default:
        https://www.virustotal.com/api/v3

CYBERGUARD_RDAP_BASE_URL
    Optional RDAP bootstrap endpoint.
    Default:
        https://rdap.org

CYBERGUARD_TI_TIMEOUT
    Network timeout in seconds.
    Default: 10

CYBERGUARD_TI_CONNECT_TIMEOUT
    Connection timeout.
    Default: 5

CYBERGUARD_TI_MAX_RETRIES
    Maximum retry count.
    Default: 2

CYBERGUARD_TI_CACHE_TTL
    Default cache lifetime in seconds.
    Default: 300

CYBERGUARD_TI_MAX_CACHE_ITEMS
    Maximum in-memory cache entries.
    Default: 1000

CYBERGUARD_VT_POLL_INTERVAL
    Polling interval when waiting for submitted VT analysis.
    Default: 3

CYBERGUARD_VT_MAX_POLLS
    Maximum analysis polling attempts.
    Default: 5
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import logging
import os
import socket
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Optional
from urllib.parse import urlparse

import requests


# ============================================================================
# LOGGING
# ============================================================================

logger = logging.getLogger("cyberguard.threat_intelligence")

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | "
        "cyberguard.threat_intelligence | %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

logger.setLevel(
    os.getenv("CYBERGUARD_LOG_LEVEL", "INFO").upper()
)


# ============================================================================
# CONFIGURATION
# ============================================================================

VT_API_KEY = os.getenv(
    "CYBERGUARD_VT_API_KEY",
    os.getenv("VIRUSTOTAL_API_KEY", ""),
).strip()

VT_BASE_URL = os.getenv(
    "CYBERGUARD_VT_BASE_URL",
    "https://www.virustotal.com/api/v3",
).rstrip("/")

RDAP_BASE_URL = os.getenv(
    "CYBERGUARD_RDAP_BASE_URL",
    "https://rdap.org",
).rstrip("/")

DEFAULT_TIMEOUT = float(
    os.getenv("CYBERGUARD_TI_TIMEOUT", "10")
)

CONNECT_TIMEOUT = float(
    os.getenv("CYBERGUARD_TI_CONNECT_TIMEOUT", "5")
)

MAX_RETRIES = max(
    0,
    int(os.getenv("CYBERGUARD_TI_MAX_RETRIES", "2")),
)

CACHE_TTL = max(
    0,
    int(os.getenv("CYBERGUARD_TI_CACHE_TTL", "300")),
)

MAX_CACHE_ITEMS = max(
    10,
    int(os.getenv("CYBERGUARD_TI_MAX_CACHE_ITEMS", "1000")),
)

VT_POLL_INTERVAL = max(
    1.0,
    float(os.getenv("CYBERGUARD_VT_POLL_INTERVAL", "3")),
)

VT_MAX_POLLS = max(
    1,
    int(os.getenv("CYBERGUARD_VT_MAX_POLLS", "5")),
)

USER_AGENT = os.getenv(
    "CYBERGUARD_TI_USER_AGENT",
    "CyberGuard-X-ThreatIntelligence/1.0",
)


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class ProviderStatus:
    """
    Describes the state of one intelligence provider.
    """

    provider: str
    configured: bool
    available: bool
    checked: bool
    status: str
    message: str = ""
    latency_ms: Optional[float] = None
    http_status: Optional[int] = None
    rate_limited: bool = False
    error: Optional[str] = None


@dataclass
class CacheEntry:
    """
    Simple in-memory TTL cache entry.
    """

    value: Any
    created_at: float
    expires_at: float


@dataclass
class VirusTotalResult:
    """
    Normalized VirusTotal result.
    """

    provider: str = "virustotal"

    configured: bool = False
    scanned: bool = False

    status: str = "not_checked"

    url: Optional[str] = None
    url_id: Optional[str] = None

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0
    failure: int = 0
    type_unsupported: int = 0

    total_engines: int = 0
    detection_ratio: float = 0.0

    reputation: Optional[int] = None

    analysis_id: Optional[str] = None
    analysis_status: Optional[str] = None

    note: Optional[str] = None
    error: Optional[str] = None

    source: str = "VirusTotal"


@dataclass
class RDAPResult:
    """
    Normalized RDAP domain intelligence.
    """

    provider: str = "rdap"

    queried: bool = False
    status: str = "not_checked"

    domain: Optional[str] = None

    handle: Optional[str] = None
    ldh_name: Optional[str] = None
    unicode_name: Optional[str] = None

    registrar_name: Optional[str] = None
    registrar_handle: Optional[str] = None

    registration_date: Optional[str] = None
    expiration_date: Optional[str] = None
    last_changed_date: Optional[str] = None

    age_days: Optional[int] = None

    nameservers: list[str] = field(
        default_factory=list
    )

    domain_status: list[str] = field(
        default_factory=list
    )

    dnssec: Optional[bool] = None

    entities: list[dict[str, Any]] = field(
        default_factory=list
    )

    source: str = "RDAP"

    error: Optional[str] = None


@dataclass
class DNSResult:
    """
    Normalized DNS intelligence.
    """

    hostname: str

    resolved: bool = False

    addresses: list[str] = field(
        default_factory=list
    )

    public_addresses: list[str] = field(
        default_factory=list
    )

    private_addresses: list[str] = field(
        default_factory=list
    )

    reserved_addresses: list[str] = field(
        default_factory=list
    )

    loopback_addresses: list[str] = field(
        default_factory=list
    )

    link_local_addresses: list[str] = field(
        default_factory=list
    )

    multicast_addresses: list[str] = field(
        default_factory=list
    )

    unspecified_addresses: list[str] = field(
        default_factory=list
    )

    status: str = "not_checked"

    error: Optional[str] = None

    source: str = "DNS"


@dataclass
class ThreatIntelligenceResult:
    """
    Unified intelligence result consumed by the application/risk engine.
    """

    target: str

    target_type: str = "unknown"

    timestamp: str = ""

    providers: dict[str, Any] = field(
        default_factory=dict
    )

    indicators: list[str] = field(
        default_factory=list
    )

    warnings: list[str] = field(
        default_factory=list
    )

    errors: list[str] = field(
        default_factory=list
    )

    external_ioc_hits: int = 0

    malicious_detected: bool = False
    suspicious_detected: bool = False

    intelligence_score: float = 0.0

    confidence: float = 0.0

    provenance: list[str] = field(
        default_factory=list
    )

    status: str = "completed"


# ============================================================================
# GENERIC HELPERS
# ============================================================================

def utc_now_iso() -> str:
    """
    Return current UTC timestamp in ISO-8601 format.
    """

    return datetime.now(
        timezone.utc
    ).isoformat()


def clamp(
    value: float,
    minimum: float = 0.0,
    maximum: float = 1.0,
) -> float:
    """
    Clamp numeric value.
    """

    try:
        numeric = float(value)
    except (
        TypeError,
        ValueError,
    ):
        numeric = minimum

    return max(
        minimum,
        min(
            numeric,
            maximum,
        ),
    )


def normalize_hostname(
    hostname: str,
) -> str:
    """
    Normalize hostname.
    """

    value = str(
        hostname or ""
    ).strip().lower().rstrip(".")

    return value


def extract_hostname(
    target: str,
) -> str:
    """
    Extract hostname from URL or hostname input.
    """

    value = str(
        target or ""
    ).strip()

    if not value:
        return ""

    if "://" not in value:
        value = f"https://{value}"

    try:
        parsed = urlparse(value)
        return normalize_hostname(
            parsed.hostname or ""
        )
    except Exception:
        return ""


def is_ip_address(
    value: str,
) -> bool:
    """
    Return True when value is a valid IPv4/IPv6 address.
    """

    try:
        ipaddress.ip_address(
            value
        )
        return True
    except ValueError:
        return False


def is_public_ip(
    value: str,
) -> bool:
    """
    Determine whether an IP is publicly routable.

    This is intentionally conservative.
    """

    try:
        ip = ipaddress.ip_address(
            value
        )

        return not any(
            [
                ip.is_private,
                ip.is_loopback,
                ip.is_reserved,
                ip.is_link_local,
                ip.is_multicast,
                ip.is_unspecified,
            ]
        )

    except ValueError:
        return False


def normalize_url(
    target_url: str,
) -> str:
    """
    Normalize URL for external reputation lookups.
    """

    value = str(
        target_url or ""
    ).strip()

    if not value:
        raise ValueError(
            "URL cannot be empty."
        )

    parsed = urlparse(value)

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        raise ValueError(
            "Only HTTP/HTTPS URLs are supported."
        )

    if not parsed.hostname:
        raise ValueError(
            "URL hostname is missing."
        )

    return value


def make_url_id(
    target_url: str,
) -> str:
    """
    VirusTotal URL object identifier.

    VT uses URL-safe base64 without padding.
    """

    encoded = base64.urlsafe_b64encode(
        target_url.encode("utf-8")
    ).decode("ascii")

    return encoded.rstrip("=")


def sha256_text(
    value: str,
) -> str:
    """
    SHA-256 helper used for cache keys.
    """

    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def parse_retry_after(
    response: requests.Response,
) -> Optional[float]:
    """
    Parse Retry-After header when available.
    """

    header = response.headers.get(
        "Retry-After"
    )

    if not header:
        return None

    try:
        return max(
            0.0,
            float(header),
        )
    except ValueError:
        pass

    try:
        retry_at = parsedate_to_datetime(
            header
        )

        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(
                tzinfo=timezone.utc
            )

        delay = (
            retry_at
            - datetime.now(timezone.utc)
        ).total_seconds()

        return max(
            0.0,
            delay,
        )

    except Exception:
        return None


# ============================================================================
# TTL CACHE
# ============================================================================

class TTLCache:
    """
    Small process-local TTL cache.

    This is intentionally simple.

    For multi-instance production deployments, replace this with Redis
    or another shared cache.
    """

    def __init__(
        self,
        ttl: int = CACHE_TTL,
        max_items: int = MAX_CACHE_ITEMS,
    ) -> None:

        self.ttl = max(
            0,
            int(ttl),
        )

        self.max_items = max(
            10,
            int(max_items),
        )

        self._items: dict[
            str,
            CacheEntry,
        ] = {}

        self._lock = asyncio.Lock()

    async def get(
        self,
        key: str,
    ) -> Any:

        async with self._lock:

            entry = self._items.get(
                key
            )

            if entry is None:
                return None

            now = time.monotonic()

            if (
                self.ttl <= 0
                or now >= entry.expires_at
            ):
                self._items.pop(
                    key,
                    None,
                )
                return None

            return entry.value

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
    ) -> None:

        effective_ttl = (
            self.ttl
            if ttl is None
            else max(
                0,
                int(ttl),
            )
        )

        if effective_ttl <= 0:
            return

        async with self._lock:

            now = time.monotonic()

            if len(self._items) >= self.max_items:
                oldest_key = min(
                    self._items,
                    key=lambda item: (
                        self._items[item].created_at
                    ),
                )

                self._items.pop(
                    oldest_key,
                    None,
                )

            self._items[key] = CacheEntry(
                value=value,
                created_at=now,
                expires_at=(
                    now + effective_ttl
                ),
            )

    async def delete(
        self,
        key: str,
    ) -> None:

        async with self._lock:
            self._items.pop(
                key,
                None,
            )

    async def clear(
        self,
    ) -> None:

        async with self._lock:
            self._items.clear()

    async def size(
        self,
    ) -> int:

        async with self._lock:
            return len(
                self._items
            )


# ============================================================================
# THREAT INTELLIGENCE SERVICE
# ============================================================================

class ThreatIntelligenceService:
    """
    Centralized threat-intelligence service.

    This class is intentionally independent from FastAPI so it can be
    tested and reused by:

        - URL scanner
        - QR scanner
        - UPI scanner
        - background workers
        - CLI tools
        - future scheduled jobs
    """

    def __init__(
        self,
        vt_api_key: Optional[str] = None,
        vt_base_url: str = VT_BASE_URL,
        rdap_base_url: str = RDAP_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        connect_timeout: float = CONNECT_TIMEOUT,
        max_retries: int = MAX_RETRIES,
        cache_ttl: int = CACHE_TTL,
        max_cache_items: int = MAX_CACHE_ITEMS,
    ) -> None:

        self.vt_api_key = (
            vt_api_key
            if vt_api_key is not None
            else VT_API_KEY
        ).strip()

        self.vt_base_url = (
            vt_base_url.rstrip("/")
        )

        self.rdap_base_url = (
            rdap_base_url.rstrip("/")
        )

        self.timeout = max(
            1.0,
            float(timeout),
        )

        self.connect_timeout = max(
            1.0,
            float(connect_timeout),
        )

        self.max_retries = max(
            0,
            int(max_retries),
        )

        self.cache = TTLCache(
            ttl=cache_ttl,
            max_items=max_cache_items,
        )

        self.session = requests.Session()

        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
            }
        )

        self._closed = False

    # ========================================================================
    # SESSION
    # ========================================================================

    def close(self) -> None:
        """
        Close underlying HTTP session.
        """

        if not self._closed:

            try:
                self.session.close()
            except Exception:
                pass

            self._closed = True

    # ========================================================================
    # HTTP REQUEST
    # ========================================================================

    def _request_sync(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, Any]] = None,
        data: Any = None,
        json_data: Any = None,
        timeout: Optional[float] = None,
    ) -> requests.Response:
        """
        Synchronous HTTP request with retry behavior.

        This function is never called directly from an async endpoint.
        Public async wrappers use asyncio.to_thread().
        """

        if self._closed:
            raise RuntimeError(
                "Threat intelligence service is closed."
            )

        effective_timeout = (
            timeout
            if timeout is not None
            else self.timeout
        )

        request_timeout = (
            min(
                self.connect_timeout,
                effective_timeout,
            ),
            effective_timeout,
        )

        last_exception: Optional[
            Exception
        ] = None

        for attempt in range(
            self.max_retries + 1
        ):

            try:

                response = self.session.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json_data,
                    timeout=request_timeout,
                )

                if response.status_code in {
                    408,
                    425,
                    429,
                    500,
                    502,
                    503,
                    504,
                } and attempt < self.max_retries:

                    retry_after = (
                        parse_retry_after(
                            response
                        )
                    )

                    if retry_after is None:
                        retry_after = min(
                            2 ** attempt,
                            5,
                        )

                    time.sleep(
                        retry_after
                    )

                    continue

                return response

            except (
                requests.Timeout,
                requests.ConnectionError,
            ) as exc:

                last_exception = exc

                if attempt >= self.max_retries:
                    raise

                delay = min(
                    2 ** attempt,
                    5,
                )

                time.sleep(
                    delay
                )

        if last_exception:
            raise last_exception

        raise RuntimeError(
            "HTTP request failed unexpectedly."
        )

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> requests.Response:

        return await asyncio.to_thread(
            self._request_sync,
            method,
            url,
            **kwargs,
        )

    # ========================================================================
    # VIRUSTOTAL CONFIGURATION
    # ========================================================================

    @property
    def virustotal_configured(
        self,
    ) -> bool:

        return bool(
            self.vt_api_key
        )

    def _vt_headers(
        self,
    ) -> dict[str, str]:

        if not self.vt_api_key:
            return {
                "Accept": "application/json",
            }

        return {
            "x-apikey": self.vt_api_key,
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }

    # ========================================================================
    # VIRUSTOTAL URL LOOKUP
    # ========================================================================

    async def check_virustotal_url(
        self,
        target_url: str,
        *,
        use_cache: bool = True,
    ) -> dict[str, Any]:
        """
        Check URL reputation in VirusTotal.

        Important:
        A URL not found in VT does NOT mean it is clean.
        """

        try:
            normalized_url = normalize_url(
                target_url
            )
        except ValueError as exc:

            result = VirusTotalResult(
                configured=self.virustotal_configured,
                status="invalid_input",
                error=str(exc),
            )

            return asdict(
                result
            )

        if not self.virustotal_configured:

            return asdict(
                VirusTotalResult(
                    configured=False,
                    scanned=False,
                    status="not_configured",
                    note=(
                        "VirusTotal API key is not configured."
                    ),
                )
            )

        cache_key = (
            "vt:url:"
            + sha256_text(
                normalized_url
            )
        )

        if use_cache:

            cached = await self.cache.get(
                cache_key
            )

            if cached is not None:
                return cached

        url_id = make_url_id(
            normalized_url
        )

        endpoint = (
            f"{self.vt_base_url}"
            f"/urls/{url_id}"
        )

        started = time.perf_counter()

        try:

            response = await self._request(
                "GET",
                endpoint,
                headers=self._vt_headers(),
            )

            latency_ms = (
                time.perf_counter()
                - started
            ) * 1000.0

            if response.status_code == 200:

                payload = response.json()

                result = (
                    self._parse_vt_url_response(
                        normalized_url,
                        url_id,
                        payload,
                    )
                )

                result["latency_ms"] = round(
                    latency_ms,
                    2,
                )

                await self.cache.set(
                    cache_key,
                    result,
                )

                return result

            if response.status_code == 404:

                result = asdict(
                    VirusTotalResult(
                        configured=True,
                        scanned=True,
                        status="not_found",
                        url=normalized_url,
                        url_id=url_id,
                        note=(
                            "URL is not currently present in "
                            "the VirusTotal URL collection."
                        ),
                    )
                )

                result["latency_ms"] = round(
                    latency_ms,
                    2,
                )

                await self.cache.set(
                    cache_key,
                    result,
                    ttl=min(
                        CACHE_TTL,
                        120,
                    ),
                )

                return result

            if response.status_code in {
                401,
                403,
            }:

                return asdict(
                    VirusTotalResult(
                        configured=True,
                        scanned=False,
                        status="authentication_error",
                        url=normalized_url,
                        url_id=url_id,
                        error=(
                            "VirusTotal API authentication "
                            "or authorization failed."
                        ),
                    )
                )

            if response.status_code == 429:

                return asdict(
                    VirusTotalResult(
                        configured=True,
                        scanned=False,
                        status="rate_limited",
                        url=normalized_url,
                        url_id=url_id,
                        note=(
                            "VirusTotal rate limit reached."
                        ),
                    )
                )

            return asdict(
                VirusTotalResult(
                    configured=True,
                    scanned=False,
                    status="provider_error",
                    url=normalized_url,
                    url_id=url_id,
                    error=(
                        f"VirusTotal returned HTTP "
                        f"{response.status_code}."
                    ),
                )
            )

        except requests.Timeout:

            return asdict(
                VirusTotalResult(
                    configured=True,
                    scanned=False,
                    status="timeout",
                    url=normalized_url,
                    url_id=url_id,
                    error=(
                        "VirusTotal request timed out."
                    ),
                )
            )

        except Exception as exc:

            logger.warning(
                "VirusTotal lookup failed: %s",
                exc,
            )

            return asdict(
                VirusTotalResult(
                    configured=True,
                    scanned=False,
                    status="error",
                    url=normalized_url,
                    url_id=url_id,
                    error=str(exc),
                )
            )

    # ========================================================================
    # VIRUSTOTAL RESPONSE PARSER
    # ========================================================================

    def _parse_vt_url_response(
        self,
        target_url: str,
        url_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:

        data = payload.get(
            "data",
            {},
        )

        attributes = data.get(
            "attributes",
            {},
        )

        stats = attributes.get(
            "last_analysis_stats",
            {},
        )

        malicious = int(
            stats.get(
                "malicious",
                0,
            )
            or 0
        )

        suspicious = int(
            stats.get(
                "suspicious",
                0,
            )
            or 0
        )

        harmless = int(
            stats.get(
                "harmless",
                0,
            )
            or 0
        )

        undetected = int(
            stats.get(
                "undetected",
                0,
            )
            or 0
        )

        timeout = int(
            stats.get(
                "timeout",
                0,
            )
            or 0
        )

        failure = int(
            stats.get(
                "failure",
                0,
            )
            or 0
        )

        type_unsupported = int(
            stats.get(
                "type-unsupported",
                0,
            )
            or 0
        )

        total = sum(
            [
                malicious,
                suspicious,
                harmless,
                undetected,
                timeout,
                failure,
                type_unsupported,
            ]
        )

        detection_ratio = (
            malicious / total
            if total > 0
            else 0.0
        )

        reputation = attributes.get(
            "reputation"
        )

        try:
            if reputation is not None:
                reputation = int(
                    reputation
                )
        except (
            TypeError,
            ValueError,
        ):
            reputation = None

        if malicious > 0:
            status = "malicious"

        elif suspicious > 0:
            status = "suspicious"

        elif total > 0:
            status = "no_malicious_detection"

        else:
            status = "no_analysis"

        return asdict(
            VirusTotalResult(
                configured=True,
                scanned=True,
                status=status,
                url=target_url,
                url_id=url_id,
                malicious=malicious,
                suspicious=suspicious,
                harmless=harmless,
                undetected=undetected,
                timeout=timeout,
                failure=failure,
                type_unsupported=type_unsupported,
                total_engines=total,
                detection_ratio=round(
                    detection_ratio,
                    4,
                ),
                reputation=reputation,
                source="VirusTotal",
            )
        )

    # ========================================================================
    # VIRUSTOTAL URL SUBMISSION
    # ========================================================================

    async def submit_url_to_virustotal(
        self,
        target_url: str,
    ) -> dict[str, Any]:
        """
        Submit a URL for VirusTotal analysis.

        Submission may consume API quota.

        This method intentionally does not automatically submit every URL.
        """

        try:
            normalized_url = normalize_url(
                target_url
            )
        except ValueError as exc:

            return {
                "provider": "virustotal",
                "submitted": False,
                "status": "invalid_input",
                "error": str(exc),
            }

        if not self.virustotal_configured:

            return {
                "provider": "virustotal",
                "submitted": False,
                "status": "not_configured",
                "error": (
                    "VirusTotal API key is not configured."
                ),
            }

        endpoint = (
            f"{self.vt_base_url}/urls"
        )

        try:

            response = await self._request(
                "POST",
                endpoint,
                headers={
                    **self._vt_headers(),
                    "Content-Type": (
                        "application/x-www-form-urlencoded"
                    ),
                },
                data={
                    "url": normalized_url,
                },
            )

            if response.status_code in {
                200,
                201,
            }:

                payload = response.json()

                data = payload.get(
                    "data",
                    {},
                )

                return {
                    "provider": "virustotal",
                    "submitted": True,
                    "status": "submitted",
                    "analysis_id": data.get(
                        "id"
                    ),
                    "type": data.get(
                        "type"
                    ),
                }

            if response.status_code == 429:

                return {
                    "provider": "virustotal",
                    "submitted": False,
                    "status": "rate_limited",
                    "error": (
                        "VirusTotal rate limit reached."
                    ),
                }

            if response.status_code in {
                401,
                403,
            }:

                return {
                    "provider": "virustotal",
                    "submitted": False,
                    "status": "authentication_error",
                    "error": (
                        "VirusTotal authorization failed."
                    ),
                }

            return {
                "provider": "virustotal",
                "submitted": False,
                "status": "provider_error",
                "http_status": response.status_code,
                "error": (
                    "VirusTotal URL submission failed."
                ),
            }

        except requests.Timeout:

            return {
                "provider": "virustotal",
                "submitted": False,
                "status": "timeout",
                "error": (
                    "VirusTotal submission timed out."
                ),
            }

        except Exception as exc:

            logger.warning(
                "VirusTotal URL submission failed: %s",
                exc,
            )

            return {
                "provider": "virustotal",
                "submitted": False,
                "status": "error",
                "error": str(exc),
            }

    # ========================================================================
    # VIRUSTOTAL ANALYSIS POLLING
    # ========================================================================

    async def get_virustotal_analysis(
        self,
        analysis_id: str,
    ) -> dict[str, Any]:
        """
        Fetch VirusTotal analysis status.
        """

        if not self.virustotal_configured:

            return {
                "provider": "virustotal",
                "status": "not_configured",
            }

        analysis_id = str(
            analysis_id or ""
        ).strip()

        if not analysis_id:

            return {
                "provider": "virustotal",
                "status": "invalid_input",
            }

        endpoint = (
            f"{self.vt_base_url}"
            f"/analyses/{analysis_id}"
        )

        try:

            response = await self._request(
                "GET",
                endpoint,
                headers=self._vt_headers(),
            )

            if response.status_code == 200:

                payload = response.json()

                data = payload.get(
                    "data",
                    {},
                )

                attributes = data.get(
                    "attributes",
                    {},
                )

                return {
                    "provider": "virustotal",
                    "status": "success",
                    "analysis_id": analysis_id,
                    "analysis_status": attributes.get(
                        "status"
                    ),
                    "stats": attributes.get(
                        "stats",
                        {},
                    ),
                }

            if response.status_code == 404:

                return {
                    "provider": "virustotal",
                    "status": "not_found",
                    "analysis_id": analysis_id,
                }

            return {
                "provider": "virustotal",
                "status": "provider_error",
                "analysis_id": analysis_id,
                "http_status": response.status_code,
            }

        except requests.Timeout:

            return {
                "provider": "virustotal",
                "status": "timeout",
                "analysis_id": analysis_id,
            }

        except Exception as exc:

            return {
                "provider": "virustotal",
                "status": "error",
                "analysis_id": analysis_id,
                "error": str(exc),
            }

    async def submit_and_poll_virustotal(
        self,
        target_url: str,
    ) -> dict[str, Any]:
        """
        Submit URL to VirusTotal and poll the resulting analysis.

        This should be used deliberately because submission may consume
        provider quota.
        """

        submission = (
            await self.submit_url_to_virustotal(
                target_url
            )
        )

        if not submission.get(
            "submitted"
        ):
            return submission

        analysis_id = submission.get(
            "analysis_id"
        )

        if not analysis_id:
            return {
                **submission,
                "status": "submitted_without_analysis_id",
            }

        latest: dict[str, Any] = {}

        for _ in range(
            VT_MAX_POLLS
        ):

            latest = (
                await self.get_virustotal_analysis(
                    analysis_id
                )
            )

            if latest.get(
                "analysis_status"
            ) == "completed":
                break

            await asyncio.sleep(
                VT_POLL_INTERVAL
            )

        return {
            **submission,
            "analysis": latest,
        }

    # ========================================================================
    # RDAP
    # ========================================================================

    async def get_rdap_domain(
        self,
        domain: str,
        *,
        use_cache: bool = True,
    ) -> dict[str, Any]:
        """
        Query RDAP domain information.
        """

        normalized_domain = extract_hostname(
            domain
        )

        if not normalized_domain:

            return asdict(
                RDAPResult(
                    queried=False,
                    status="invalid_domain",
                    error=(
                        "Could not determine domain."
                    ),
                )
            )

        if is_ip_address(
            normalized_domain
        ):

            return asdict(
                RDAPResult(
                    queried=False,
                    status="ip_address",
                    domain=normalized_domain,
                    note=(
                        "RDAP domain lookup skipped because "
                        "target is an IP address."
                    )
                    if hasattr(
                        RDAPResult,
                        "note",
                    )
                    else None,
                )
            )

        cache_key = (
            "rdap:domain:"
            + normalized_domain
        )

        if use_cache:

            cached = await self.cache.get(
                cache_key
            )

            if cached is not None:
                return cached

        endpoint = (
            f"{self.rdap_base_url}"
            f"/domain/{normalized_domain}"
        )

        try:

            response = await self._request(
                "GET",
                endpoint,
                headers={
                    "Accept": (
                        "application/rdap+json,"
                        "application/json"
                    ),
                },
            )

            if response.status_code == 200:

                payload = response.json()

                result = (
                    self._parse_rdap_response(
                        normalized_domain,
                        payload,
                    )
                )

                await self.cache.set(
                    cache_key,
                    result,
                )

                return result

            if response.status_code == 404:

                result = asdict(
                    RDAPResult(
                        queried=True,
                        status="not_found",
                        domain=normalized_domain,
                        error=(
                            "Domain was not found in RDAP."
                        ),
                    )
                )

                await self.cache.set(
                    cache_key,
                    result,
                    ttl=min(
                        CACHE_TTL,
                        120,
                    ),
                )

                return result

            if response.status_code == 429:

                return asdict(
                    RDAPResult(
                        queried=False,
                        status="rate_limited",
                        domain=normalized_domain,
                    )
                )

            return asdict(
                RDAPResult(
                    queried=False,
                    status="provider_error",
                    domain=normalized_domain,
                    error=(
                        f"RDAP returned HTTP "
                        f"{response.status_code}."
                    ),
                )
            )

        except requests.Timeout:

            return asdict(
                RDAPResult(
                    queried=False,
                    status="timeout",
                    domain=normalized_domain,
                    error=(
                        "RDAP request timed out."
                    ),
                )
            )

        except Exception as exc:

            logger.warning(
                "RDAP lookup failed: %s",
                exc,
            )

            return asdict(
                RDAPResult(
                    queried=False,
                    status="error",
                    domain=normalized_domain,
                    error=str(exc),
                )
            )

    # ========================================================================
    # RDAP PARSER
    # ========================================================================

    def _parse_rdap_response(
        self,
        domain: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:

        events = payload.get(
            "events",
            [],
        )

        registration_date = None
        expiration_date = None
        last_changed_date = None

        for event in events:

            action = str(
                event.get(
                    "eventAction",
                    "",
                )
            ).lower()

            date_value = event.get(
                "eventDate"
            )

            if action == "registration":
                registration_date = date_value

            elif action in {
                "expiration",
                "expiration date",
            }:
                expiration_date = date_value

            elif action in {
                "last changed",
                "last changed date",
                "last update of rdap database",
            }:
                last_changed_date = date_value

        age_days = self._calculate_domain_age(
            registration_date
        )

        registrar_name = None
        registrar_handle = None

        entities: list[
            dict[str, Any]
        ] = []

        for entity in payload.get(
            "entities",
            [],
        ):

            roles = entity.get(
                "roles",
                [],
            )

            vcard = entity.get(
                "vcardArray",
                [],
            )

            entity_info = {
                "handle": entity.get(
                    "handle"
                ),
                "roles": roles,
            }

            entities.append(
                entity_info
            )

            if "registrar" in roles:

                registrar_handle = entity.get(
                    "handle"
                )

                registrar_name = (
                    self._extract_vcard_name(
                        vcard
                    )
                )

        nameservers: list[str] = []

        for nameserver in payload.get(
            "nameservers",
            [],
        ):

            name = (
                nameserver.get(
                    "ldhName"
                )
                or nameserver.get(
                    "unicodeName"
                )
            )

            if name:
                nameservers.append(
                    normalize_hostname(
                        name
                    )
                )

        status_values = [
            str(item)
            for item in payload.get(
                "status",
                [],
            )
            if item
        ]

        dnssec = payload.get(
            "secureDNS",
            {},
        ).get(
            "delegationSigned"
        )

        result = RDAPResult(
            queried=True,
            status="success",
            domain=domain,
            handle=payload.get(
                "handle"
            ),
            ldh_name=payload.get(
                "ldhName"
            ),
            unicode_name=payload.get(
                "unicodeName"
            ),
            registrar_name=registrar_name,
            registrar_handle=registrar_handle,
            registration_date=registration_date,
            expiration_date=expiration_date,
            last_changed_date=last_changed_date,
            age_days=age_days,
            nameservers=nameservers,
            domain_status=status_values,
            dnssec=dnssec,
            entities=entities,
            source="RDAP",
        )

        return asdict(
            result
        )

    @staticmethod
    def _extract_vcard_name(
        vcard: Any,
    ) -> Optional[str]:

        if not isinstance(
            vcard,
            list,
        ):
            return None

        if len(vcard) < 2:
            return None

        properties = vcard[1]

        if not isinstance(
            properties,
            list,
        ):
            return None

        for property_item in properties:

            if not isinstance(
                property_item,
                list,
            ):
                continue

            if len(property_item) < 4:
                continue

            property_name = str(
                property_item[0]
            ).lower()

            if property_name in {
                "fn",
                "org",
            }:

                value = property_item[3]

                if isinstance(
                    value,
                    str,
                ):
                    return value.strip()

                if isinstance(
                    value,
                    list,
                ):
                    return " ".join(
                        str(item)
                        for item in value
                        if item
                    ).strip()

        return None

    @staticmethod
    def _calculate_domain_age(
        registration_date: Optional[str],
    ) -> Optional[int]:

        if not registration_date:
            return None

        try:

            normalized = (
                registration_date
                .replace(
                    "Z",
                    "+00:00",
                )
            )

            registered = (
                datetime.fromisoformat(
                    normalized
                )
            )

            if registered.tzinfo is None:
                registered = registered.replace(
                    tzinfo=timezone.utc
                )

            age = (
                datetime.now(
                    timezone.utc
                )
                - registered
            ).days

            return max(
                0,
                age,
            )

        except Exception:

            return None

    # ========================================================================
    # DNS INTELLIGENCE
    # ========================================================================

    async def resolve_hostname(
        self,
        hostname: str,
        *,
        use_cache: bool = True,
    ) -> dict[str, Any]:

        normalized = normalize_hostname(
            hostname
        )

        if not normalized:

            return asdict(
                DNSResult(
                    hostname="",
                    status="invalid_hostname",
                    error=(
                        "Hostname is empty."
                    ),
                )
            )

        cache_key = (
            "dns:"
            + normalized
        )

        if use_cache:

            cached = await self.cache.get(
                cache_key
            )

            if cached is not None:
                return cached

        try:

            addresses = await asyncio.to_thread(
                self._resolve_hostname_sync,
                normalized,
            )

            public_addresses = []
            private_addresses = []
            reserved_addresses = []
            loopback_addresses = []
            link_local_addresses = []
            multicast_addresses = []
            unspecified_addresses = []

            for address in addresses:

                try:
                    ip = ipaddress.ip_address(
                        address
                    )

                    if ip.is_private:
                        private_addresses.append(
                            address
                        )

                    elif ip.is_loopback:
                        loopback_addresses.append(
                            address
                        )

                    elif ip.is_reserved:
                        reserved_addresses.append(
                            address
                        )

                    elif ip.is_link_local:
                        link_local_addresses.append(
                            address
                        )

                    elif ip.is_multicast:
                        multicast_addresses.append(
                            address
                        )

                    elif ip.is_unspecified:
                        unspecified_addresses.append(
                            address
                        )

                    elif is_public_ip(
                        address
                    ):
                        public_addresses.append(
                            address
                        )

                except ValueError:
                    continue

            result = asdict(
                DNSResult(
                    hostname=normalized,
                    resolved=bool(
                        addresses
                    ),
                    addresses=addresses,
                    public_addresses=public_addresses,
                    private_addresses=private_addresses,
                    reserved_addresses=reserved_addresses,
                    loopback_addresses=loopback_addresses,
                    link_local_addresses=link_local_addresses,
                    multicast_addresses=multicast_addresses,
                    unspecified_addresses=unspecified_addresses,
                    status=(
                        "resolved"
                        if addresses
                        else "no_records"
                    ),
                )
            )

            await self.cache.set(
                cache_key,
                result,
            )

            return result

        except Exception as exc:

            result = asdict(
                DNSResult(
                    hostname=normalized,
                    status="error",
                    error=str(exc),
                )
            )

            return result

    @staticmethod
    def _resolve_hostname_sync(
        hostname: str,
    ) -> list[str]:

        addresses: set[str] = set()

        try:

            results = socket.getaddrinfo(
                hostname,
                None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            )

            for result in results:

                sockaddr = result[4]

                if not sockaddr:
                    continue

                address = sockaddr[0]

                try:
                    ipaddress.ip_address(
                        address
                    )

                    addresses.add(
                        address
                    )

                except ValueError:
                    continue

        except (
            socket.gaierror,
            OSError,
        ):

            return []

        return sorted(
            addresses
        )

    # ========================================================================
    # DOMAIN AGE SIGNAL
    # ========================================================================

    @staticmethod
    def domain_age_signal(
        age_days: Optional[int],
    ) -> float:
        """
        Convert domain age into novelty score.

        IMPORTANT:
        This is a heuristic signal, not a maliciousness verdict.
        """

        if age_days is None:
            return 0.10

        if age_days < 7:
            return 1.00

        if age_days < 30:
            return 0.90

        if age_days < 90:
            return 0.60

        if age_days < 180:
            return 0.45

        if age_days < 365:
            return 0.30

        return 0.10

    # ========================================================================
    # UNIFIED INTELLIGENCE
    # ========================================================================

    async def analyze_url(
        self,
        target_url: str,
        *,
        check_virustotal: bool = True,
        check_rdap: bool = True,
        check_dns: bool = True,
        submit_to_virustotal: bool = False,
    ) -> dict[str, Any]:
        """
        Perform all available threat-intelligence checks for a URL.

        By default:
            - VT lookup is enabled
            - RDAP is enabled
            - DNS is enabled
            - VT submission is disabled

        VT submission is deliberately opt-in because it can consume
        external API quota.
        """

        normalized_url = normalize_url(
            target_url
        )

        hostname = extract_hostname(
            normalized_url
        )

        timestamp = utc_now_iso()

        provider_results: dict[
            str,
            Any
        ] = {}

        indicators: list[str] = []
        warnings: list[str] = []
        errors: list[str] = []

        provenance: list[str] = []

        external_ioc_hits = 0
        malicious_detected = False
        suspicious_detected = False

        tasks = []

        if check_virustotal:
            tasks.append(
                (
                    "virustotal",
                    self.check_virustotal_url(
                        normalized_url
                    ),
                )
            )

        if check_rdap and hostname:

            tasks.append(
                (
                    "rdap",
                    self.get_rdap_domain(
                        hostname
                    ),
                )
            )

        if check_dns and hostname:

            tasks.append(
                (
                    "dns",
                    self.resolve_hostname(
                        hostname
                    ),
                )
            )

        if tasks:

            results = await asyncio.gather(
                *[
                    task
                    for _, task in tasks
                ],
                return_exceptions=True,
            )

            for (
                provider_name,
                result,
            ) in zip(
                [
                    name
                    for name, _ in tasks
                ],
                results,
            ):

                if isinstance(
                    result,
                    Exception,
                ):

                    provider_results[
                        provider_name
                    ] = {
                        "status": "error",
                        "error": str(
                            result
                        ),
                    }

                    errors.append(
                        f"{provider_name}: {result}"
                    )

                    continue

                provider_results[
                    provider_name
                ] = result

        # --------------------------------------------------------------------
        # VirusTotal interpretation
        # --------------------------------------------------------------------

        vt = provider_results.get(
            "virustotal"
        )

        if isinstance(
            vt,
            dict,
        ):

            vt_status = vt.get(
                "status"
            )

            if vt_status == "malicious":

                malicious_detected = True

                malicious_count = int(
                    vt.get(
                        "malicious",
                        0,
                    )
                    or 0
                )

                external_ioc_hits += 1

                indicators.append(
                    "VirusTotal reported malicious detections."
                )

                indicators.append(
                    f"VirusTotal malicious engines: "
                    f"{malicious_count}."
                )

                provenance.append(
                    "VirusTotal"
                )

            elif vt_status == "suspicious":

                suspicious_detected = True

                external_ioc_hits += 1

                indicators.append(
                    "VirusTotal reported suspicious detections."
                )

                provenance.append(
                    "VirusTotal"
                )

            elif vt_status == "no_malicious_detection":

                provenance.append(
                    "VirusTotal"
                )

                warnings.append(
                    "VirusTotal currently reports no malicious "
                    "detections among available engines."
                )

            elif vt_status == "not_found":

                warnings.append(
                    "VirusTotal has no current URL record for this target."
                )

            elif vt_status in {
                "not_configured",
                "authentication_error",
                "rate_limited",
                "timeout",
                "provider_error",
                "error",
            }:

                warnings.append(
                    f"VirusTotal status: {vt_status}."
                )

        # --------------------------------------------------------------------
        # RDAP interpretation
        # --------------------------------------------------------------------

        rdap = provider_results.get(
            "rdap"
        )

        if isinstance(
            rdap,
            dict,
        ):

            rdap_status = rdap.get(
                "status"
            )

            if rdap_status == "success":

                provenance.append(
                    "RDAP"
                )

                age_days = rdap.get(
                    "age_days"
                )

                if (
                    isinstance(
                        age_days,
                        int,
                    )
                    and age_days < 30
                ):

                    indicators.append(
                        f"Domain registration age is approximately "
                        f"{age_days} day(s)."
                    )

                elif (
                    isinstance(
                        age_days,
                        int,
                    )
                    and age_days < 90
                ):

                    warnings.append(
                        f"Domain is relatively new "
                        f"({age_days} day(s))."
                    )

            elif rdap_status in {
                "timeout",
                "rate_limited",
                "provider_error",
                "error",
            }:

                warnings.append(
                    f"RDAP status: {rdap_status}."
                )

        # --------------------------------------------------------------------
        # DNS interpretation
        # --------------------------------------------------------------------

        dns = provider_results.get(
            "dns"
        )

        if isinstance(
            dns,
            dict,
        ):

            if dns.get(
                "resolved"
            ):

                provenance.append(
                    "DNS"
                )

                private_addresses = dns.get(
                    "private_addresses",
                    [],
                )

                loopback_addresses = dns.get(
                    "loopback_addresses",
                    [],
                )

                if private_addresses:

                    indicators.append(
                        "Hostname resolves to a private-network address."
                    )

                if loopback_addresses:

                    indicators.append(
                        "Hostname resolves to a loopback address."
                    )

            else:

                warnings.append(
                    "Hostname did not produce a normal DNS resolution."
                )

        # --------------------------------------------------------------------
        # Optional VT submission
        # --------------------------------------------------------------------

        if submit_to_virustotal:

            submission = (
                await self.submit_and_poll_virustotal(
                    normalized_url
                )
            )

            provider_results[
                "virustotal_submission"
            ] = submission

            if submission.get(
                "submitted"
            ):

                provenance.append(
                    "VirusTotal submission"
                )

        # --------------------------------------------------------------------
        # Intelligence score
        # --------------------------------------------------------------------

        intelligence_score = 0.0

        if malicious_detected:
            intelligence_score = max(
                intelligence_score,
                0.90,
            )

        elif suspicious_detected:
            intelligence_score = max(
                intelligence_score,
                0.65,
            )

        if (
            isinstance(
                rdap,
                dict,
            )
            and rdap.get(
                "status"
            ) == "success"
        ):

            age_days = rdap.get(
                "age_days"
            )

            intelligence_score = max(
                intelligence_score,
                self.domain_age_signal(
                    age_days
                ) * 0.35,
            )

        intelligence_score = clamp(
            intelligence_score
        )

        # --------------------------------------------------------------------
        # Confidence
        # --------------------------------------------------------------------

        available_sources = 0
        successful_sources = 0

        for provider_name in [
            "virustotal",
            "rdap",
            "dns",
        ]:

            provider = provider_results.get(
                provider_name
            )

            if provider is None:
                continue

            available_sources += 1

            if provider.get(
                "status"
            ) in {
                "malicious",
                "suspicious",
                "no_malicious_detection",
                "success",
                "resolved",
            }:

                successful_sources += 1

        if available_sources:

            confidence = clamp(
                successful_sources
                / available_sources
            )

        else:

            confidence = 0.0

        # Increase confidence when independent malicious evidence exists.
        if malicious_detected:
            confidence = max(
                confidence,
                0.80,
            )

        result = ThreatIntelligenceResult(
            target=normalized_url,
            target_type="url",
            timestamp=timestamp,
            providers=provider_results,
            indicators=indicators,
            warnings=warnings,
            errors=errors,
            external_ioc_hits=min(
                external_ioc_hits,
                3,
            ),
            malicious_detected=malicious_detected,
            suspicious_detected=suspicious_detected,
            intelligence_score=round(
                intelligence_score,
                4,
            ),
            confidence=round(
                confidence,
                4,
            ),
            provenance=list(
                dict.fromkeys(
                    provenance
                )
            ),
            status=(
                "completed_with_errors"
                if errors
                else "completed"
            ),
        )

        return asdict(
            result
        )

    # ========================================================================
    # DOMAIN-ONLY ANALYSIS
    # ========================================================================

    async def analyze_domain(
        self,
        domain: str,
        *,
        check_rdap: bool = True,
        check_dns: bool = True,
    ) -> dict[str, Any]:

        hostname = extract_hostname(
            domain
        )

        if not hostname:

            return {
                "status": "invalid_input",
                "domain": domain,
                "indicators": [],
                "warnings": [
                    "Could not determine hostname."
                ],
                "errors": [],
            }

        providers: dict[
            str,
            Any
        ] = {}

        tasks = []

        if check_rdap:
            tasks.append(
                (
                    "rdap",
                    self.get_rdap_domain(
                        hostname
                    ),
                )
            )

        if check_dns:
            tasks.append(
                (
                    "dns",
                    self.resolve_hostname(
                        hostname
                    ),
                )
            )

        if tasks:

            results = await asyncio.gather(
                *[
                    task
                    for _, task in tasks
                ],
                return_exceptions=True,
            )

            for (
                name,
                result,
            ) in zip(
                [
                    name
                    for name, _ in tasks
                ],
                results,
            ):

                if isinstance(
                    result,
                    Exception,
                ):

                    providers[name] = {
                        "status": "error",
                        "error": str(
                            result
                        ),
                    }

                else:

                    providers[name] = result

        indicators: list[str] = []
        warnings: list[str] = []

        rdap = providers.get(
            "rdap"
        )

        if (
            isinstance(
                rdap,
                dict,
            )
            and rdap.get(
                "age_days"
            ) is not None
        ):

            age_days = rdap[
                "age_days"
            ]

            if age_days < 30:

                indicators.append(
                    f"Very new domain: {age_days} day(s) old."
                )

            elif age_days < 90:

                warnings.append(
                    f"Relatively new domain: {age_days} day(s) old."
                )

        dns = providers.get(
            "dns"
        )

        if isinstance(
            dns,
            dict,
        ):

            if dns.get(
                "private_addresses"
            ):

                indicators.append(
                    "Private IP resolution detected."
                )

        return {
            "status": "completed",
            "domain": hostname,
            "providers": providers,
            "indicators": indicators,
            "warnings": warnings,
            "errors": [],
            "provenance": [
                name
                for name in providers
            ],
        }

    # ========================================================================
    # PROVIDER HEALTH
    # ========================================================================

    async def provider_health(
        self,
    ) -> dict[str, Any]:
        """
        Check configuration and basic reachability of providers.

        This does not consume a VirusTotal scan.
        """

        results: dict[
            str,
            Any
        ] = {}

        # --------------------------------------------------------------------
        # VirusTotal
        # --------------------------------------------------------------------

        if not self.virustotal_configured:

            results[
                "virustotal"
            ] = asdict(
                ProviderStatus(
                    provider="virustotal",
                    configured=False,
                    available=False,
                    checked=False,
                    status="not_configured",
                    message=(
                        "VirusTotal API key is not configured."
                    ),
                )
            )

        else:

            started = time.perf_counter()

            try:

                response = await self._request(
                    "GET",
                    f"{self.vt_base_url}/users/self",
                    headers=self._vt_headers(),
                )

                latency = (
                    time.perf_counter()
                    - started
                ) * 1000.0

                if response.status_code == 200:

                    status = ProviderStatus(
                        provider="virustotal",
                        configured=True,
                        available=True,
                        checked=True,
                        status="healthy",
                        message=(
                            "VirusTotal API authentication "
                            "is working."
                        ),
                        latency_ms=round(
                            latency,
                            2,
                        ),
                        http_status=response.status_code,
                    )

                elif response.status_code == 429:

                    status = ProviderStatus(
                        provider="virustotal",
                        configured=True,
                        available=False,
                        checked=True,
                        status="rate_limited",
                        message=(
                            "VirusTotal rate limit reached."
                        ),
                        latency_ms=round(
                            latency,
                            2,
                        ),
                        http_status=response.status_code,
                        rate_limited=True,
                    )

                else:

                    status = ProviderStatus(
                        provider="virustotal",
                        configured=True,
                        available=False,
                        checked=True,
                        status="provider_error",
                        message=(
                            "VirusTotal health check failed."
                        ),
                        latency_ms=round(
                            latency,
                            2,
                        ),
                        http_status=response.status_code,
                    )

                results[
                    "virustotal"
                ] = asdict(
                    status
                )

            except Exception as exc:

                results[
                    "virustotal"
                ] = asdict(
                    ProviderStatus(
                        provider="virustotal",
                        configured=True,
                        available=False,
                        checked=True,
                        status="error",
                        error=str(exc),
                    )
                )

        # --------------------------------------------------------------------
        # RDAP
        # --------------------------------------------------------------------

        started = time.perf_counter()

        try:

            response = await self._request(
                "GET",
                f"{self.rdap_base_url}/domain/example.com",
                headers={
                    "Accept": (
                        "application/rdap+json,"
                        "application/json"
                    ),
                },
            )

            latency = (
                time.perf_counter()
                - started
            ) * 1000.0

            results[
                "rdap"
            ] = asdict(
                ProviderStatus(
                    provider="rdap",
                    configured=True,
                    available=response.status_code
                    in {
                        200,
                        404,
                    },
                    checked=True,
                    status=(
                        "healthy"
                        if response.status_code
                        in {
                            200,
                            404,
                        }
                        else "provider_error"
                    ),
                    latency_ms=round(
                        latency,
                        2,
                    ),
                    http_status=response.status_code,
                )
            )

        except Exception as exc:

            results[
                "rdap"
            ] = asdict(
                ProviderStatus(
                    provider="rdap",
                    configured=True,
                    available=False,
                    checked=True,
                    status="error",
                    error=str(exc),
                )
            )

        return {
            "status": "completed",
            "timestamp": utc_now_iso(),
            "providers": results,
        }

    # ========================================================================
    # CACHE MANAGEMENT
    # ========================================================================

    async def clear_cache(
        self,
    ) -> None:
        await self.cache.clear()

    async def cache_size(
        self,
    ) -> int:
        return await self.cache.size()


# ============================================================================
# SINGLETON SERVICE
# ============================================================================

_default_service: Optional[
    ThreatIntelligenceService
] = None


def get_threat_intelligence_service() -> (
    ThreatIntelligenceService
):
    """
    Return the process-wide intelligence service.

    This is convenient for FastAPI applications.
    """

    global _default_service

    if _default_service is None:
        _default_service = (
            ThreatIntelligenceService()
        )

    return _default_service


# ============================================================================
# BACKWARD-COMPATIBLE VIRUSTOTAL HELPER
# ============================================================================

async def check_virustotal_url(
    target_url: str,
) -> dict[str, Any]:
    """
    Compatibility helper for existing CyberGuard X code.

    Existing code can continue doing:

        from threat_intelligence import check_virustotal_url

    while the actual implementation lives inside the service.
    """

    service = (
        get_threat_intelligence_service()
    )

    return await service.check_virustotal_url(
        target_url
    )


# ============================================================================
# DOMAIN AGE COMPATIBILITY HELPER
# ============================================================================

async def get_domain_registration_age(
    domain: str,
) -> tuple[
    Optional[int],
    Optional[str],
    str,
]:
    """
    Compatibility helper matching the previous backend interface.

    Returns:

        age_days
        registration_date
        source/status
    """

    service = (
        get_threat_intelligence_service()
    )

    result = await service.get_rdap_domain(
        domain
    )

    return (
        result.get(
            "age_days"
        ),
        result.get(
            "registration_date"
        ),
        (
            "rdap.org"
            if result.get(
                "status"
            ) == "success"
            else result.get(
                "status",
                "unavailable",
            )
        ),
    )


# ============================================================================
# LOCAL SELF TEST
# ============================================================================

async def _self_test() -> None:
    """
    Local sanity test.

    This test does not submit URLs to VirusTotal.
    """

    service = (
        ThreatIntelligenceService()
    )

    try:

        print(
            "\nCYBERGUARD X Threat Intelligence Test"
        )

        print(
            "====================================="
        )

        print(
            f"VirusTotal configured: "
            f"{service.virustotal_configured}"
        )

        print(
            "\nChecking RDAP..."
        )

        rdap = await service.get_rdap_domain(
            "example.com"
        )

        print(
            f"RDAP status: "
            f"{rdap.get('status')}"
        )

        print(
            f"Domain age: "
            f"{rdap.get('age_days')}"
        )

        print(
            "\nChecking DNS..."
        )

        dns = await service.resolve_hostname(
            "example.com"
        )

        print(
            f"DNS status: "
            f"{dns.get('status')}"
        )

        print(
            f"Addresses: "
            f"{dns.get('addresses')}"
        )

        print(
            "\nChecking VirusTotal configuration..."
        )

        vt = await service.check_virustotal_url(
            "https://example.com"
        )

        print(
            f"VirusTotal status: "
            f"{vt.get('status')}"
        )

        print(
            "\nProvider health..."
        )

        health = await service.provider_health()

        for (
            provider,
            provider_status,
        ) in health.get(
            "providers",
            {},
        ).items():

            print(
                f"{provider}: "
                f"{provider_status.get('status')}"
            )

    finally:

        service.close()


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    asyncio.run(
        _self_test()
    )
