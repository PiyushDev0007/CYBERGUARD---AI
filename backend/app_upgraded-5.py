"""
============================================================
CYBERGUARD X — Advanced Threat Detection Backend
============================================================

FastAPI backend for:

- URL threat analysis
- SMS / email / text analysis
- QR / quishing analysis
- Redirect-chain analysis
- Domain intelligence
- RDAP registration age
- Typosquatting detection
- URL obfuscation detection
- UPI scam indicators
- HTTP security-header analysis
- Explainable AI / XAI
- SSRF protection
- Scan IDs
- Health / readiness endpoints
- Basic service metrics

Compatible with the existing CyberGuard X frontend.

Expected project structure:

project/
│
├── ai/
│   └── risk_engine.py
│
└── backend/
    └── app_upgraded-5.py

============================================================
"""

from __future__ import annotations

# ============================================================
# STANDARD LIBRARY
# ============================================================

import asyncio
import ipaddress
import os
import re
import shutil
import socket
import sys
import time
import uuid

from collections import defaultdict, deque
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


# ============================================================
# THIRD-PARTY
# ============================================================

import cv2
import requests

from fastapi import (
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
)

from fastapi.middleware.cors import CORSMiddleware

from pydantic import (
    BaseModel,
    Field,
    field_validator,
)

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    async_playwright,
)


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# RISK ENGINE
# ============================================================

try:
    from ai.risk_engine import CyberGuardRiskEngine, ThreatSignals
except ImportError as exc:
    raise RuntimeError(
        "Could not import ai.risk_engine. "
        "Make sure ai/risk_engine.py exists and exposes "
        "CyberGuardRiskEngine and ThreatSignals."
    ) from exc


# ============================================================
# APPLICATION
# ============================================================

APP_VERSION = "3.0.0"

app = FastAPI(
    title="CYBERGUARD X — Advanced Threat Detection Platform",
    description=(
        "CyberGuard X defensive threat-analysis backend for "
        "URLs, messages, QR codes, redirect chains and "
        "multi-signal phishing indicators."
    ),
    version=APP_VERSION,
)


risk_engine = CyberGuardRiskEngine()


# ============================================================
# CONFIGURATION
# ============================================================

BACKEND_NAME = "cyberguard-x-backend"

MAX_URL_LENGTH = 4096
MAX_TEXT_LENGTH = 50000

MAX_REDIRECT_HOPS = 10
MAX_PAGE_REQUESTS = 80

REQUEST_TIMEOUT_SECONDS = 12

MAX_QR_FILE_SIZE = 5 * 1024 * 1024

RDAP_TIMEOUT_SECONDS = 8

# Production should preferably use explicit frontend origins.
#
# Example:
# CYBERGUARD_ALLOWED_ORIGINS=
# https://your-frontend.com,https://www.your-frontend.com
#
# "*" is retained as a development fallback.
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CYBERGUARD_ALLOWED_ORIGINS",
        "*",
    ).split(",")
    if origin.strip()
]


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ============================================================
# MONITORED BRANDS
# ============================================================

MONITORED_BRANDS = [
    "sbi",
    "hdfc",
    "icici",
    "axis",
    "kotak",
    "paytm",
    "phonepe",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "netflix",
    "incometax",
    "paypal",
    "instagram",
    "facebook",
    "whatsapp",
    "telegram",
    "flipkart",
]


# ============================================================
# SUSPICIOUS / HIGH-RISK URL SIGNALS
# ============================================================

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".su",
    ".click",
    ".work",
    ".zip",
    ".mov",
    ".gq",
    ".tk",
    ".ml",
    ".cf",
}


URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
}


URGENCY_KEYWORDS = [
    "urgent",
    "immediately",
    "verify now",
    "act now",
    "account blocked",
    "account suspended",
    "suspended",
    "blocked",
    "verify",
    "kyc",
    "kyc update",
    "otp",
    "refund",
    "winner",
    "lottery",
    "prize",
    "claim now",
    "limited time",
    "last warning",
    "security alert",
    "unusual activity",
    "unauthorized",
    "confirm identity",
    "click immediately",
]


UPI_HANDLES = [
    "@ybl",
    "@okaxis",
    "@oksbi",
    "@okhdfcbank",
    "@paytm",
    "@ibl",
    "@axl",
]


SUSPICIOUS_PATH_WORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "password",
    "wallet",
    "payment",
    "refund",
    "kyc",
    "otp",
]


# ============================================================
# SIMPLE IN-MEMORY METRICS
# ============================================================

METRICS = {
    "total_scans": 0,
    "url_scans": 0,
    "text_scans": 0,
    "qr_scans": 0,
    "successful_scans": 0,
    "failed_scans": 0,
    "fallback_errors": 0,
}


def increment_metric(name: str) -> None:
    if name in METRICS:
        METRICS[name] += 1


# ============================================================
# SIMPLE RATE LIMITER
# ============================================================

RATE_LIMIT_REQUESTS = int(
    os.getenv("CYBERGUARD_RATE_LIMIT", "30")
)

RATE_LIMIT_WINDOW = int(
    os.getenv("CYBERGUARD_RATE_WINDOW", "60")
)

_request_history: dict[str, deque[float]] = defaultdict(
    deque
)


def get_client_identifier(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")

    if forwarded:
        return forwarded.split(",")[0].strip()

    if request.client:
        return request.client.host

    return "unknown"


def check_rate_limit(request: Request) -> None:
    client = get_client_identifier(request)

    now = time.monotonic()

    history = _request_history[client]

    while history and (
        now - history[0] > RATE_LIMIT_WINDOW
    ):
        history.popleft()

    if len(history) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=(
                "Rate limit exceeded. "
                "Please wait before submitting another scan."
            ),
        )

    history.append(now)


# ============================================================
# REQUEST MODELS
# ============================================================

class URLScanRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=MAX_URL_LENGTH,
    )

    @field_validator("url")
    @classmethod
    def validate_url_input(cls, value: str) -> str:
        value = str(value).strip()

        if not value:
            raise ValueError("URL cannot be empty.")

        return value


class TextScanRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=MAX_TEXT_LENGTH,
    )

    @field_validator("text")
    @classmethod
    def validate_text_input(cls, value: str) -> str:
        value = str(value).strip()

        if not value:
            raise ValueError("Text cannot be empty.")

        return value


# ============================================================
# GENERAL HELPERS
# ============================================================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_scan_id() -> str:
    return str(uuid.uuid4())


def normalize_url(value: str) -> str:
    value = str(value or "").strip()

    if not value:
        raise ValueError("URL cannot be empty.")

    if len(value) > MAX_URL_LENGTH:
        raise ValueError("URL is too long.")

    return value


def get_hostname(target_url: str) -> str:
    try:
        return (
            urlparse(target_url)
            .hostname
            or ""
        ).lower().strip().rstrip(".")
    except Exception:
        return ""


def is_http_url(target_url: str) -> bool:
    try:
        parsed = urlparse(target_url)

        return (
            parsed.scheme.lower()
            in {"http", "https"}
            and bool(parsed.hostname)
        )

    except Exception:
        return False


def get_url_scheme(target_url: str) -> str:
    try:
        return urlparse(target_url).scheme.lower()
    except Exception:
        return ""


def is_ip_hostname(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def normalize_hostname(hostname: str) -> str:
    return (
        str(hostname or "")
        .lower()
        .strip()
        .rstrip(".")
    )


# ============================================================
# URL EXTRACTION
# ============================================================

URL_REGEX = re.compile(
    r"(?i)\b"
    r"(?:https?://|www\.)"
    r"[^\s<>'\"]+"
)


def extract_urls(text: str) -> list[str]:
    matches = URL_REGEX.findall(text or "")

    cleaned: list[str] = []

    for value in matches:
        value = value.rstrip(
            ".,!?;:)]}"
        )

        if value.lower().startswith("www."):
            value = "https://" + value

        if value not in cleaned:
            cleaned.append(value)

    return cleaned[:20]


# ============================================================
# SSRF / NETWORK SAFETY
# ============================================================

def resolve_hostname(hostname: str) -> list[str]:
    hostname = normalize_hostname(hostname)

    if not hostname:
        return []

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
                ipaddress.ip_address(address)
                addresses.add(address)
            except ValueError:
                continue

    except (
        socket.gaierror,
        OSError,
    ):
        return []

    return sorted(addresses)


def is_public_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)

        return not any(
            [
                ip.is_private,
                ip.is_loopback,
                ip.is_reserved,
                ip.is_link_local,
                ip.is_multicast,
                ip.is_unspecified,
                ip.is_broadcast
                if hasattr(ip, "is_broadcast")
                else False,
            ]
        )

    except ValueError:
        return False


def is_safe_target(target_url: str) -> bool:
    """
    Defensive SSRF protection.

    Only public HTTP/HTTPS destinations are allowed.
    """

    if not is_http_url(target_url):
        return False

    parsed = urlparse(target_url)

    hostname = normalize_hostname(
        parsed.hostname or ""
    )

    if not hostname:
        return False

    # Reject credentials embedded in URL.
    if parsed.username or parsed.password:
        return False

    # Direct IP.
    if is_ip_hostname(hostname):
        return is_public_ip(hostname)

    addresses = resolve_hostname(hostname)

    if not addresses:
        return False

    return all(
        is_public_ip(address)
        for address in addresses
    )


# ============================================================
# URL STRUCTURE INTELLIGENCE
# ============================================================

def analyze_hostname_structure(
    hostname: str,
) -> dict[str, Any]:

    hostname = normalize_hostname(hostname)

    labels = [
        label
        for label in hostname.split(".")
        if label
    ]

    return {
        "hostname_length": len(hostname),
        "label_count": len(labels),
        "subdomain_count": max(
            0,
            len(labels) - 2,
        ),
        "hyphen_count": hostname.count("-"),
        "digit_count": sum(
            char.isdigit()
            for char in hostname
        ),
        "punycode": "xn--" in hostname,
        "numeric_hostname": (
            is_ip_hostname(hostname)
        ),
    }


def detect_suspicious_tld(domain: str) -> bool:
    domain = normalize_hostname(domain)

    return any(
        domain.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    )


def detect_url_shortener(domain: str) -> bool:
    domain = normalize_hostname(domain)

    return domain in URL_SHORTENERS


def detect_suspicious_path(
    target_url: str,
) -> tuple[float, list[str]]:

    try:
        parsed = urlparse(target_url)

    except Exception:
        return 0.0, []

    path = unquote(
        parsed.path or ""
    ).lower()

    matched = [
        word
        for word in SUSPICIOUS_PATH_WORDS
        if word in path
    ]

    if not matched:
        return 0.0, []

    score = min(
        1.0,
        len(matched) * 0.18,
    )

    return score, matched


# ============================================================
# TYPOSQUATTING
# ============================================================

def advanced_typosquat_analysis(
    domain: str,
) -> dict[str, Any]:

    domain = normalize_hostname(domain)

    if not domain:
        return {
            "score": 0.0,
            "matched_brand": None,
            "technique": None,
            "signals": [],
        }

    labels = domain.split(".")

    main_domain = (
        labels[-2]
        if len(labels) >= 2
        else labels[0]
    )

    score = 0.0
    matched_brand = None
    technique = None

    signals: list[str] = []

    for brand in MONITORED_BRANDS:

        if main_domain == brand:
            continue

        similarity = SequenceMatcher(
            None,
            main_domain,
            brand,
        ).ratio()

        candidate = main_domain

        detected_technique = None

        if (
            brand in candidate
            and candidate != brand
        ):
            detected_technique = (
                "brand_insertion"
            )

        elif (
            candidate.startswith(brand)
            or candidate.endswith(brand)
        ):
            detected_technique = (
                "brand_extension"
            )

        elif (
            len(candidate)
            == len(brand) + 1
        ):

            if any(
                candidate[:i]
                + candidate[i + 1:]
                == brand
                for i in range(
                    len(candidate)
                )
            ):
                detected_technique = (
                    "character_insertion"
                )

        elif (
            len(candidate)
            == len(brand) - 1
        ):

            if any(
                brand[:i]
                + brand[i + 1:]
                == candidate
                for i in range(
                    len(brand)
                )
            ):
                detected_technique = (
                    "character_deletion"
                )

        if (
            similarity >= 0.78
            or detected_technique
        ):

            effective_score = max(
                similarity,
                0.80
                if detected_technique
                else similarity,
            )

            if effective_score > score:
                score = effective_score
                matched_brand = brand
                technique = (
                    detected_technique
                    or "high_similarity"
                )

    if "xn--" in main_domain:
        signals.append(
            "Punycode/IDN hostname detected."
        )

    if main_domain.count("-") >= 2:
        signals.append(
            "Multiple hyphens in the registrable hostname."
        )

    if main_domain.isdigit():
        signals.append(
            "Numeric-only hostname label detected."
        )

    if matched_brand:
        signals.append(
            "Hostname resembles monitored brand "
            f"'{matched_brand}'."
        )

    return {
        "score": round(
            min(score, 1.0),
            3,
        ),
        "matched_brand": matched_brand,
        "technique": technique,
        "signals": signals,
    }


# ============================================================
# URL OBFUSCATION
# ============================================================

def advanced_url_obfuscation(
    target_url: str,
) -> dict[str, Any]:

    findings: list[str] = []
    risk = 0.0

    parsed = urlparse(target_url)

    hostname = get_hostname(
        target_url
    )

    decoded = unquote(
        target_url
    )

    if (
        parsed.username
        or parsed.password
        or "@" in target_url
    ):
        findings.append(
            "URL contains user-info/@ syntax "
            "that can obscure the destination."
        )

        risk = max(
            risk,
            0.85,
        )

    if "%" in target_url:
        findings.append(
            "Percent-encoded characters are present."
        )

        risk = max(
            risk,
            0.35,
        )

    if target_url.lower().startswith(
        "http://"
    ):
        findings.append(
            "URL uses unencrypted HTTP."
        )

        risk = max(
            risk,
            0.45,
        )

    if target_url.count("//") > 1:
        findings.append(
            "Multiple protocol separators are present."
        )

        risk = max(
            risk,
            0.55,
        )

    if len(target_url) > 180:
        findings.append(
            "URL is unusually long."
        )

        risk = max(
            risk,
            0.30,
        )

    if target_url.count(".") >= 5:
        findings.append(
            "URL contains many subdomain levels."
        )

        risk = max(
            risk,
            0.40,
        )

    if (
        hostname.startswith("xn--")
        or ".xn--" in hostname
    ):
        findings.append(
            "Punycode hostname detected."
        )

        risk = max(
            risk,
            0.50,
        )

    if is_ip_hostname(hostname):
        findings.append(
            "Destination uses a literal IP address "
            "instead of a domain."
        )

        risk = max(
            risk,
            0.55,
        )

    if decoded != target_url:
        findings.append(
            "URL changes after percent-decoding."
        )

        risk = max(
            risk,
            0.40,
        )

    if len(parsed.query) > 800:
        findings.append(
            "URL query string is unusually large."
        )

        risk = max(
            risk,
            0.25,
        )

    return {
        "score": round(
            min(risk, 1.0),
            3,
        ),
        "findings": findings,
    }


# ============================================================
# DOMAIN AGE / RDAP
# ============================================================

def domain_age_signal(
    age_days: int | None,
) -> float:

    if age_days is None:
        return 0.10

    if age_days < 30:
        return 0.90

    if age_days < 90:
        return 0.60

    if age_days < 365:
        return 0.30

    return 0.10


async def get_domain_registration_age(
    domain: str,
) -> tuple[int | None, str | None, str]:

    if not domain:
        return (
            None,
            None,
            "unavailable",
        )

    def fetch() -> tuple[
        int | None,
        str | None,
        str,
    ]:

        try:
            response = requests.get(
                f"https://rdap.org/domain/{domain}",
                headers={
                    "Accept":
                        "application/rdap+json"
                },
                timeout=RDAP_TIMEOUT_SECONDS,
            )

            if response.status_code != 200:
                return (
                    None,
                    None,
                    "rdap_unavailable",
                )

            data = response.json()

            registration_date = None

            for event in data.get(
                "events",
                [],
            ):

                if (
                    event.get(
                        "eventAction"
                    )
                    == "registration"
                ):
                    registration_date = (
                        event.get(
                            "eventDate"
                        )
                    )
                    break

            if not registration_date:
                return (
                    None,
                    None,
                    "registration_date_unavailable",
                )

            registered_at = (
                datetime.fromisoformat(
                    registration_date.replace(
                        "Z",
                        "+00:00",
                    )
                )
            )

            age_days = max(
                0,
                (
                    datetime.now(
                        timezone.utc
                    )
                    - registered_at
                ).days,
            )

            return (
                age_days,
                registration_date,
                "rdap.org",
            )

        except Exception:
            return (
                None,
                None,
                "rdap_error",
            )

    return await asyncio.to_thread(
        fetch
    )


# ============================================================
# TEXT SIGNALS
# ============================================================

def detect_urgency(
    text: str,
) -> tuple[float, list[str]]:

    lowered = text.lower()

    matched = [
        word
        for word in URGENCY_KEYWORDS
        if word in lowered
    ]

    return (
        min(
            len(matched) * 0.20,
            1.0,
        ),
        matched,
    )


def detect_upi_signals(
    text: str,
) -> tuple[int, list[str]]:

    lowered = text.lower()

    findings: list[str] = []

    if "upi://" in lowered:
        findings.append(
            "UPI URI detected."
        )

    for handle in UPI_HANDLES:

        if handle in lowered:
            findings.append(
                "UPI handle pattern detected: "
                f"{handle}"
            )

    return (
        1 if findings else 0,
        findings,
    )


def detect_brand_mentions(
    text: str,
) -> list[str]:

    lowered = text.lower()

    return [
        brand
        for brand in MONITORED_BRANDS
        if brand in lowered
    ]


def detect_payment_language(
    text: str,
) -> list[str]:

    lowered = text.lower()

    payment_terms = [
        "payment",
        "pay now",
        "bank transfer",
        "credit card",
        "debit card",
        "upi",
        "wallet",
        "refund",
        "transaction",
        "beneficiary",
    ]

    return [
        term
        for term in payment_terms
        if term in lowered
    ]


# ============================================================
# REDIRECT INTELLIGENCE
# ============================================================

async def trace_url_hops(
    target_url: str,
) -> tuple[
    list[dict[str, Any]],
    str,
    list[str],
]:

    redirect_chain: list[
        dict[str, Any]
    ] = []

    security_events: list[str] = []

    final_url = target_url

    request_count = 0

    async with async_playwright() as playwright:

        browser: Browser = await playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
            ],
        )

        context: BrowserContext = (
            await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 "
                    "(Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "(KHTML, like Gecko) "
                    "Chrome/120.0 Safari/537.36"
                ),
                java_script_enabled=True,
                ignore_https_errors=False,
            )
        )

        page: Page = await context.new_page()

        async def guard_route(route):

            nonlocal request_count

            request_count += 1

            if (
                request_count
                > MAX_PAGE_REQUESTS
            ):
                security_events.append(
                    "Page request limit reached."
                )

                await route.abort()
                return

            requested_url = (
                route.request.url
            )

            if (
                is_http_url(
                    requested_url
                )
                and not is_safe_target(
                    requested_url
                )
            ):

                security_events.append(
                    "Blocked navigation/request "
                    "to a restricted network target."
                )

                await route.abort()
                return

            await route.continue_()

        async def handle_response(
            response,
        ):

            if response.status in {
                301,
                302,
                303,
                307,
                308,
            }:

                if (
                    len(redirect_chain)
                    < MAX_REDIRECT_HOPS
                ):

                    redirect_chain.append(
                        {
                            "url":
                                response.url,
                            "status":
                                response.status,
                        }
                    )

        await page.route(
            "**/*",
            guard_route,
        )

        page.on(
            "response",
            handle_response,
        )

        try:

            await page.goto(
                target_url,
                wait_until="domcontentloaded",
                timeout=(
                    REQUEST_TIMEOUT_SECONDS
                    * 1000
                ),
            )

            final_url = (
                page.url
                or target_url
            )

        except Exception as exc:

            security_events.append(
                "Browser navigation completed "
                "with a controlled exception: "
                f"{type(exc).__name__}."
            )

            final_url = (
                page.url
                or target_url
            )

        finally:

            await browser.close()

    return (
        redirect_chain,
        final_url,
        security_events,
    )


# ============================================================
# HTTP SECURITY HEADERS
# ============================================================

async def inspect_http_headers(
    target_url: str,
) -> dict[str, Any]:

    def fetch():

        try:

            response = requests.get(
                target_url,
                timeout=REQUEST_TIMEOUT_SECONDS,
                allow_redirects=False,
                headers={
                    "User-Agent":
                        "CyberGuard-X-Security-Scanner/3.0"
                },
            )

            headers = {
                key.lower(): value
                for key, value
                in response.headers.items()
            }

            important_headers = {
                "strict-transport-security":
                    headers.get(
                        "strict-transport-security"
                    ),
                "content-security-policy":
                    headers.get(
                        "content-security-policy"
                    ),
                "x-frame-options":
                    headers.get(
                        "x-frame-options"
                    ),
                "x-content-type-options":
                    headers.get(
                        "x-content-type-options"
                    ),
                "referrer-policy":
                    headers.get(
                        "referrer-policy"
                    ),
                "permissions-policy":
                    headers.get(
                        "permissions-policy"
                    ),
            }

            return {
                "status_code":
                    response.status_code,
                "server":
                    headers.get("server"),
                "security_headers":
                    important_headers,
            }

        except Exception as exc:

            return {
                "error":
                    type(exc).__name__,
                "security_headers": {},
            }

    return await asyncio.to_thread(
        fetch
    )


# ============================================================
# RISK ENGINE ADAPTER
# ============================================================

def evaluate_signals(
    signals: ThreatSignals,
) -> Any:

    try:

        return risk_engine.evaluate(
            signals
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Risk engine evaluation failed. "
                "Check ai/risk_engine.py."
            ),
        ) from exc


def normalize_assessment(
    assessment: Any,
) -> dict[str, Any]:

    if isinstance(
        assessment,
        dict,
    ):

        score = assessment.get(
            "score"
        )

        if score is None:
            score = assessment.get(
                "risk_score",
                0,
            )

        try:
            score = float(score)
        except (
            TypeError,
            ValueError,
        ):
            score = 0.0

        score = max(
            0.0,
            min(
                100.0,
                score,
            ),
        )

        xai = (
            assessment.get("xai")
            or assessment.get(
                "xai_breakdown"
            )
            or assessment.get(
                "explainability"
            )
            or []
        )

        severity = str(
            assessment.get(
                "severity"
            )
            or "LOW"
        ).upper()

        return {
            **assessment,
            "score":
                round(score, 2),
            "risk_score":
                round(score, 2),
            "severity":
                severity,
            "explanation":
                str(
                    assessment.get(
                        "explanation"
                    )
                    or
                    "Risk assessment completed."
                ),
            "xai":
                xai,
        }

    return {
        "score": 0.0,
        "risk_score": 0.0,
        "severity": "LOW",
        "explanation":
            "Risk assessment completed.",
        "xai": [],
    }


def append_xai(
    assessment: dict[str, Any],
    items: list[str],
) -> None:

    current = assessment.get(
        "xai"
    )

    xai = (
        list(current)
        if isinstance(
            current,
            list,
        )
        else []
    )

    for item in items:

        if item and item not in xai:
            xai.append(item)

    assessment["xai"] = xai


# ============================================================
# COMMON URL ANALYSIS
# ============================================================

async def perform_url_analysis(
    target_url: str,
    source: str = "url",
) -> dict[str, Any]:

    target_url = normalize_url(
        target_url
    )

    if not is_http_url(
        target_url
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Only valid HTTP/HTTPS URLs "
                "are supported."
            ),
        )

    if not is_safe_target(
        target_url
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Security Exception: target resolves "
                "to a restricted or non-public network address."
            ),
        )

    (
        chain,
        final_url,
        navigation_events,
    ) = await trace_url_hops(
        target_url
    )

    if not is_http_url(
        final_url
    ):
        final_url = target_url

    if not is_safe_target(
        final_url
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Security Exception: redirect destination "
                "resolves to a restricted or non-public target."
            ),
        )

    final_domain = (
        get_hostname(final_url)
        or get_hostname(target_url)
    )

    target_domain = get_hostname(
        target_url
    )

    typo_analysis = (
        advanced_typosquat_analysis(
            final_domain
        )
    )

    typo_score = typo_analysis[
        "score"
    ]

    tld_hit = detect_suspicious_tld(
        final_domain
    )

    shortener_hit = (
        detect_url_shortener(
            target_domain
        )
    )

    advanced_obfuscation = (
        advanced_url_obfuscation(
            final_url
        )
    )

    path_score, path_matches = (
        detect_suspicious_path(
            final_url
        )
    )

    (
        domain_age_days,
        registration_date,
        age_source,
    ) = await get_domain_registration_age(
        final_domain
    )

    urgency_score, urgency_matches = (
        detect_urgency(
            target_url
        )
    )

    upi_flag, upi_findings = (
        detect_upi_signals(
            target_url
        )
    )

    protocol_insecure = (
        get_url_scheme(target_url)
        == "http"
    )

    ioc_hits = 0

    if tld_hit:
        ioc_hits += 1

    if typo_score >= 0.78:
        ioc_hits += 1

    if len(chain) >= 2:
        ioc_hits += 1

    if (
        advanced_obfuscation[
            "score"
        ] >= 0.60
    ):
        ioc_hits += 1

    if shortener_hit:
        ioc_hits += 1

    signals = ThreatSignals(
        domain_age_days=
            domain_age_signal(
                domain_age_days
            ),

        redirect_hops=
            len(chain),

        typosquat_similarity=
            typo_score,

        nlp_urgency_score=
            max(
                urgency_score,
                path_score,
            ),

        auth_failure_flag=
            int(
                protocol_insecure
            ),

        visual_brand_spoof=
            typo_score,

        external_ioc_hits=
            min(
                ioc_hits,
                3,
            ),

        upi_anomaly_flag=
            upi_flag,
    )

    assessment = normalize_assessment(
        evaluate_signals(
            signals
        )
    )

    extra_xai: list[str] = []

    extra_xai.extend(
        urgency_matches
    )

    extra_xai.extend(
        upi_findings
    )

    extra_xai.extend(
        advanced_obfuscation[
            "findings"
        ]
    )

    extra_xai.extend(
        typo_analysis[
            "signals"
        ]
    )

    if path_matches:

        extra_xai.append(
            "Sensitive/security-related "
            "path indicators detected: "
            + ", ".join(
                path_matches
            )
        )

    if shortener_hit:

        extra_xai.append(
            "URL-shortening service detected."
        )

    if tld_hit:

        extra_xai.append(
            "Suspicious TLD pattern detected "
            f"on {final_domain}."
        )

    if len(chain) >= 2:

        extra_xai.append(
            "Multiple redirects detected: "
            f"{len(chain)} hop(s)."
        )

    if domain_age_days is not None:

        if domain_age_days < 90:

            extra_xai.append(
                "Domain registration age is "
                f"approximately {domain_age_days} day(s)."
            )

    if navigation_events:

        extra_xai.extend(
            navigation_events
        )

    append_xai(
        assessment,
        extra_xai,
    )

    # --------------------------------------------------------
    # HTTP HEADER INTELLIGENCE
    # --------------------------------------------------------

    header_data = (
        await inspect_http_headers(
            final_url
        )
    )

    # --------------------------------------------------------
    # URL STRUCTURE
    # --------------------------------------------------------

    hostname_structure = (
        analyze_hostname_structure(
            final_domain
        )
    )

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    return {
        "status": "success",

        "input_type":
            source,

        "scan_id":
            new_scan_id(),

        "scanned_at":
            utc_now_iso(),

        "trace": {
            "original_url":
                target_url,

            "final_url":
                final_url,

            "hops":
                chain,
        },

        "assessment":
            assessment,

        "metadata": {

            "domain":
                final_domain,

            "original_domain":
                target_domain,

            "domain_age_days":
                domain_age_days,

            "registration_date":
                registration_date,

            "age_source":
                age_source,

            "typosquat_similarity":
                typo_score,

            "typosquat":
                typo_analysis,

            "suspicious_tld":
                tld_hit,

            "url_shortener":
                shortener_hit,

            "obfuscation":
                advanced_obfuscation,

            "redirect_hops":
                len(chain),

            "ioc_indicator_count":
                ioc_hits,

            "path_score":
                path_score,

            "path_matches":
                path_matches,

            "hostname_structure":
                hostname_structure,

            "http_headers":
                header_data,

            "https":
                get_url_scheme(
                    final_url
                ) == "https",
        },
    }


# ============================================================
# URL SCANNER
# ============================================================

@app.post("/scan/url")
async def scan_url(
    request: Request,
    payload: URLScanRequest,
):

    check_rate_limit(
        request
    )

    increment_metric(
        "total_scans"
    )

    increment_metric(
        "url_scans"
    )

    try:

        result = await perform_url_analysis(
            payload.url,
            source="url",
        )

        increment_metric(
            "successful_scans"
        )

        return result

    except HTTPException:
        increment_metric(
            "failed_scans"
        )
        raise

    except Exception as exc:

        increment_metric(
            "failed_scans"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unexpected URL analysis error."
            ),
        ) from exc


# ============================================================
# TEXT / SMS / EMAIL SCANNER
# ============================================================

@app.post("/scan/text")
async def scan_text(
    request: Request,
    payload: TextScanRequest,
):

    check_rate_limit(
        request
    )

    increment_metric(
        "total_scans"
    )

    increment_metric(
        "text_scans"
    )

    content = payload.text.strip()

    if not content:
        raise HTTPException(
            status_code=400,
            detail=(
                "Text content cannot be empty."
            ),
        )

    try:

        urgency_score, urgency_matches = (
            detect_urgency(
                content
            )
        )

        upi_flag, upi_findings = (
            detect_upi_signals(
                content
            )
        )

        brand_mentions = (
            detect_brand_mentions(
                content
            )
        )

        payment_language = (
            detect_payment_language(
                content
            )
        )

        extracted_urls = extract_urls(
            content
        )

        signals = ThreatSignals(
            domain_age_days=0.0,

            redirect_hops=0,

            typosquat_similarity=(
                0.75
                if brand_mentions
                else 0.0
            ),

            nlp_urgency_score=
                urgency_score,

            auth_failure_flag=0,

            visual_brand_spoof=0.0,

            external_ioc_hits=
                min(
                    len(extracted_urls),
                    3,
                ),

            upi_anomaly_flag=
                upi_flag,
        )

        assessment = normalize_assessment(
            evaluate_signals(
                signals
            )
        )

        extra_xai: list[str] = []

        if urgency_matches:

            extra_xai.append(
                "Urgency/social-engineering "
                "indicators: "
                + ", ".join(
                    urgency_matches
                )
            )

        if brand_mentions:

            extra_xai.append(
                "Monitored brand mentioned: "
                + ", ".join(
                    brand_mentions
                )
            )

        if payment_language:

            extra_xai.append(
                "Payment-related language detected: "
                + ", ".join(
                    payment_language
                )
            )

        if extracted_urls:

            extra_xai.append(
                f"{len(extracted_urls)} URL(s) "
                "found in submitted content."
            )

        extra_xai.extend(
            upi_findings
        )

        append_xai(
            assessment,
            extra_xai,
        )

        result = {

            "status":
                "success",

            "input_type":
                "text/sms/email",

            "scan_id":
                new_scan_id(),

            "scanned_at":
                utc_now_iso(),

            "assessment":
                assessment,

            "metadata": {

                "urgency_score":
                    urgency_score,

                "urgency_matches":
                    urgency_matches,

                "brand_mentions":
                    brand_mentions,

                "upi_signal":
                    bool(
                        upi_flag
                    ),

                "payment_language":
                    payment_language,

                "extracted_urls":
                    extracted_urls,

                "url_count":
                    len(
                        extracted_urls
                    ),
            },
        }

        increment_metric(
            "successful_scans"
        )

        return result

    except HTTPException:
        increment_metric(
            "failed_scans"
        )
        raise

    except Exception as exc:

        increment_metric(
            "failed_scans"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unexpected text analysis error."
            ),
        ) from exc


# ============================================================
# QR IMAGE DECODING
# ============================================================

def decode_qr_image(
    image,
) -> tuple[
    str | None,
    dict[str, Any],
]:

    detector = cv2.QRCodeDetector()

    payload = None

    # --------------------------------------------------------
    # First attempt
    # --------------------------------------------------------

    try:

        decoded, _, _ = (
            detector.detectAndDecode(
                image
            )
        )

        if decoded:
            payload = decoded.strip()

    except Exception:
        payload = None

    # --------------------------------------------------------
    # Multi QR fallback
    # --------------------------------------------------------

    if not payload:

        try:

            results, _, _ = (
                detector.detectAndDecodeMulti(
                    image
                )
            )

            if results:

                decoded_values = [
                    value.strip()
                    for value in results
                    if value
                    and value.strip()
                ]

                if decoded_values:
                    payload = decoded_values[0]

                    return (
                        payload,
                        {
                            "decoder":
                                "opencv-multi",
                            "count":
                                len(
                                    decoded_values
                                ),
                            "payloads":
                                decoded_values,
                        },
                    )

        except Exception:
            pass

    if payload:

        return (
            payload,
            {
                "decoder":
                    "opencv",
                "count":
                    1,
                "payloads":
                    [payload],
            },
        )

    return (
        None,
        {
            "decoder":
                "opencv",
            "count":
                0,
            "payloads":
                [],
        },
    )


# ============================================================
# QR / QUISHING SCANNER
# ============================================================

@app.post("/scan/quishing")
async def scan_quishing(
    request: Request,
    file: UploadFile = File(...),
):

    check_rate_limit(
        request
    )

    increment_metric(
        "total_scans"
    )

    increment_metric(
        "qr_scans"
    )

    if not file.filename:

        increment_metric(
            "failed_scans"
        )

        raise HTTPException(
            status_code=400,
            detail="No file provided.",
        )

    allowed_types = {
        "image/png",
        "image/jpeg",
        "image/webp",
    }

    if file.content_type not in allowed_types:

        increment_metric(
            "failed_scans"
        )

        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported image type. "
                "Use PNG, JPEG or WEBP."
            ),
        )

    safe_filename = os.path.basename(
        file.filename
    )[:100]

    temp_file = os.path.join(
        "/tmp",
        (
            "cyberguard_qr_"
            f"{uuid.uuid4().hex}_"
            f"{safe_filename}"
        ),
    )

    try:

        # ----------------------------------------------------
        # Size-limited upload
        # ----------------------------------------------------

        total_bytes = 0

        with open(
            temp_file,
            "wb",
        ) as buffer:

            while True:

                chunk = await file.read(
                    1024 * 256
                )

                if not chunk:
                    break

                total_bytes += len(
                    chunk
                )

                if (
                    total_bytes
                    > MAX_QR_FILE_SIZE
                ):

                    raise HTTPException(
                        status_code=413,
                        detail=(
                            "QR image is too large. "
                            f"Maximum size is "
                            f"{MAX_QR_FILE_SIZE // (1024 * 1024)} MB."
                        ),
                    )

                buffer.write(
                    chunk
                )

        # ----------------------------------------------------
        # Decode image
        # ----------------------------------------------------

        image = cv2.imread(
            temp_file
        )

        if image is None:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Invalid image file."
                ),
            )

        qr_payload, qr_info = (
            decode_qr_image(
                image
            )
        )

        # ----------------------------------------------------
        # No QR detected
        # ----------------------------------------------------

        if not qr_payload:

            increment_metric(
                "successful_scans"
            )

            return {
                "status":
                    "error",

                "input_type":
                    "qr",

                "scan_id":
                    new_scan_id(),

                "scanned_at":
                    utc_now_iso(),

                "message":
                    "No valid QR code payload detected.",

                "assessment": {
                    "score":
                        0.0,

                    "risk_score":
                        0.0,

                    "severity":
                        "LOW",

                    "explanation":
                        (
                            "The uploaded image was "
                            "processed, but no QR payload "
                            "could be decoded."
                        ),

                    "xai": [
                        "Image processing completed.",
                        "No QR payload was decoded.",
                    ],
                },

                "metadata": {
                    "filename":
                        safe_filename,

                    "file_size_bytes":
                        total_bytes,

                    "decoder":
                        qr_info.get(
                            "decoder"
                        ),

                    "qr_count":
                        qr_info.get(
                            "count"
                        ),
                },
            }

        qr_payload = qr_payload.strip()

        payload_lower = (
            qr_payload.lower()
        )

        is_url = payload_lower.startswith(
            (
                "http://",
                "https://",
            )
        )

        is_upi = payload_lower.startswith(
            "upi://"
        )

        # ----------------------------------------------------
        # Plain text QR
        # ----------------------------------------------------

        if not is_url and not is_upi:

            assessment = {
                "score":
                    0.0,

                "risk_score":
                    0.0,

                "severity":
                    "LOW",

                "explanation":
                    (
                        "QR payload was decoded successfully "
                        "but is not an HTTP/HTTPS URL "
                        "or UPI URI."
                    ),

                "xai": [
                    "QR payload successfully decoded.",
                    "Payload classified as plain text.",
                ],
            }

            increment_metric(
                "successful_scans"
            )

            return {
                "status":
                    "success",

                "input_type":
                    "qr",

                "scan_id":
                    new_scan_id(),

                "scanned_at":
                    utc_now_iso(),

                "payload_type":
                    "text",

                "extracted_payload":
                    qr_payload,

                "assessment":
                    assessment,

                "metadata": {
                    "decoder":
                        qr_info.get(
                            "decoder"
                        ),

                    "qr_count":
                        qr_info.get(
                            "count"
                        ),

                    "file_size_bytes":
                        total_bytes,
                },
            }

        # ----------------------------------------------------
        # UPI QR
        # ----------------------------------------------------

        if is_upi:

            upi_signals = (
                ThreatSignals(
                    domain_age_days=0.0,
                    redirect_hops=0,
                    typosquat_similarity=0.0,
                    nlp_urgency_score=0.2,
                    auth_failure_flag=0,
                    visual_brand_spoof=0.0,
                    external_ioc_hits=0,
                    upi_anomaly_flag=1,
                )
            )

            assessment = (
                normalize_assessment(
                    evaluate_signals(
                        upi_signals
                    )
                )
            )

            append_xai(
                assessment,
                [
                    "QR payload contains a UPI URI."
                ],
            )

            increment_metric(
                "successful_scans"
            )

            return {
                "status":
                    "success",

                "input_type":
                    "qr",

                "scan_id":
                    new_scan_id(),

                "scanned_at":
                    utc_now_iso(),

                "payload_type":
                    "upi",

                "extracted_payload":
                    qr_payload,

                "assessment":
                    assessment,

                "metadata": {
                    "decoder":
                        qr_info.get(
                            "decoder"
                        ),

                    "qr_count":
                        qr_info.get(
                            "count"
                        ),

                    "file_size_bytes":
                        total_bytes,

                    "upi":
                        True,
                },
            }

        # ----------------------------------------------------
        # QR URL
        # ----------------------------------------------------

        if not is_safe_target(
            qr_payload
        ):

            raise HTTPException(
                status_code=400,
                detail=(
                    "Security Exception: QR URL resolves "
                    "to a restricted or unsafe target."
                ),
            )

        result = await perform_url_analysis(
            qr_payload,
            source="qr",
        )

        result["payload_type"] = "url"

        result["extracted_payload"] = (
            qr_payload
        )

        result["metadata"][
            "decoder"
        ] = qr_info.get(
            "decoder"
        )

        result["metadata"][
            "qr_count"
        ] = qr_info.get(
            "count"
        )

        result["metadata"][
            "file_size_bytes"
        ] = total_bytes

        increment_metric(
            "successful_scans"
        )

        return result

    except HTTPException:

        increment_metric(
            "failed_scans"
        )

        raise

    except Exception as exc:

        increment_metric(
            "failed_scans"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unexpected QR analysis error."
            ),
        ) from exc

    finally:

        try:
            await file.close()
        except Exception:
            pass

        if os.path.exists(
            temp_file
        ):

            try:
                os.remove(
                    temp_file
                )
            except OSError:
                pass


# ============================================================
# GENERIC API INFORMATION
# ============================================================

@app.get("/")
async def root():

    return {
        "status":
            "online",

        "service":
            "CYBERGUARD X",

        "version":
            APP_VERSION,

        "engine":
            "Core Threat Analysis Engine",

        "features": [

            "URL threat scanning",

            "Advanced redirect intelligence",

            "Final redirect safety validation",

            "RDAP domain registration age",

            "Advanced typosquatting detection",

            "URL obfuscation detection",

            "Suspicious TLD detection",

            "URL shortener detection",

            "Suspicious path detection",

            "HTTP security-header inspection",

            "SMS / Email analysis",

            "URL extraction from text",

            "UPI scam signal detection",

            "QR / Quishing analysis",

            "Multi-QR decoding",

            "Explainable AI",

            "Multi-signal risk scoring",

            "SSRF protection",

            "Rate limiting",

            "Scan identifiers",

            "Operational metrics",
        ],
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():

    return {
        "status":
            "healthy",

        "service":
            BACKEND_NAME,

        "version":
            APP_VERSION,

        "risk_engine":
            "available",

        "advanced_url_intelligence":
            "enabled",

        "qr_analysis":
            "enabled",

        "ssrf_protection":
            "enabled",

        "rate_limiting":
            "enabled",
    }


# ============================================================
# READINESS
# ============================================================

@app.get("/ready")
async def ready():

    return {
        "ready":
            True,

        "service":
            BACKEND_NAME,

        "version":
            APP_VERSION,
    }


# ============================================================
# METRICS
# ============================================================

@app.get("/metrics")
async def metrics():

    return {
        "service":
            BACKEND_NAME,

        "version":
            APP_VERSION,

        "metrics":
            dict(METRICS),
    }


# ============================================================
# API ERROR HANDLER
# ============================================================

@app.exception_handler(
    Exception
)
async def global_exception_handler(
    request: Request,
    exc: Exception,
):

    increment_metric(
        "failed_scans"
    )

    print(
        "Unhandled CyberGuard X exception:",
        repr(exc),
    )

    return HTTPException(
        status_code=500,
        detail=(
            "Internal CyberGuard X backend error."
        ),
    )


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup_event():

    print(
        "=================================================="
    )

    print(
        " CYBERGUARD X BACKEND"
    )

    print(
        f" Version: {APP_VERSION}"
    )

    print(
        " Threat engine: loaded"
    )

    print(
        " SSRF protection: enabled"
    )

    print(
        " QR analysis: enabled"
    )

    print(
        " Redirect intelligence: enabled"
    )

    print(
        "=================================================="
    )
