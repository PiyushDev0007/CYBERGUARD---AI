import ipaddress
import os
import shutil
import socket
import sys
import uuid
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import cv2
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from playwright.async_api import async_playwright


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# EXISTING RISK ENGINE
# ============================================================

try:
    from ai.risk_engine import CyberGuardRiskEngine, ThreatSignals
except ImportError as exc:
    raise RuntimeError(
        "Could not import ai.risk_engine. "
        "Make sure ai/risk_engine.py exists."
    ) from exc


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="CYBERGUARD X — Advanced Threat Detection Platform",
    description=(
        "CyberGuard X backend for URL, text, QR and "
        "multi-signal cyber threat analysis."
    ),
    version="1.1.0",
)


risk_engine = CyberGuardRiskEngine()


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# CONSTANTS
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
]

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".su",
    ".click",
    ".work",
    ".zip",
    ".mov",
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


# ============================================================
# REQUEST MODELS
# ============================================================

class URLScanRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="HTTP or HTTPS URL to analyze.",
    )


class TextScanRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=50000,
        description="SMS, email or suspicious text.",
    )


# ============================================================
# BASIC HELPERS
# ============================================================

def normalize_url(value: str) -> str:
    """
    Normalize user-provided URL input.

    We intentionally do NOT automatically convert arbitrary text
    into a URL. Only HTTP/HTTPS URLs are accepted here.
    """

    value = str(value or "").strip()

    if not value:
        raise ValueError("URL cannot be empty.")

    if len(value) > 4096:
        raise ValueError("URL is too long.")

    return value


def get_hostname(target_url: str) -> str:
    """Return lowercase hostname without raising."""

    try:
        parsed = urlparse(target_url)
        return (parsed.hostname or "").lower().strip()
    except Exception:
        return ""


def is_http_url(target_url: str) -> bool:
    """Check whether a URL uses HTTP or HTTPS."""

    try:
        parsed = urlparse(target_url)

        return (
            parsed.scheme.lower() in {"http", "https"}
            and bool(parsed.hostname)
        )

    except Exception:
        return False


# ============================================================
# SSRF PROTECTION
# ============================================================

def resolve_hostname(hostname: str) -> list[str]:
    """
    Resolve a hostname to IPv4/IPv6 addresses.

    Multiple addresses are returned because a hostname may resolve
    to multiple destinations.
    """

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

            if sockaddr:
                address = sockaddr[0]

                try:
                    ipaddress.ip_address(address)
                    addresses.add(address)
                except ValueError:
                    continue

    except socket.gaierror:
        return []

    return sorted(addresses)


def is_public_ip(address: str) -> bool:
    """Return True only for publicly routable-looking IP addresses."""

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
            ]
        )

    except ValueError:
        return False


def is_safe_target(target_url: str) -> bool:
    """
    SSRF protection for server-side URL inspection.

    Blocks:
    - non HTTP/HTTPS schemes
    - missing hosts
    - private IPs
    - loopback
    - link-local
    - multicast
    - reserved
    - unspecified addresses

    IMPORTANT:
    This is a defensive baseline, not a complete enterprise SSRF
    prevention system.
    """

    if not is_http_url(target_url):
        return False

    hostname = get_hostname(target_url)

    if not hostname:
        return False

    # Direct IP target.
    try:
        direct_ip = ipaddress.ip_address(hostname)

        return is_public_ip(str(direct_ip))

    except ValueError:
        pass

    # Hostname target.
    addresses = resolve_hostname(hostname)

    if not addresses:
        return False

    return all(is_public_ip(address) for address in addresses)


# ============================================================
# DOMAIN / URL FEATURES
# ============================================================

def calculate_typosquat(domain: str) -> float:
    """
    Basic brand similarity detection.

    Returns:
        0.0 - 1.0
    """

    domain = str(domain or "").lower().strip()

    if not domain:
        return 0.0

    # Remove a trailing dot if present.
    domain = domain.rstrip(".")

    labels = domain.split(".")

    if not labels:
        return 0.0

    main_domain = labels[-2] if len(labels) >= 2 else labels[0]

    max_score = 0.0

    for brand in MONITORED_BRANDS:

        if brand == main_domain:
            continue

        similarity = SequenceMatcher(
            None,
            main_domain,
            brand,
        ).ratio()

        if similarity >= 0.65 or brand in main_domain:
            max_score = max(
                max_score,
                similarity,
            )

    return round(max_score, 3)


def detect_suspicious_tld(domain: str) -> bool:
    domain = str(domain or "").lower().rstrip(".")

    return any(
        domain.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    )


def detect_url_obfuscation(target_url: str) -> list[str]:
    """
    Detect common URL-level suspicious patterns.

    This is intentionally heuristic and does not claim that a
    matching pattern is automatically malicious.
    """

    findings: list[str] = []

    lowered = target_url.lower()

    if "@" in target_url:
        findings.append(
            "URL contains '@', which can obscure the actual destination."
        )

    if "%" in target_url:
        findings.append(
            "URL contains percent-encoded characters."
        )

    if lowered.startswith("http://"):
        findings.append(
            "URL uses unencrypted HTTP."
        )

    if target_url.count("//") > 1:
        findings.append(
            "URL contains multiple protocol separators."
        )

    if len(target_url) > 180:
        findings.append(
            "URL is unusually long."
        )

    if target_url.count(".") >= 5:
        findings.append(
            "URL contains an unusually high number of subdomain levels."
        )

    return findings
# ============================================================
# ADVANCED URL INTELLIGENCE
# ============================================================

async def get_domain_registration_age(domain: str):
    """
    Best-effort RDAP lookup for domain registration information.

    Returns:
        {
            "age_days": int | None,
            "registration_date": str | None,
            "source": "RDAP" | None
        }

    This is intelligence enrichment only.
    If RDAP is unavailable, the scanner continues safely.
    """

    domain = str(domain or "").lower().strip().rstrip(".")

    if not domain:
        return {
            "age_days": None,
            "registration_date": None,
            "source": None,
        }

    try:
        timeout = httpx.Timeout(
            connect=3.0,
            read=5.0,
            write=5.0,
            pool=5.0,
        )

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": "CYBERGUARD-X/1.0"
            },
        ) as client:

            response = await client.get(
                f"https://rdap.org/domain/{domain}"
            )

            if response.status_code != 200:
                return {
                    "age_days": None,
                    "registration_date": None,
                    "source": None,
                }

            data = response.json()

        events = data.get("events", [])

        registration_date = None

        for event in events:

            event_action = str(
                event.get("eventAction", "")
            ).lower()

            if event_action in {
                "registration",
                "registered",
                "registration date",
            }:

                registration_date = event.get(
                    "eventDate"
                )

                if registration_date:
                    break

        if not registration_date:
            return {
                "age_days": None,
                "registration_date": None,
                "source": None,
            }

        from datetime import datetime, timezone

        parsed_date = datetime.fromisoformat(
            registration_date.replace(
                "Z",
                "+00:00"
            )
        )

        now = datetime.now(timezone.utc)

        age_days = max(
            0,
            (now - parsed_date).days,
        )

        return {
            "age_days": age_days,
            "registration_date": registration_date,
            "source": "RDAP",
        }

    except Exception:
        # Intelligence enrichment must never break
        # the main security scanner.
        return {
            "age_days": None,
            "registration_date": None,
            "source": None,
        }


def advanced_typosquat_analysis(domain: str) -> dict:
    """
    More detailed brand/domain similarity analysis.

    Returns:
        {
            "score": float,
            "matched_brand": str | None,
            "signals": list[str]
        }
    """

    domain = str(domain or "").lower().strip()
    domain = domain.rstrip(".")

    if not domain:
        return {
            "score": 0.0,
            "matched_brand": None,
            "signals": [],
        }

    labels = domain.split(".")

    if len(labels) >= 2:
        main_domain = labels[-2]
    else:
        main_domain = labels[0]

    best_score = 0.0
    best_brand = None
    signals = []

    for brand in MONITORED_BRANDS:

        brand = brand.lower()

        if main_domain == brand:
            continue

        similarity = SequenceMatcher(
            None,
            main_domain,
            brand,
        ).ratio()

        # Strong similarity
        if similarity > best_score:
            best_score = similarity
            best_brand = brand

    if best_brand:

        if best_score >= 0.90:
            signals.append(
                f"Very high similarity to monitored brand: {best_brand}."
            )

        elif best_score >= 0.75:
            signals.append(
                f"High similarity to monitored brand: {best_brand}."
            )

        elif best_score >= 0.65:
            signals.append(
                f"Potential brand similarity detected: {best_brand}."
            )

    # Brand hidden inside a larger domain name.
    for brand in MONITORED_BRANDS:

        if (
            brand.lower() in main_domain
            and main_domain != brand.lower()
        ):
            signals.append(
                f"Brand name appears inside domain: {brand}."
            )

            best_brand = brand
            best_score = max(
                best_score,
                0.72,
            )

    return {
        "score": round(
            min(best_score, 1.0),
            3,
        ),
        "matched_brand": best_brand,
        "signals": list(dict.fromkeys(signals)),
    }


def advanced_url_obfuscation(target_url: str) -> list[str]:
    """
    Detect additional suspicious URL structures.
    """

    findings = []

    try:
        parsed = urlparse(target_url)

        hostname = (
            parsed.hostname or ""
        ).lower()

        # Userinfo trick:
        # https://trusted.com@evil.com
        if parsed.username or parsed.password:
            findings.append(
                "URL contains username/password-style userinfo before the destination host."
            )

        # Punycode / IDN domain.
        if "xn--" in hostname:
            findings.append(
                "Domain contains punycode/IDN encoding."
            )

        # Numeric IP instead of normal domain.
        try:
            ipaddress.ip_address(hostname)

            findings.append(
                "URL uses a direct IP address instead of a domain name."
            )

        except ValueError:
            pass

        # Excessive subdomains.
        labels = [
            x for x in hostname.split(".")
            if x
        ]

        if len(labels) >= 5:
            findings.append(
                "Domain contains many subdomain levels."
            )

        # Suspicious encoded characters.
        if "%" in target_url:
            findings.append(
                "URL contains percent-encoded characters."
            )

        # Very long query.
        if len(parsed.query) > 300:
            findings.append(
                "URL contains an unusually large query string."
            )

    except Exception:
        pass

    return list(
        dict.fromkeys(findings)
    )


def build_domain_age_signal(
    age_days: int | None,
) -> float:
    """
    Convert real domain age into a novelty signal.

    0.0 = established domain
    1.0 = very new / unknown domain

    Unknown age receives a neutral value rather than
    automatically being treated as malicious.
    """

    if age_days is None:
        return 0.0

    if age_days <= 7:
        return 1.0

    if age_days <= 30:
        return 0.85

    if age_days <= 90:
        return 0.65

    if age_days <= 180:
        return 0.45

    if age_days <= 365:
        return 0.25

    return 0.05

def detect_urgency(text: str) -> tuple[float, list[str]]:
    """
    Simple deterministic urgency detector.

    The NLP model will be added in the later backend phase.
    """

    lowered = text.lower()

    matched = [
        word
        for word in URGENCY_KEYWORDS
        if word in lowered
    ]

    if not matched:
        return 0.0, []

    score = min(
        len(matched) * 0.20,
        1.0,
    )

    return score, matched


def detect_upi_signals(text: str) -> tuple[int, list[str]]:
    lowered = text.lower()

    findings = []

    if "upi://" in lowered:
        findings.append("UPI URI detected.")

    for handle in UPI_HANDLES:
        if handle in lowered:
            findings.append(
                f"UPI handle pattern detected: {handle}"
            )

    return (
        1 if findings else 0,
        findings,
    )


def detect_brand_mentions(text: str) -> list[str]:
    lowered = text.lower()

    return [
        brand
        for brand in MONITORED_BRANDS
        if brand in lowered
    ]


# ============================================================
# REDIRECT ANALYSIS
# ============================================================

async def trace_url_hops(
    target_url: str,
) -> tuple[list[dict[str, Any]], str]:
    """
    Safely inspect HTTP navigation using Playwright.

    Returns:
        redirect chain,
        final URL
    """

    redirect_chain: list[dict[str, Any]] = []
    final_url = target_url

    async with async_playwright() as playwright:

        browser = await playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
            ],
        )

        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 "
                "(Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            )
        )

        page = await context.new_page()

        def handle_response(response):
            if response.status in {
                301,
                302,
                303,
                307,
                308,
            }:
                redirect_chain.append(
                    {
                        "url": response.url,
                        "status": response.status,
                    }
                )

        page.on(
            "response",
            handle_response,
        )

        try:
            await page.goto(
                target_url,
                wait_until="domcontentloaded",
                timeout=12000,
            )

            final_url = page.url

        except Exception:
            # Do not expose browser internals.
            final_url = page.url or target_url

        finally:
            await browser.close()

    return redirect_chain, final_url


# ============================================================
# RISK ENGINE ADAPTER
# ============================================================

def evaluate_signals(
    signals: ThreatSignals,
) -> Any:
    """
    Single gateway to the existing CyberGuard Risk Engine.

    Keeping this in one place makes it easier to upgrade the
    engine later without rewriting every scanner.
    """

    try:
        return risk_engine.evaluate(signals)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Risk engine evaluation failed. "
                "Check ai/risk_engine.py."
            ),
        ) from exc


# ============================================================
# NORMALIZE ASSESSMENT
# ============================================================

def normalize_assessment(
    assessment: Any,
) -> dict[str, Any]:
    """
    Convert different possible risk-engine outputs into a stable
    API response.

    This prevents the frontend from having to understand internal
    model implementation details.
    """

    if isinstance(assessment, dict):

        score = (
            assessment.get("score")
            if assessment.get("score") is not None
            else assessment.get("risk_score", 0)
        )

        severity = (
            assessment.get("severity")
            or "LOW"
        )

        explanation = (
            assessment.get("explanation")
            or "Risk assessment completed."
        )

        xai = (
            assessment.get("xai")
            or assessment.get("xai_breakdown")
            or assessment.get("explainability")
            or []
        )

        try:
            score = float(score)
        except (TypeError, ValueError):
            score = 0.0

        score = max(
            0.0,
            min(100.0, score),
        )

        return {
            **assessment,
            "score": round(score, 2),
            "risk_score": round(score, 2),
            "severity": str(severity).upper(),
            "explanation": str(explanation),
            "xai": xai,
        }

    # Defensive fallback if the current risk engine returns
    # an unexpected object.
    return {
        "score": 0.0,
        "risk_score": 0.0,
        "severity": "LOW",
        "explanation": "Risk assessment completed.",
        "xai": [],
    }


# ============================================================
# URL SCANNER
# ============================================================

@app.post("/scan/url")
async def scan_url(request: URLScanRequest):

    target_url = normalize_url(request.url)

    if not is_http_url(target_url):
        raise HTTPException(
            status_code=400,
            detail=(
                "Only valid HTTP/HTTPS URLs are supported."
            ),
        )

    if not is_safe_target(target_url):
        raise HTTPException(
            status_code=400,
            detail=(
                "Security Exception: target resolves to a "
                "restricted or non-public network address."
            ),
        )

    chain, final_url = await trace_url_hops(
        target_url
    )

    final_domain = get_hostname(final_url)

    if not final_domain:
        final_domain = get_hostname(target_url)

    typo_score = calculate_typosquat(
        final_domain
    )

    tld_hit = detect_suspicious_tld(
        final_domain
    )

    urgency_score, urgency_matches = detect_urgency(
        target_url
    )

    upi_flag, upi_findings = detect_upi_signals(
        target_url
    )

    obfuscation_findings = detect_url_obfuscation(
        target_url
    )

    # ------------------------------------------------------------
    # Current MVP signals
    #
    # These are deliberately labelled as heuristic proxies.
    # Actual domain age, reputation and IOC feeds will be added
    # in the Advanced URL Intelligence phase.
    # ------------------------------------------------------------

    signals = ThreatSignals(
        domain_age_days=(
            0.9 if tld_hit else 0.2
        ),

        redirect_hops=len(chain),

        typosquat_similarity=typo_score,

        nlp_urgency_score=urgency_score,

        auth_failure_flag=int(
            target_url.lower().startswith("http://")
        ),

        visual_brand_spoof=typo_score,

        external_ioc_hits=int(
            tld_hit or len(chain) >= 2
        ),

        upi_anomaly_flag=upi_flag,
    )

    raw_assessment = evaluate_signals(
        signals
    )

    assessment = normalize_assessment(
        raw_assessment
    )

    xai = list(
        assessment.get("xai", [])
        if isinstance(
            assessment.get("xai"),
            list,
        )
        else []
    )

    xai.extend(
        urgency_matches
    )

    xai.extend(
        upi_findings
    )

    xai.extend(
        obfuscation_findings
    )

    if tld_hit:
        xai.append(
            f"Suspicious TLD pattern detected on {final_domain}."
        )

    if typo_score >= 0.65:
        xai.append(
            "Domain has similarity to a monitored brand."
        )

    assessment["xai"] = xai

    return {
        "status": "success",
        "input_type": "url",
        "scan_id": str(uuid.uuid4()),
        "trace": {
            "original_url": target_url,
            "final_url": final_url,
            "hops": chain,
        },
        "assessment": assessment,
        "metadata": {
            "domain": final_domain,
            "typosquat_similarity": typo_score,
            "suspicious_tld": tld_hit,
            "redirect_hops": len(chain),
        },
    }


# ============================================================
# TEXT / SMS / EMAIL SCANNER
# ============================================================

@app.post("/scan/text")
async def scan_text(request: TextScanRequest):

    content = request.text.strip()

    if not content:
        raise HTTPException(
            status_code=400,
            detail="Text content cannot be empty.",
        )

    urgency_score, urgency_matches = detect_urgency(
        content
    )

    upi_flag, upi_findings = detect_upi_signals(
        content
    )

    brand_mentions = detect_brand_mentions(
        content
    )

    # Basic brand impersonation signal.
    brand_impersonation = bool(
        brand_mentions
    )

    signals = ThreatSignals(
        domain_age_days=0.0,

        redirect_hops=0,

        typosquat_similarity=(
            0.75
            if brand_impersonation
            else 0.0
        ),

        nlp_urgency_score=urgency_score,

        auth_failure_flag=0,

        visual_brand_spoof=0.0,

        external_ioc_hits=0,

        upi_anomaly_flag=upi_flag,
    )

    raw_assessment = evaluate_signals(
        signals
    )

    assessment = normalize_assessment(
        raw_assessment
    )

    xai = list(
        assessment.get("xai", [])
        if isinstance(
            assessment.get("xai"),
            list,
        )
        else []
    )

    if urgency_matches:
        xai.append(
            "Urgency/social-engineering indicators: "
            + ", ".join(urgency_matches)
        )

    if brand_mentions:
        xai.append(
            "Monitored brand mentioned: "
            + ", ".join(brand_mentions)
        )

    xai.extend(
        upi_findings
    )

    assessment["xai"] = xai

    return {
        "status": "success",
        "input_type": "text/sms/email",
        "scan_id": str(uuid.uuid4()),
        "assessment": assessment,
        "metadata": {
            "urgency_score": urgency_score,
            "brand_mentions": brand_mentions,
            "upi_signal": bool(upi_flag),
        },
    }


# ============================================================
# QR / QUISHING SCANNER
# ============================================================

@app.post("/scan/quishing")
async def scan_quishing(
    file: UploadFile = File(...),
):

    if not file.filename:
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
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported image type. "
                "Use PNG, JPEG or WEBP."
            ),
        )

    safe_filename = os.path.basename(
        file.filename
    )

    # Prevent pathological filenames.
    safe_filename = safe_filename[:100]

    temp_file = os.path.join(
        "/tmp",
        f"cyberguard_qr_{uuid.uuid4().hex}_{safe_filename}",
    )

    try:

        # --------------------------------------------------------
        # Save upload
        # --------------------------------------------------------

        with open(
            temp_file,
            "wb",
        ) as buffer:

            shutil.copyfileobj(
                file.file,
                buffer,
            )

        # --------------------------------------------------------
        # Decode image
        # --------------------------------------------------------

        image = cv2.imread(
            temp_file
        )

        if image is None:
            raise HTTPException(
                status_code=400,
                detail="Invalid image file.",
            )

        # --------------------------------------------------------
        # QR decoder
        # --------------------------------------------------------

        qr_detector = cv2.QRCodeDetector()

        qr_payload, points, _ = (
            qr_detector.detectAndDecode(image)
        )

        if not qr_payload:

            return {
                "status": "error",
                "input_type": "qr",
                "scan_id": str(uuid.uuid4()),
                "message": (
                    "No valid QR code payload detected."
                ),
            }

        qr_payload = qr_payload.strip()

        payload_lower = qr_payload.lower()

        is_url = payload_lower.startswith(
            (
                "http://",
                "https://",
            )
        )

        is_upi = payload_lower.startswith(
            "upi://"
        )

        # --------------------------------------------------------
        # Plain text QR
        # --------------------------------------------------------

        if not is_url and not is_upi:

            return {
                "status": "success",
                "input_type": "qr",
                "scan_id": str(uuid.uuid4()),
                "payload_type": "text",
                "extracted_payload": qr_payload,
                "assessment": {
                    "score": 0.0,
                    "risk_score": 0.0,
                    "severity": "LOW",
                    "explanation": (
                        "QR payload was decoded successfully "
                        "but is not an HTTP/HTTPS URL or UPI URI."
                    ),
                    "xai": [
                        "QR payload successfully decoded.",
                        "Payload classified as plain text.",
                    ],
                },
            }

        # --------------------------------------------------------
        # UPI QR
        # --------------------------------------------------------

        if is_upi:

            upi_signals = ThreatSignals(
                domain_age_days=0.0,
                redirect_hops=0,
                typosquat_similarity=0.0,
                nlp_urgency_score=0.2,
                auth_failure_flag=0,
                visual_brand_spoof=0.0,
                external_ioc_hits=0,
                upi_anomaly_flag=1,
            )

            raw_assessment = evaluate_signals(
                upi_signals
            )

            assessment = normalize_assessment(
                raw_assessment
            )

            return {
                "status": "success",
                "input_type": "qr",
                "scan_id": str(uuid.uuid4()),
                "payload_type": "upi",
                "extracted_payload": qr_payload,
                "assessment": assessment,
            }

        # --------------------------------------------------------
        # QR URL
        # --------------------------------------------------------

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

        chain, final_url = await trace_url_hops(
            qr_payload
        )

        final_domain = get_hostname(
            final_url
        )

        typo_score = calculate_typosquat(
            final_domain
        )

        tld_hit = detect_suspicious_tld(
            final_domain
        )

        signals = ThreatSignals(
            domain_age_days=(
                0.8 if tld_hit else 0.2
            ),

            redirect_hops=len(chain),

            typosquat_similarity=typo_score,

            nlp_urgency_score=0.2,

            auth_failure_flag=int(
                qr_payload.lower().startswith(
                    "http://"
                )
            ),

            visual_brand_spoof=typo_score,

            external_ioc_hits=int(
                tld_hit or len(chain) >= 2
            ),

            upi_anomaly_flag=0,
        )

        raw_assessment = evaluate_signals(
            signals
        )

        assessment = normalize_assessment(
            raw_assessment
        )

        xai = list(
            assessment.get("xai", [])
            if isinstance(
                assessment.get
                assessment.get("xai"),
        list,
    )
    else []
)

if tld_hit:
    xai.append(
        f"Suspicious TLD pattern detected on {final_domain}."
    )

if typo_score >= 0.65:
    xai.append(
        "QR destination domain has similarity to a monitored brand."
    )

if len(chain) >= 2:
    xai.append(
        f"Multiple redirects detected: {len(chain)} hop(s)."
    )

if qr_payload.lower().startswith("http://"):
    xai.append(
        "QR destination uses unencrypted HTTP."
    )

assessment["xai"] = xai

return {
    "status": "success",
    "input_type": "qr",
    "scan_id": str(uuid.uuid4()),
    "payload_type": "url",
    "extracted_payload": qr_payload,
    "trace": {
        "original_url": qr_payload,
        "final_url": final_url,
        "hops": chain,
    },
    "assessment": assessment,
    "metadata": {
        "domain": final_domain,
        "typosquat_similarity": typo_score,
        "suspicious_tld": tld_hit,
        "redirect_hops": len(chain),
    },
}

    finally:

        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except OSError:
                pass


# ============================================================
# ROOT / HEALTH CHECK
# ============================================================

@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "CYBERGUARD X",
        "version": "1.1.0",
        "engine": "Core Threat Analysis Engine",
        "features": [
            "URL threat scanning",
            "Redirect chain analysis",
            "Typosquatting detection",
            "Suspicious TLD detection",
            "SMS / Email analysis",
            "UPI scam signal detection",
            "QR / Quishing analysis",
            "Explainable AI",
            "Multi-signal risk scoring",
        ],
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "cyberguard-x-backend",
        "risk_engine": "available",
    }
