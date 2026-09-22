import asyncio
import ipaddress
import os
import shutil
import socket
import sys
import uuid
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import cv2
import requests
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
# RISK ENGINE
# ============================================================

try:
    from ai.risk_engine import CyberGuardRiskEngine, ThreatSignals
except ImportError as exc:
    raise RuntimeError(
        "Could not import ai.risk_engine. Make sure ai/risk_engine.py exists."
    ) from exc

app = FastAPI(
    title="CYBERGUARD X — Advanced Threat Detection Platform",
    description=(
        "CyberGuard X backend for URL, text, QR and multi-signal "
        "cyber threat analysis."
    ),
    version="2.0.0",
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
    "sbi", "hdfc", "icici", "axis", "kotak",
    "paytm", "phonepe", "google", "microsoft",
    "apple", "amazon", "netflix", "incometax", "paypal",
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".su", ".click", ".work", ".zip", ".mov",
}

URGENCY_KEYWORDS = [
    "urgent", "immediately", "verify now", "act now",
    "account blocked", "account suspended", "suspended",
    "blocked", "verify", "kyc", "kyc update", "otp",
    "refund", "winner", "lottery", "prize", "claim now",
]

UPI_HANDLES = [
    "@ybl", "@okaxis", "@oksbi", "@okhdfcbank",
    "@paytm", "@ibl", "@axl",
]

MAX_REDIRECT_HOPS = 10
MAX_PAGE_REQUESTS = 80

# ============================================================
# REQUEST MODELS
# ============================================================

class URLScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)


class TextScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)

# ============================================================
# BASIC HELPERS
# ============================================================

def normalize_url(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        raise ValueError("URL cannot be empty.")
    if len(value) > 4096:
        raise ValueError("URL is too long.")
    return value


def get_hostname(target_url: str) -> str:
    try:
        return (urlparse(target_url).hostname or "").lower().strip().rstrip(".")
    except Exception:
        return ""


def is_http_url(target_url: str) -> bool:
    try:
        parsed = urlparse(target_url)
        return parsed.scheme.lower() in {"http", "https"} and bool(parsed.hostname)
    except Exception:
        return False


# ============================================================
# SSRF / NETWORK SAFETY
# ============================================================

def resolve_hostname(hostname: str) -> list[str]:
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
                    pass
    except (socket.gaierror, OSError):
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
            ]
        )
    except ValueError:
        return False


def is_safe_target(target_url: str) -> bool:
    if not is_http_url(target_url):
        return False

    hostname = get_hostname(target_url)
    if not hostname:
        return False

    try:
        direct_ip = ipaddress.ip_address(hostname)
        return is_public_ip(str(direct_ip))
    except ValueError:
        pass

    addresses = resolve_hostname(hostname)
    return bool(addresses) and all(is_public_ip(address) for address in addresses)


# ============================================================
# ADVANCED URL INTELLIGENCE
# ============================================================

def advanced_typosquat_analysis(domain: str) -> dict[str, Any]:
    domain = str(domain or "").lower().strip().rstrip(".")
    if not domain:
        return {
            "score": 0.0,
            "matched_brand": None,
            "technique": None,
            "signals": [],
        }

    labels = domain.split(".")
    main_domain = labels[-2] if len(labels) >= 2 else labels[0]
    score = 0.0
    matched_brand = None
    technique = None
    signals: list[str] = []

    for brand in MONITORED_BRANDS:
        if main_domain == brand:
            continue

        similarity = SequenceMatcher(None, main_domain, brand).ratio()
        candidate = main_domain
        detected_technique = None

        if brand in candidate and candidate != brand:
            detected_technique = "brand_insertion"
        elif candidate.startswith(brand) or candidate.endswith(brand):
            detected_technique = "brand_extension"
        elif len(candidate) == len(brand) + 1:
            if any(
                candidate[:i] + candidate[i + 1:] == brand
                for i in range(len(candidate))
            ):
                detected_technique = "character_insertion"
        elif len(candidate) == len(brand) - 1:
            if any(
                brand[:i] + brand[i + 1:] == candidate
                for i in range(len(brand))
            ):
                detected_technique = "character_deletion"

        if similarity >= 0.78 or detected_technique:
            effective_score = max(
                similarity,
                0.80 if detected_technique else similarity,
            )
            if effective_score > score:
                score = effective_score
                matched_brand = brand
                technique = detected_technique or "high_similarity"

    if "xn--" in main_domain:
        signals.append("Punycode/IDN hostname detected.")

    if main_domain.count("-") >= 2:
        signals.append("Multiple hyphens in the registrable hostname.")

    if main_domain.isdigit():
        signals.append("Numeric-only hostname label detected.")

    if matched_brand:
        signals.append(
            f"Hostname resembles monitored brand '{matched_brand}'."
        )

    return {
        "score": round(min(score, 1.0), 3),
        "matched_brand": matched_brand,
        "technique": technique,
        "signals": signals,
    }


def advanced_url_obfuscation(target_url: str) -> dict[str, Any]:
    findings: list[str] = []
    risk = 0.0

    parsed = urlparse(target_url)
    hostname = get_hostname(target_url)
    decoded = unquote(target_url)

    if parsed.username or parsed.password or "@" in target_url:
        findings.append(
            "URL contains user-info/@ syntax that can obscure the destination."
        )
        risk = max(risk, 0.85)

    if "%" in target_url:
        findings.append("Percent-encoded characters are present in the URL.")
        risk = max(risk, 0.35)

    if target_url.lower().startswith("http://"):
        findings.append("URL uses unencrypted HTTP.")
        risk = max(risk, 0.45)

    if target_url.count("//") > 1:
        findings.append("Multiple protocol separators are present.")
        risk = max(risk, 0.55)

    if len(target_url) > 180:
        findings.append("URL is unusually long.")
        risk = max(risk, 0.30)

    if target_url.count(".") >= 5:
        findings.append("URL contains many subdomain levels.")
        risk = max(risk, 0.40)

    if hostname.startswith("xn--") or ".xn--" in hostname:
        findings.append("Punycode hostname detected.")
        risk = max(risk, 0.50)

    try:
        ipaddress.ip_address(hostname)
        findings.append(
            "Destination uses a literal IP address instead of a domain."
        )
        risk = max(risk, 0.55)
    except ValueError:
        pass

    if decoded != target_url:
        findings.append("URL changes after percent-decoding.")
        risk = max(risk, 0.40)

    if len(parsed.query) > 800:
        findings.append("URL query string is unusually large.")
        risk = max(risk, 0.25)

    return {
        "score": round(min(risk, 1.0), 3),
        "findings": findings,
    }


def domain_age_signal(age_days: int | None) -> float:
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
    """Fetch domain registration information from RDAP."""

    if not domain:
        return None, None, "unavailable"

    def fetch() -> tuple[int | None, str | None, str]:
        try:
            response = requests.get(
                f"https://rdap.org/domain/{domain}",
                headers={"Accept": "application/rdap+json"},
                timeout=8,
            )

            if response.status_code != 200:
                return None, None, "rdap_unavailable"

            data = response.json()
            registration_date = None

            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    registration_date = event.get("eventDate")
                    break

            if not registration_date:
                return None, None, "registration_date_unavailable"

            from datetime import datetime, timezone

            registered_at = datetime.fromisoformat(
                registration_date.replace("Z", "+00:00")
            )

            age_days = max(
                0,
                (datetime.now(timezone.utc) - registered_at).days,
            )

            return age_days, registration_date, "rdap.org"

        except Exception:
            return None, None, "rdap_error"

    return await asyncio.to_thread(fetch)


def detect_suspicious_tld(domain: str) -> bool:
    domain = str(domain or "").lower().rstrip(".")
    return any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)


def detect_url_obfuscation(target_url: str) -> list[str]:
    return advanced_url_obfuscation(target_url)["findings"]


def detect_urgency(text: str) -> tuple[float, list[str]]:
    lowered = text.lower()
    matched = [word for word in URGENCY_KEYWORDS if word in lowered]
    return min(len(matched) * 0.20, 1.0), matched


def detect_upi_signals(text: str) -> tuple[int, list[str]]:
    lowered = text.lower()
    findings: list[str] = []

    if "upi://" in lowered:
        findings.append("UPI URI detected.")

    for handle in UPI_HANDLES:
        if handle in lowered:
            findings.append(f"UPI handle pattern detected: {handle}")

    return (1 if findings else 0), findings


def detect_brand_mentions(text: str) -> list[str]:
    lowered = text.lower()
    return [brand for brand in MONITORED_BRANDS if brand in lowered]


# ============================================================
# REDIRECT INTELLIGENCE
# ============================================================

async def trace_url_hops(
    target_url: str,
) -> tuple[list[dict[str, Any]], str]:
    redirect_chain: list[dict[str, Any]] = []
    final_url = target_url
    request_count = 0

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"],
        )

        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            )
        )

        page = await context.new_page()

        async def guard_route(route):
            nonlocal request_count
            request_count += 1

            if request_count > MAX_PAGE_REQUESTS:
                await route.abort()
                return

            url = route.request.url

            if is_http_url(url) and not is_safe_target(url):
                await route.abort()
                return

            await route.continue_()

        async def handle_response(response):
            if response.status in {301, 302, 303, 307, 308}:
                if len(redirect_chain) < MAX_REDIRECT_HOPS:
                    redirect_chain.append(
                        {
                            "url": response.url,
                            "status": response.status,
                        }
                    )

        await page.route("**/*", guard_route)
        page.on("response", handle_response)

        try:
            await page.goto(
                target_url,
                wait_until="domcontentloaded",
                timeout=12000,
            )
            final_url = page.url or target_url
        except Exception:
            final_url = page.url or target_url
        finally:
            await browser.close()

    return redirect_chain, final_url


# ============================================================
# RISK ENGINE ADAPTER
# ============================================================

def evaluate_signals(signals: ThreatSignals) -> Any:
    try:
        return risk_engine.evaluate(signals)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Risk engine evaluation failed. Check ai/risk_engine.py.",
        ) from exc


def normalize_assessment(assessment: Any) -> dict[str, Any]:
    if isinstance(assessment, dict):
        score = assessment.get("score")
        if score is None:
            score = assessment.get("risk_score", 0)

        try:
            score = float(score)
        except (TypeError, ValueError):
            score = 0.0

        score = max(0.0, min(100.0, score))

        xai = (
            assessment.get("xai")
            or assessment.get("xai_breakdown")
            or assessment.get("explainability")
            or []
        )

        return {
            **assessment,
            "score": round(score, 2),
            "risk_score": round(score, 2),
            "severity": str(assessment.get("severity") or "LOW").upper(),
            "explanation": str(
                assessment.get("explanation")
                or "Risk assessment completed."
            ),
            "xai": xai,
        }

    return {
        "score": 0.0,
        "risk_score": 0.0,
        "severity": "LOW",
        "explanation": "Risk assessment completed.",
        "xai": [],
    }


def append_xai(assessment: dict[str, Any], items: list[str]) -> None:
    current = assessment.get("xai")
    xai = list(current) if isinstance(current, list) else []

    for item in items:
        if item and item not in xai:
            xai.append(item)

    assessment["xai"] = xai


# ============================================================
# URL SCANNER
# ============================================================

@app.post("/scan/url")
async def scan_url(request: URLScanRequest):
    target_url = normalize_url(request.url)

    if not is_http_url(target_url):
        raise HTTPException(
            status_code=400,
            detail="Only valid HTTP/HTTPS URLs are supported.",
        )

    if not is_safe_target(target_url):
        raise HTTPException(
            status_code=400,
            detail=(
                "Security Exception: target resolves to a restricted "
                "or non-public network address."
            ),
        )

    chain, final_url = await trace_url_hops(target_url)

    if not is_safe_target(final_url):
        raise HTTPException(
            status_code=400,
            detail=(
                "Security Exception: redirect destination resolves "
                "to a restricted or non-public target."
            ),
        )

    final_domain = get_hostname(final_url) or get_hostname(target_url)

    typo_analysis = advanced_typosquat_analysis(final_domain)
    typo_score = typo_analysis["score"]

    tld_hit = detect_suspicious_tld(final_domain)
    advanced_obfuscation = advanced_url_obfuscation(final_url)

    domain_age_days, registration_date, age_source = (
        await get_domain_registration_age(final_domain)
    )

    urgency_score, urgency_matches = detect_urgency(target_url)
    upi_flag, upi_findings = detect_upi_signals(target_url)

    protocol_insecure = target_url.lower().startswith("http://")

    ioc_hits = 0

    if tld_hit:
        ioc_hits += 1
    if typo_score >= 0.78:
        ioc_hits += 1
    if len(chain) >= 2:
        ioc_hits += 1
    if advanced_obfuscation["score"] >= 0.60:
        ioc_hits += 1

    signals = ThreatSignals(
        domain_age_days=domain_age_signal(domain_age_days),
        redirect_hops=len(chain),
        typosquat_similarity=typo_score,
        nlp_urgency_score=urgency_score,
        auth_failure_flag=int(protocol_insecure),
        visual_brand_spoof=typo_score,
        external_ioc_hits=min(ioc_hits, 3),
        upi_anomaly_flag=upi_flag,
    )

    assessment = normalize_assessment(
        evaluate_signals(signals)
    )

    extra_xai: list[str] = []
    extra_xai.extend(urgency_matches)
    extra_xai.extend(upi_findings)
    extra_xai.extend(advanced_obfuscation["findings"])
    extra_xai.extend(typo_analysis["signals"])

    if tld_hit:
        extra_xai.append(
            f"Suspicious TLD pattern detected on {final_domain}."
        )

    if len(chain) >= 2:
        extra_xai.append(
            f"Multiple redirects detected: {len(chain)} hop(s)."
        )

    if domain_age_days is not None and domain_age_days < 90:
        extra_xai.append(
            f"Domain registration age is approximately {domain_age_days} day(s)."
        )

    append_xai(assessment, extra_xai)

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
            "domain_age_days": domain_age_days,
            "registration_date": registration_date,
            "age_source": age_source,
            "typosquat_similarity": typo_score,
            "typosquat": typo_analysis,
            "suspicious_tld": tld_hit,
            "obfuscation": advanced_obfuscation,
            "redirect_hops": len(chain),
            "ioc_indicator_count": ioc_hits,
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

    urgency_score, urgency_matches = detect_urgency(content)
    upi_flag, upi_findings = detect_upi_signals(content)
    brand_mentions = detect_brand_mentions(content)

    signals = ThreatSignals(
        domain_age_days=0.0,
        redirect_hops=0,
        typosquat_similarity=0.75 if brand_mentions else 0.0,
        nlp_urgency_score=urgency_score,
        auth_failure_flag=0,
        visual_brand_spoof=0.0,
        external_ioc_hits=0,
        upi_anomaly_flag=upi_flag,
    )

    assessment = normalize_assessment(
        evaluate_signals(signals)
    )

    extra_xai: list[str] = []

    if urgency_matches:
        extra_xai.append(
            "Urgency/social-engineering indicators: "
            + ", ".join(urgency_matches)
        )

    if brand_mentions:
        extra_xai.append(
            "Monitored brand mentioned: "
            + ", ".join(brand_mentions)
        )

    extra_xai.extend(upi_findings)
    append_xai(assessment, extra_xai)

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
async def scan_quishing(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file provided.",
        )

    allowed_types = {"image/png", "image/jpeg", "image/webp"}

    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="Unsupported image type. Use PNG, JPEG or WEBP.",
        )

    safe_filename = os.path.basename(file.filename)[:100]
    temp_file = os.path.join(
        "/tmp",
        f"cyberguard_qr_{uuid.uuid4().hex}_{safe_filename}",
    )

    try:
        with open(temp_file, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        image = cv2.imread(temp_file)

        if image is None:
            raise HTTPException(
                status_code=400,
                detail="Invalid image file.",
            )

        qr_detector = cv2.QRCodeDetector()
        qr_payload, _, _ = qr_detector.detectAndDecode(image)

        if not qr_payload:
            return {
                "status": "error",
                "input_type": "qr",
                "scan_id": str(uuid.uuid4()),
                "message": "No valid QR code payload detected.",
            }

        qr_payload = qr_payload.strip()
        payload_lower = qr_payload.lower()

        is_url = payload_lower.startswith(("http://", "https://"))
        is_upi = payload_lower.startswith("upi://")

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
                        "QR payload was decoded successfully but is not "
                        "an HTTP/HTTPS URL or UPI URI."
                    ),
                    "xai": [
                        "QR payload successfully decoded.",
                        "Payload classified as plain text.",
                    ],
                },
            }

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

            assessment = normalize_assessment(
                evaluate_signals(upi_signals)
            )

            append_xai(
                assessment,
                ["QR payload contains a UPI URI."],
            )

            return {
                "status": "success",
                "input_type": "qr",
                "scan_id": str(uuid.uuid4()),
                "payload_type": "upi",
                "extracted_payload": qr_payload,
                "assessment": assessment,
            }

        if not is_safe_target(qr_payload):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Security Exception: QR URL resolves to a "
                    "restricted or unsafe target."
                ),
            )

        chain, final_url = await trace_url_hops(qr_payload)

        if not is_safe_target(final_url):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Security Exception: QR redirect destination "
                    "resolves to a restricted or unsafe target."
                ),
            )

        final_domain = get_hostname(final_url) or get_hostname(qr_payload)

        typo_analysis = advanced_typosquat_analysis(final_domain)
        typo_score = typo_analysis["score"]
        tld_hit = detect_suspicious_tld(final_domain)
        advanced_obfuscation = advanced_url_obfuscation(final_url)

        domain_age_days, registration_date, age_source = (
            await get_domain_registration_age(final_domain)
        )

        ioc_hits = 0

        if tld_hit:
            ioc_hits += 1
        if typo_score >= 0.78:
            ioc_hits += 1
        if len(chain) >= 2:
            ioc_hits += 1
        if advanced_obfuscation["score"] >= 0.60:
            ioc_hits += 1

        signals = ThreatSignals(
            domain_age_days=domain_age_signal(domain_age_days),
            redirect_hops=len(chain),
            typosquat_similarity=typo_score,
            nlp_urgency_score=0.2,
            auth_failure_flag=int(payload_lower.startswith("http://")),
            visual_brand_spoof=typo_score,
            external_ioc_hits=min(ioc_hits, 3),
            upi_anomaly_flag=0,
        )

        assessment = normalize_assessment(
            evaluate_signals(signals)
        )

        extra_xai: list[str] = []
        extra_xai.extend(advanced_obfuscation["findings"])
        extra_xai.extend(typo_analysis["signals"])

        if tld_hit:
            extra_xai.append(
                f"Suspicious TLD pattern detected on {final_domain}."
            )

        if len(chain) >= 2:
            extra_xai.append(
                f"Multiple redirects detected: {len(chain)} hop(s)."
            )

        if domain_age_days is not None and domain_age_days < 90:
            extra_xai.append(
                f"Domain registration age is approximately {domain_age_days} day(s)."
            )

        append_xai(assessment, extra_xai)

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
                "domain_age_days": domain_age_days,
                "registration_date": registration_date,
                "age_source": age_source,
                "typosquat_similarity": typo_score,
                "typosquat": typo_analysis,
                "suspicious_tld": tld_hit,
                "obfuscation": advanced_obfuscation,
                "redirect_hops": len(chain),
                "ioc_indicator_count": ioc_hits,
            },
        }

    finally:
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except OSError:
                pass


# ============================================================
# ROOT / HEALTH
# ============================================================

@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "CYBERGUARD X",
        "version": "2.0.0",
        "engine": "Core Threat Analysis Engine",
        "features": [
            "URL threat scanning",
            "Advanced redirect intelligence",
            "Final redirect safety validation",
            "RDAP domain registration age",
            "Advanced typosquatting detection",
            "URL obfuscation detection",
            "Suspicious TLD detection",
            "SMS / Email analysis",
            "UPI scam signal detection",
            "QR / Quishing analysis",
            "Explainable AI",
            "Multi-signal risk scoring",
            "SSRF protection",
        ],
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "cyberguard-x-backend",
        "risk_engine": "available",
        "advanced_url_intelligence": "enabled",
    }
