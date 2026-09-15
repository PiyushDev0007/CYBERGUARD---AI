import ipaddress
import os
import shutil
import socket
import sys
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import urlparse

import cv2
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from playwright.async_api import async_playwright

# -------------------------------------------------------------------
# AI Risk Engine
# -------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from ai.risk_engine import CyberGuardRiskEngine, ThreatSignals


# -------------------------------------------------------------------
# FastAPI Application
# -------------------------------------------------------------------

app = FastAPI(
    title="CYBERGUARD X — Core Engine",
    version="1.0.0",
)

risk_engine = CyberGuardRiskEngine()


# -------------------------------------------------------------------
# CORS
# -------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------------------------------------------------------------------
# Monitored Brands
# -------------------------------------------------------------------

MONITORED_BRANDS = [
    "sbi",
    "hdfc",
    "icici",
    "paytm",
    "microsoft",
    "google",
    "netflix",
    "amazon",
    "incometax",
]


# -------------------------------------------------------------------
# Security Helpers
# -------------------------------------------------------------------

def is_safe_target(target_url: str) -> bool:
    """
    Basic SSRF protection.

    Blocks:
    - private IP addresses
    - loopback addresses
    - reserved addresses
    - link-local addresses
    """

    try:
        parsed = urlparse(target_url)

        if parsed.scheme not in {"http", "https"}:
            return False

        host = parsed.hostname

        if not host:
            return False

        ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip)

        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
        )

    except Exception:
        return False


def calculate_typosquat(domain: str) -> float:
    """
    Basic brand-similarity detection.

    Returns a value between 0.0 and 1.0.
    """

    domain = domain.lower().strip()

    # Remove port if present and isolate the first hostname label.
    main_domain = domain.split(".")[0]

    max_score = 0.0

    for brand in MONITORED_BRANDS:

        # Exact monitored brand match is not treated as typosquatting.
        if brand == main_domain:
            continue

        similarity = SequenceMatcher(
            None,
            main_domain,
            brand,
        ).ratio()

        if similarity > 0.65 or brand in main_domain:
            max_score = max(max_score, similarity)

    return round(max_score, 3)


async def trace_url_hops(target_url: str):
    """
    Uses Playwright Chromium to inspect the URL navigation
    and record HTTP redirect responses.
    """

    redirect_chain = []
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
            if response.status in {301, 302, 303, 307, 308}:
                redirect_chain.append(
                    {
                        "url": response.url,
                        "status": response.status,
                    }
                )

        page.on("response", handle_response)

        try:
            await page.goto(
                target_url,
                wait_until="networkidle",
                timeout=12000,
            )

            final_url = page.url

        except Exception:
            # Do not expose internal browser errors to the user.
            final_url = target_url

        finally:
            await browser.close()

    return redirect_chain, final_url


# -------------------------------------------------------------------
# URL Scanner
# -------------------------------------------------------------------

@app.post("/scan/url")
async def scan_url(target_url: str = Form(...)):

    target_url = target_url.strip()

    if not target_url:
        raise HTTPException(
            status_code=400,
            detail="URL cannot be empty.",
        )

    if not is_safe_target(target_url):
        raise HTTPException(
            status_code=400,
            detail=(
                "Security Exception: Restricted, private IP, "
                "loopback or unsupported URL."
            ),
        )

    chain, final_url = await trace_url_hops(target_url)

    parsed = urlparse(final_url)

    domain = (
        parsed.hostname
        or urlparse(target_url).hostname
        or ""
    ).lower()

    target_lower = target_url.lower()

    # ---------------------------------------------------------------
    # URL Signals
    # ---------------------------------------------------------------

    typo_score = calculate_typosquat(domain)

    upi_flag = int(
        "upi://" in final_url.lower()
        or "@ok" in final_url.lower()
        or "@apl" in final_url.lower()
    )

    urgency_words = [
        "urgent",
        "immediately",
        "verify",
        "kyc",
        "suspended",
        "blocked",
        "refund",
        "otp",
    ]

    urgency = (
        0.85
        if any(word in target_lower for word in urgency_words)
        else 0.10
    )

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".su",
        ".click",
        ".me",
        ".work",
    ]

    tld_hit = int(
        any(domain.endswith(tld) for tld in suspicious_tlds)
    )

    # ---------------------------------------------------------------
    # Threat Signals
    # ---------------------------------------------------------------

    signals = ThreatSignals(
        # Current implementation uses this as a novelty proxy,
        # not actual WHOIS/domain-age data.
        domain_age_days=0.9 if tld_hit else 0.2,

        redirect_hops=len(chain),

        typosquat_similarity=typo_score,

        nlp_urgency_score=urgency,

        # This represents insecure transport in the current MVP.
        # It is NOT a DMARC/SPF result.
        auth_failure_flag=int(
            not target_url.startswith("https://")
        ),

        visual_brand_spoof=typo_score,

        # Current MVP proxy, not a live external threat feed.
        external_ioc_hits=int(
            len(chain) >= 2 or tld_hit
        ),

        upi_anomaly_flag=upi_flag,
    )

    assessment = risk_engine.evaluate(signals)

    return {
        "status": "success",
        "input_type": "url",
        "trace": {
            "original_url": target_url,
            "final_url": final_url,
            "hops_detail": chain,
        },
        "assessment": assessment,
    }


# -------------------------------------------------------------------
# Text / SMS / Email Scanner
# -------------------------------------------------------------------

@app.post("/scan/text")
async def scan_text(content: str = Form(...)):

    content = content.strip()

    if not content:
        raise HTTPException(
            status_code=400,
            detail="Text content cannot be empty.",
        )

    content_lower = content.lower()

    urgency_keywords = [
        "urgent",
        "immediately",
        "blocked",
        "suspended",
        "lottery",
        "winner",
        "prize",
        "otp",
        "kyc update",
    ]

    matched = sum(
        1
        for word in urgency_keywords
        if word in content_lower
    )

    urgency_score = min(
        matched * 0.25,
        1.0,
    )

    upi_anomaly = int(
        any(
            handle in content_lower
            for handle in [
                "@ybl",
                "@okaxis",
                "@paytm",
                "upi://",
            ]
        )
    )

    brand_impersonation = int(
        any(
            brand in content_lower
            for brand in MONITORED_BRANDS
        )
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

        upi_anomaly_flag=upi_anomaly,
    )

    assessment = risk_engine.evaluate(signals)

    return {
        "status": "success",
        "input_type": "text/sms/email",
        "assessment": assessment,
    }


# -------------------------------------------------------------------
# QR / Quishing Scanner
# -------------------------------------------------------------------

@app.post("/scan/quishing")
async def scan_quishing(file: UploadFile = File(...)):

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file provided.",
        )

    # Keep the temporary filename simple and predictable.
    safe_filename = os.path.basename(file.filename)

    temp_file = os.path.join(
        "/tmp",
        f"cyberguard_qr_{safe_filename}",
    )

    try:

        # -----------------------------------------------------------
        # Save uploaded image
        # -----------------------------------------------------------

        with open(temp_file, "wb") as buffer:
            shutil.copyfileobj(
                file.file,
                buffer,
            )

        # -----------------------------------------------------------
        # Read image using OpenCV
        # -----------------------------------------------------------

        image = cv2.imread(temp_file)

        if image is None:
            raise HTTPException(
                status_code=400,
                detail="Invalid image format.",
            )

        # -----------------------------------------------------------
        # Detect and decode QR
        # -----------------------------------------------------------

        qr_detector = cv2.QRCodeDetector()

        qr_payload, points, _ = (
            qr_detector.detectAndDecode(image)
        )

        if not qr_payload:
            return {
                "status": "error",
                "input_type": "qr",
                "message": (
                    "No valid QR code payload detected."
                ),
            }

        qr_payload = qr_payload.strip()

        # -----------------------------------------------------------
        # QR payload classification
        # -----------------------------------------------------------

        payload_lower = qr_payload.lower()

        is_url = payload_lower.startswith(
            ("http://", "https://")
        )

        is_upi = payload_lower.startswith("upi://")

        # -----------------------------------------------------------
        # Non-URL QR payload
        # -----------------------------------------------------------

        if not is_url and not is_upi:
            return {
                "status": "success",
                "input_type": "qr",
                "payload_type": "text",
                "extracted_payload": qr_payload,
                "assessment": {
                    "risk_score": 0.0,
                    "severity": "LOW",
                    "xai_breakdown": [
                        "QR payload was decoded successfully.",
                        "Payload is not an HTTP/HTTPS URL or UPI URI.",
                    ],
                },
            }

        # -----------------------------------------------------------
        # UPI QR payload
        # -----------------------------------------------------------

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

            assessment = risk_engine.evaluate(
                upi_signals
            )

            return {
                "status": "success",
                "input_type": "qr",
                "payload_type": "upi",
                "extracted_payload": qr_payload,
                "assessment": assessment,
            }

        # -----------------------------------------------------------
        # URL safety check
        # -----------------------------------------------------------

        if not is_safe_target(qr_payload):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Security Exception: QR target is "
                    "restricted or unsafe."
                ),
            )

        # -----------------------------------------------------------
        # Redirect tracing
        # -----------------------------------------------------------

        chain, final_url = await trace_url_hops(
            qr_payload
        )

        final_lower = final_url.lower()

        upi_flag = int(
            "upi://" in final_lower
        )

        final_domain = (
            urlparse(final_url).hostname
            or ""
        ).lower()

        typo_score = calculate_typosquat(
            final_domain
        )

        suspicious_tlds = [
            ".xyz",
            ".top",
            ".su",
            ".click",
            ".me",
            ".work",
        ]

        tld_hit = int(
            any(
                final_domain.endswith(tld)
                for tld in suspicious_tlds
            )
        )

        signals = ThreatSignals(
            # MVP proxy only — not actual domain-age intelligence.
            domain_age_days=0.8 if tld_hit else 0.2,

            redirect_hops=len(chain),

            typosquat_similarity=typo_score,

            nlp_urgency_score=0.2,

            auth_failure_flag=int(
                not qr_payload.startswith("https://")
            ),

            visual_brand_spoof=typo_score,

            # MVP proxy only — not a live threat-feed result.
            external_ioc_hits=int(
                len(chain) >= 2 or tld_hit
            ),

            upi_anomaly_flag=upi_flag,
        )

        assessment = risk_engine.evaluate(
            signals
        )

        return {
            "status": "success",
            "input_type": "qr",
            "payload_type": "url",
            "extracted_payload": qr_payload,
            "trace": {
                "final_url": final_url,
                "hops_detail": chain,
            },
            "assessment": assessment,
        }

    finally:

        # -----------------------------------------------------------
        # Cleanup temporary file
        # -----------------------------------------------------------

        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except OSError:
                pass


# -------------------------------------------------------------------
# Health Check
# -------------------------------------------------------------------

@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "CYBERGUARD X",
        "engine": "Core Threat Analysis Engine",
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
}
