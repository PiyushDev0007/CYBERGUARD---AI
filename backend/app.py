import os
import sys
import shutil
import socket
import ipaddress
from pathlib import Path
from urllib.parse import urlparse
from difflib import SequenceMatcher

import cv2
from pyzbar.pyzbar import decode
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from playwright.async_api import async_playwright

# AI Risk Engine import
sys.path.append(str(Path(__file__).resolve().parent.parent))
from ai.risk_engine import CyberGuardRiskEngine, ThreatSignals

app = FastAPI(title="CYBERGUARD X — Core Engine")
risk_engine = CyberGuardRiskEngine()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MONITORED_BRANDS = ["sbi", "hdfc", "icici", "paytm", "microsoft", "google", "netflix", "amazon", "incometax"]

def is_safe_target(target_url: str) -> bool:
    """SSRF Guard: Private IPs, loopbacks aur cloud metadata block karta hai"""
    try:
        host = urlparse(target_url).hostname
        if not host:
            return False
        ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
    except Exception:
        return False

def calculate_typosquat(domain: str) -> float:
    """Levenshtein ratio based brand spoofing detection"""
    main_domain = domain.split(".")[0]
    max_score = 0.0
    for brand in MONITORED_BRANDS:
        if brand == main_domain:
            return 0.0  # Legitimate official domain
        similarity = SequenceMatcher(None, main_domain, brand).ratio()
        if similarity > 0.65 or brand in main_domain:
            max_score = max(max_score, similarity)
    return max_score

async def trace_url_hops(target_url: str):
    redirect_chain = []
    final_url = target_url

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        page = await context.new_page()

        def handle_response(response):
            if response.status in [301, 302, 303, 307, 308]:
                redirect_chain.append({
                    "url": response.url,
                    "status": response.status
                })

        page.on("response", handle_response)

        try:
            await page.goto(target_url, wait_until="networkidle", timeout=12000)
            final_url = page.url
        except Exception:
            final_url = target_url
        finally:
            await browser.close()

    return redirect_chain, final_url

@app.post("/scan/url")
async def scan_url(target_url: str = Form(...)):
    if not is_safe_target(target_url):
        raise HTTPException(status_code=400, detail="Security Exception: Restricted, private IP or loopback address.")

    chain, final_url = await trace_url_hops(target_url)
    
    parsed = urlparse(final_url)
    domain = (parsed.netloc or target_url).lower()
    target_lower = target_url.lower()

    typo_score = calculate_typosquat(domain)
    upi_flag = 1 if ("upi://" in final_url.lower() or "@ok" in final_url.lower() or "@apl" in final_url.lower()) else 0
    urgency_words = ["urgent", "immediately", "verify", "kyc", "suspended", "blocked", "refund", "otp"]
    urgency = 0.85 if any(w in target_lower for w in urgency_words) else 0.1
    tld_hit = 1 if any(domain.endswith(tld) for tld in [".xyz", ".top", ".su", ".click", ".me", ".work"]) else 0

    signals = ThreatSignals(
        domain_age_days=0.9 if tld_hit else 0.2,
        redirect_hops=len(chain),
        typosquat_similarity=typo_score,
        nlp_urgency_score=urgency,
        auth_failure_flag=1 if not target_url.startswith("https://") else 0,
        visual_brand_spoof=typo_score,
        external_ioc_hits=1 if (len(chain) >= 2 or tld_hit) else 0,
        upi_anomaly_flag=upi_flag
    )

    assessment = risk_engine.evaluate(signals)

    return {
        "status": "success",
        "trace": {
            "final_url": final_url,
            "hops_detail": chain
        },
        "assessment": assessment
    }

@app.post("/scan/text")
async def scan_text(content: str = Form(...)):
    content_lower = content.lower()
    urgency_keywords = ["urgent", "immediately", "blocked", "suspended", "lottery", "winner", "prize", "otp", "kyc update"]
    
    matched = sum(1 for w in urgency_keywords if w in content_lower)
    urgency_score = min(matched * 0.25, 1.0)
    upi_anomaly = 1 if any(h in content_lower for h in ["@ybl", "@okaxis", "@paytm", "upi://"]) else 0
    
    signals = ThreatSignals(
        domain_age_days=0.0,
        redirect_hops=0,
        typosquat_similarity=0.75 if any(b in content_lower for b in MONITORED_BRANDS) else 0.0,
        nlp_urgency_score=urgency_score,
        auth_failure_flag=0,
        visual_brand_spoof=0.0,
        external_ioc_hits=0,
        upi_anomaly_flag=upi_anomaly
    )
    
    assessment = risk_engine.evaluate(signals)
    return {
        "status": "success",
        "input_type": "text/sms",
        "assessment": assessment
    }

@app.post("/scan/quishing")
async def scan_quishing(file: UploadFile = File(...)):
    temp_file = os.path.join("/tmp", f"temp_{file.filename}")
    with open(temp_file, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        img = cv2.imread(temp_file)
        if img is None:
            return {"status": "error", "message": "Invalid image format"}

        decoded = decode(img)
        if not decoded:
            return {"status": "error", "message": "No valid QR code payload detected."}
        
        qr_url = decoded[0].data.decode("utf-8")
        
        if not is_safe_target(qr_url):
            raise HTTPException(status_code=400, detail="Security Exception: QR target is restricted.")

        chain, final_url = await trace_url_hops(qr_url)

        upi_flag = 1 if "upi://" in final_url.lower() else 0
        signals = ThreatSignals(
            domain_age_days=0.8,
            redirect_hops=len(chain),
            typosquat_similarity=0.5,
            nlp_urgency_score=0.7,
            auth_failure_flag=0,
            visual_brand_spoof=0.8,
            external_ioc_hits=1,
            upi_anomaly_flag=upi_flag
        )

        assessment = risk_engine.evaluate(signals)

        return {
            "status": "success",
            "extracted_payload": qr_url,
            "trace": {
                "final_url": final_url,
                "hops_detail": chain
            },
            "assessment": assessment
        }
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
