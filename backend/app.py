import os
import sys
import shutil
from pathlib import Path
from urllib.parse import urlparse

import cv2
from pyzbar.pyzbar import decode
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from playwright.async_api import async_playwright

# Root directory ko path me add karke AI engine import karna
sys.path.append(str(Path(__file__).resolve().parent.parent))
from ai.risk_engine import CyberGuardRiskEngine, ThreatSignals

app = FastAPI(title="CYBERGUARD X — Core Engine")
risk_engine = CyberGuardRiskEngine()

# Frontend (GitHub Pages / Localhost) ko allow karna
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    chain, final_url = await trace_url_hops(target_url)
    
    final_lower = final_url.lower()
    target_lower = target_url.lower()

    # Feature extraction for AI Risk Engine
    typo = 0.9 if any(brand in final_lower and not f"{brand}.com" in final_lower and not f"{brand}.in" in final_lower for brand in ["sbi", "hdfc", "microsoft", "paytm"]) else 0.0
    upi_flag = 1 if ("upi://" in final_lower or "@ok" in final_lower or "@apl" in final_lower) else 0
    urgency = 0.85 if any(w in target_lower for w in ["urgent", "immediately", "verify", "kyc", "suspended", "blocked"]) else 0.1
    tld_hit = 1 if any(final_lower.endswith(tld) for tld in [".xyz", ".top", ".su", ".click", ".me"]) else 0

    signals = ThreatSignals(
        domain_age_days=0.9 if tld_hit else 0.2,
        redirect_hops=len(chain),
        typosquat_similarity=typo,
        nlp_urgency_score=urgency,
        auth_failure_flag=0,
        visual_brand_spoof=0.0,
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

@app.post("/scan/quishing")
async def scan_quishing(file: UploadFile = File(...)):
    temp_file = f"temp_{file.filename}"
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
                            
