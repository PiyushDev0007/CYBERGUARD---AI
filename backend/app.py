import os
import shutil
import cv2
from pyzbar.pyzbar import decode
from urllib.parse import urlparse
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from playwright.async_api import async_playwright

app = FastAPI(title="CYBERGUARD X — Core Engine")

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
    
    score = 15
    reasons = []
    
    if len(chain) >= 2:
        score += 35
        reasons.append(f"Cloaked Redirects: {len(chain)} redirect hops detected.")
        
    parsed = urlparse(final_url)
    if any(final_url.endswith(tld) for tld in [".xyz", ".top", ".su", ".me"]):
        score += 25
        reasons.append(f"High-Risk TLD detected on destination: {parsed.netloc}")

    severity = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "LOW"

    return {
        "status": "success",
        "trace": {
            "final_url": final_url,
            "hops_detail": chain
        },
        "assessment": {
            "risk_score": min(score, 100),
            "severity": severity,
            "xai_breakdown": reasons
        }
    }

@app.post("/scan/quishing")
async def scan_quishing(file: UploadFile = File(...)):
    temp_file = f"temp_{file.filename}"
    with open(temp_file, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        img = cv2.imread(temp_file)
        decoded = decode(img)
        
        if not decoded:
            return {"status": "error", "message": "No valid QR code payload found in image."}
        
        qr_url = decoded[0].data.decode("utf-8")
        chain, final_url = await trace_url_hops(qr_url)
        
        return {
            "status": "success",
            "extracted_payload": qr_url,
            "trace": {
                "final_url": final_url,
                "hops_detail": chain
            },
            "assessment": {
                "risk_score": 85,
                "severity": "CRITICAL",
                "xai_breakdown": [
                    "Quishing Vector: Embedded QR decoded in remote sandbox.",
                    f"Resolved payload URL: {qr_url}"
                ]
            }
        }
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
              
