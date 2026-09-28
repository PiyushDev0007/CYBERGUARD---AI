# CYBERGUARD X

**AI-Powered Multi-Signal Cyber Threat, Phishing & Digital Scam Detection Platform**

CyberGuard X analyzes suspicious URLs, messages, and QR codes and returns an explainable, 0–100 risk score — combining deterministic security rules, a trained risk-scoring engine, and external threat intelligence into one unified verdict.

---

## 🚨 Problem Statement

Cyber fraud increasingly spans multiple channels:

- Phishing URLs
- Fake KYC / account-verification messages
- SMS and email scams
- QR-code scams (quishing)
- UPI / payment-related fraud
- Suspicious redirects
- Digital impersonation attempts

Traditional tools analyze these signals in isolation. CyberGuard X unifies them into a single platform and a single score.

---

## 💡 Solution

Submit a **URL**, **SMS/email/message**, or **QR code**, and CyberGuard X returns:

- Risk Score (0–100) and Severity (Low / Medium / High / Critical)
- Explainable risk factors (XAI)
- URL redirect-chain information
- Domain / registration intelligence
- A full security assessment — not just "Safe" or "Unsafe"

---

## 🧱 Architecture

```
USER
  │
  ▼
FRONTEND (HTML/CSS/JS)
  │
  ├── URL   ├── TEXT   ├── QR
  │
  ▼
FASTAPI BACKEND
  │
  ├── Auth Service (JWT)
  ├── Security Layer (rate limiting, SSRF/private-IP guards, validation)
  │
  ▼
DETECTION SIGNALS
  URL structure · Typosquatting · Obfuscation · Redirect hops
  Urgency / UPI / KYC / brand-mention language · QR payload decode
  │
  ▼
THREAT INTELLIGENCE
  VirusTotal · RDAP (domain registration) · DNS resolution
  │
  ▼
RISK ENGINE (LightGBM + SHAP)
  │
  ▼
RISK SCORE · SEVERITY · XAI EXPLANATION
  │
  ▼
HISTORY / DATABASE  →  Scan history, statistics, dashboard data
```

---

## 🛠️ Technology Stack

**Frontend:** HTML5, CSS3, JavaScript

**Backend:** Python, FastAPI, Uvicorn, SQLAlchemy

**AI / Risk Engine:** LightGBM, SHAP, scikit-learn

**QR Analysis:** OpenCV (`QRCodeDetector`)

**Web / Redirect Analysis:** Playwright (Chromium), httpx

**Threat Intelligence:** VirusTotal API, RDAP, DNS (dnspython)

**Auth & Persistence:** JWT-based auth service, SQLAlchemy ORM

**Deployment:** Render

> Note: `transformers`, `torch`, and `reportlab` are listed in `requirements.txt` for planned NLP and PDF-reporting features, but are **not yet imported or used** anywhere in the codebase — see [Current Status](#-current-status) below.

---

## 📁 Project Structure

```
CYBERGUARD X/
│
├── main.py                  # FastAPI app, middleware, router registration
├── auth.py / auth_service.py    # Auth routes & JWT logic
├── scan.py / scan_service.py    # Scan routes & detection orchestration
├── history.py / history_service.py  # Scan history & statistics
├── database.py               # SQLAlchemy models & DB access
├── config.py                  # Settings (pydantic-settings)
├── security.py                # Validation, rate limiting, SSRF guards
├── risk_engine.py              # LightGBM + SHAP risk-scoring engine
├── threat_intelligence.py       # VirusTotal / RDAP / DNS integration
├── schemas.py                  # Pydantic request/response models
├── app_upgraded.py               # URL/text/QR analysis pipeline
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── requirements.txt
└── render.yaml
```

---

## ⚙️ Run Locally

```bash
# 1. Clone the repository
git clone YOUR_REPOSITORY_URL
cd "CYBERGUARD X"

# 2. Create & activate a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
playwright install chromium

# 4. Start the backend
uvicorn main:app --reload
```

Backend runs at `http://127.0.0.1:8000` — API docs at `http://127.0.0.1:8000/docs`.

---

## 🔌 API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | API information |
| GET | `/health` | Backend health check |
| GET | `/ready` | Readiness probe |
| GET | `/metrics` | Basic runtime metrics |
| POST | `/auth/register` | Register a new user |
| POST | `/auth/login` | Authenticate & receive a token |
| GET | `/auth/me` | Current user profile |
| POST | `/scan/url` | Analyze a URL |
| POST | `/scan/text` | Analyze a message / SMS / email |
| POST | `/scan/quishing` | Analyze a QR code image |
| GET | `/history` | List past scans |
| GET | `/history/{id}` | Retrieve a specific scan |
| DELETE | `/history/{id}` | Delete a scan record |

---

## 📊 Risk Levels

| Score | Severity |
|---|---|
| 0–39 | Low |
| 40–69 | Medium |
| 70–89 | High |
| 90–100 | Critical |

---

## 📌 Current Status

The platform's core detection pipeline, auth, and persistence layers are production-grade. The table below reflects an honest audit of what's actually implemented in code versus what remains a dependency, comment, or roadmap item.

| # | Module | Status | Notes |
|---|---|---|---|
| 1 | URL & Phishing Intelligence | ✅ ~95% | Typosquat detection, URL obfuscation analysis, RDAP domain age, redirect-hop tracing |
| 2 | QR / Quishing Detection | ✅ ~85% | Decodes QR payloads and re-runs the URL analysis pipeline |
| 3 | Email/SMS Scam Detection | 🟡 ~50% | Solid rule-based urgency/UPI/payment/brand detection; NLP model (`transformers`/`torch`) is a listed dependency but not yet integrated |
| 4 | Digital Impersonation Detection | 🟡 ~35% | Brand-similarity signal only; no sender-header spoofing or SPF/DKIM/DMARC analysis, no dedicated impersonation score |
| 5 | Multi-Signal Risk Engine | ✅ ~90% | LightGBM + SHAP engine aggregating all detection signals |
| 6 | Explainable AI (XAI) | ✅ ~85% | SHAP-based, per-factor attribution on every verdict |
| 7 | Threat Intelligence Integration | 🟡 ~55% | VirusTotal, RDAP, and DNS are live; AbuseIPDB and AlienVault OTX are not yet integrated |
| 8 | Real-Time Threat Monitoring | 🔴 ~10% | No streaming/websocket layer yet |
| 9 | Security Dashboard | 🟡 ~40% | Backend statistics endpoints exist; no historical/trend UI yet |
| 10 | Automated Incident Reporting | 🔴 ~10% | `reportlab` is a listed dependency, not yet used |
| 11 | Smart Alerting (webhook/SIEM) | 🔴 ~5% | Not implemented |
| 12 | Threat Correlation Engine | 🔴 ~5% | Roadmap only |
| 13 | UPI / KYC Scam Intelligence | ✅ ~80% | Dedicated detection logic and schema |

**Overall: ~45–50% of the full "Advanced" 13-module vision is built.** Auth, database persistence, rate limiting, SSRF/security middleware, the risk engine, and URL/UPI intelligence are solid; the operational layer — correlation, real-time streaming, automated reporting, and alerting/SIEM — is still ahead.

### Foundational (non-module) infrastructure — done
- FastAPI backend with structured middleware, exception handling, and security headers
- JWT authentication & user management
- SQLAlchemy-backed scan history with statistics
- Rate limiting & SSRF/private-network protections
- Input validation & sanitization

### Planned next
- Wire up NLP model for message scoring
- AbuseIPDB / AlienVault OTX integration
- Real-time monitoring (WebSocket/SSE) console
- Historical dashboard UI (trend charts, vector distribution)
- Automated PDF/JSON incident reports on High/Critical breach
- Webhook / email / SIEM alerting
- Multi-stage threat correlation engine
- Production-grade ML training dataset

---

## 🔐 Security Approach

CyberGuard X is built as a defensive cybersecurity system. The backend validates and blocks requests targeting private/local network addresses (SSRF protection), rate-limits clients, and sanitizes all inputs and uploads.

Intended for: threat detection, scam awareness, security analysis, and defensive cybersecurity research.

---

## ⚠️ Disclaimer

CyberGuard X is a research/development project. Its risk assessment should not be treated as a guarantee that a URL, message, or QR code is safe or malicious. Production use would require a larger real-world training dataset, further security testing, full threat-intelligence coverage, and privacy review.

---

## 👥 Team

**Project:** CyberGuard X
**Category:** Cybersecurity / Artificial Intelligence
**Type:** Innovation & Startup Project
