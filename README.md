CYBERNEXUS AI

AI-Powered Cyber Threat, Phishing & Digital Scam Detection Platform

CYBERGUARD X is an intelligent cybersecurity platform designed to analyze suspicious URLs, messages, and QR codes and provide an explainable risk assessment.

The system combines multiple security signals such as suspicious URLs, urgency-based scam language, UPI-related patterns, QR-based threats, domain characteristics, and redirect behavior to generate a risk score.

---

🚨 Problem Statement

Cyber fraud is increasingly occurring through multiple channels:

- Phishing URLs
- Fake KYC messages
- SMS and email scams
- QR-code scams (Quishing)
- UPI/payment-related fraud
- Fake account verification messages
- Suspicious redirects
- Digital impersonation attempts

Traditional security systems may analyze these signals separately.

CYBERGUARD X aims to provide a unified platform where multiple suspicious signals can be analyzed together.

---

💡 Our Solution

CYBERGUARD X analyzes a submitted:

- URL
- SMS/email/message
- QR code

and generates:

- Risk Score
- Threat Severity
- Explainable Risk Factors
- URL Redirect Information
- Security Assessment

The goal is to help users understand why something may be suspicious, rather than simply showing "Safe" or "Unsafe".

---

🔥 Key Features

1. Phishing URL Analysis

Analyzes URLs for suspicious characteristics and security signals.

2. QR / Quishing Detection

Users can upload a QR-code image.

The system extracts the QR payload and checks whether it contains:

- URL
- UPI/payment information
- Other text

3. Scam Message Detection

Analyzes text for suspicious patterns such as:

- Urgency
- KYC requests
- Account suspension claims
- UPI/payment-related content
- Scam-related keywords

4. Redirect Analysis

The URL scanner can trace HTTP redirect behavior and return redirect-chain information.

5. Risk Scoring

CYBERGUARD X generates a risk score from:

0 → 100

Higher scores represent greater detected risk.

6. Explainable Risk Analysis

Instead of only providing a score, the platform shows contributing risk factors.

This improves transparency and helps users understand the assessment.

7. Multi-Signal Risk Engine

Different security signals are combined into a single risk assessment.

This provides a foundation for detecting complex scam patterns.

---

🧠 AI / Risk Engine

The current prototype uses a machine-learning-based risk engine with:

- LightGBM
- SHAP explainability
- Multiple cybersecurity signals
- Deterministic security rules for critical conditions

The current model is a prototype baseline.

For production deployment, it should be trained and validated using a large real-world cybersecurity dataset.

---

🏗️ System Architecture

                 ┌─────────────────────┐
                 │      USER           │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │   CYBERGUARD X      │
                 │     FRONTEND        │
                 └──────────┬──────────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
              ▼             ▼             ▼
            URL           TEXT           QR
              │             │             │
              └─────────────┼─────────────┘
                            ▼
                 ┌─────────────────────┐
                 │     FASTAPI         │
                 │      BACKEND        │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │   SECURITY SIGNALS  │
                 │                     │
                 │ URL / UPI / KYC     │
                 │ Urgency / Redirect  │
                 │ QR / Domain Signals │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │    RISK ENGINE      │
                 │  LightGBM + SHAP    │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │   RISK SCORE        │
                 │   SEVERITY          │
                 │   XAI EXPLANATION   │
                 └─────────────────────┘

---

🛠️ Technology Stack

Frontend

- HTML5
- CSS3
- JavaScript

Backend

- Python
- FastAPI
- Uvicorn

AI / Machine Learning

- LightGBM
- SHAP
- NumPy

QR Analysis

- OpenCV
- OpenCV QRCodeDetector

Web Analysis

- Playwright
- Chromium

Deployment

- Render

---

📁 Project Structure

CYBERGUARD X/
│
├── backend/
│   └── app.py
│
├── ai/
│   └── risk_engine.py
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── requirements.txt
└── render.yaml

---

⚙️ Run Locally

1. Clone the repository

git clone YOUR_REPOSITORY_URL
cd "CYBERGUARD X"

2. Create virtual environment

python -m venv venv

3. Activate environment

Windows

venv\Scripts\activate

Linux / macOS

source venv/bin/activate

4. Install dependencies

pip install -r requirements.txt

5. Install Chromium

playwright install chromium

6. Start backend

uvicorn backend.app:app --reload

Backend will run on:

http://127.0.0.1:8000

7. API documentation

Open:

http://127.0.0.1:8000/docs

---

🔌 API Endpoints

Method| Endpoint| Purpose
GET| "/"| API information
GET| "/health"| Backend health check
POST| "/scan/url"| Analyze URL
POST| "/scan/text"| Analyze text/message
POST| "/scan/quishing"| Analyze QR image

---

📊 Risk Levels

Score| Severity
0–39| Low
40–69| Medium
70–89| High
90–100| Critical

---

🔐 Security Approach

CYBERGUARD X is designed as a defensive cybersecurity system.

The backend includes URL validation and protection against requests targeting private or local network addresses.

The platform is intended for:

- Threat detection
- Scam awareness
- Security analysis
- Defensive cybersecurity research

---

🚀 Future Scope

The current prototype can be extended with:

- Real-time threat monitoring
- Live threat-intelligence feeds
- Domain reputation APIs
- WHOIS/domain-age intelligence
- SPF/DKIM/DMARC analysis
- Advanced email-header analysis
- Digital impersonation detection
- UPI fraud intelligence
- KYC scam intelligence
- Incident correlation
- Security dashboard
- Automated alerting
- Historical threat database
- PDF security reports
- Production-grade cybersecurity datasets
- Continuous ML model training

Advanced Correlation Vision

A future version can correlate multiple events into a single incident:

SMS
 ↓
QR Code
 ↓
Suspicious URL
 ↓
Fake KYC Page
 ↓
Payment Request
 ↓
Unified Risk Score

This can help CYBERGUARD X move beyond simple single-input detection toward multi-channel cyber-threat intelligence and correlation.

---

🎯 Project Vision

CYBERGUARD X aims to make cybersecurity analysis more understandable and accessible by combining:

Detection + Risk Scoring + Explainability + Multi-Signal Analysis

into a single platform.

---

⚠️ Current Prototype Disclaimer

CYBERGUARD X is currently a research/prototype project.

Its risk assessment should not be considered a guarantee that a URL, message, or QR code is completely safe or malicious.

Production deployment would require extensive real-world datasets, security testing, model validation, threat-intelligence integration, monitoring, and privacy controls.

---

👥 Team

Project: CYBERGUARD X
Category: Cybersecurity / Artificial Intelligence
Project Type: Innovation & Startup Project

---

📌 Status

Current Stage: Prototype / Development

Completed

- URL scanning
- Text/message scanning
- QR-code analysis
- Risk scoring
- Explainable risk factors
- Redirect analysis
- FastAPI backend
- Web frontend

Planned

- Advanced threat intelligence
- Multi-channel incident correlation
- Real-time monitoring
- Production ML model
- Advanced security dashboard
- Automated threat alerts


**README bhi complete ✅**

Ab hamare coding files ka audit practically complete hai. **Next step mein testing karna hai**, especially `pip install`, backend `/health`, `/docs`, `/scan/text`, `/scan/url`—taaki deployment se pehle actual errors pakad saken.
