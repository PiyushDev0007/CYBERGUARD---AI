# 🛡️ CYBERGUARD X — Advanced Threat Intelligence Engine

[![GitHub Pages](https://img.shields.io/badge/Live-Demo-brightgreen)](https://omyaranjandora82-git.github.io/cyberguard-x/)
[![Architecture](https://img.shields.io/badge/Difficulty-9%2F10-red)](#)
[![Python](https://img.shields.io/badge/Backend-FastAPI-blue)](#)

CYBERGUARD X is an enterprise-grade cyber threat analysis platform engineered to detect multi-stage social engineering campaigns, recursive URL cloaking, QR quishing payloads, and Indian financial/UPI scams.

## 🚀 Key Modules
- **Quishing Defense:** Sandboxed OpenCV matrix decoding for QR payloads.
- **Recursive Redirect Tracer:** Playwright Chromium headless redirection auditor.
- **Multi-Signal AI Engine:** LightGBM classifier with SHAP-based Explainable AI (XAI).
- **Financial Intel:** Deep inspection for deceptive UPI schemes and reverse-charge collect frauds.

## 💻 Local Setup
\`\`\`bash
git clone https://github.com/omyaranjandora82-git/cyberguard-x.git
cd cyberguard-x
pip install -r requirements.txt
playwright install chromium
uvicorn backend.app:app --reload --port 8000
\`\`\`
