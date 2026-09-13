document.addEventListener("DOMContentLoaded", function () {
    const analyzeBtn = document.getElementById("analyzeBtn");
    const threatInput = document.getElementById("threatInput");
    const qrFileInput = document.getElementById("qrFileInput");
    const fileNameDisplay = document.getElementById("fileNameDisplay");

    const riskScore = document.getElementById("riskScore");
    const meterBar = document.getElementById("meterBar");
    const threatStatus = document.getElementById("threatStatus");
    const explanation = document.getElementById("explanation");
    const severityBadge = document.getElementById("severityBadge");
    const forensicsWrapper = document.getElementById("forensicsWrapper");
    const xaiList = document.getElementById("xaiList");
    const hopChainWrapper = document.getElementById("hopChainWrapper");
    const hopChainLogs = document.getElementById("hopChainLogs");
    const downloadReportBtn = document.getElementById("downloadReportBtn");

    const BACKEND_API = "https://cyberguard-x-backend.onrender.com";
    
    let lastScanReport = null;

    if (qrFileInput && fileNameDisplay) {
        qrFileInput.addEventListener("change", function (e) {
            if (e.target.files && e.target.files.length > 0) {
                fileNameDisplay.textContent = "Attached: " + e.target.files[0].name;
            } else {
                fileNameDisplay.textContent = "";
            }
        });
    }

    if (downloadReportBtn) {
        downloadReportBtn.addEventListener("click", function () {
            if (!lastScanReport) return;
            const blob = new Blob([JSON.stringify(lastScanReport, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `CYBERGUARD_INCIDENT_${Date.now()}.json`;
            a.click();
            URL.revokeObjectURL(url);
        });
    }

    if (!analyzeBtn) return;

    analyzeBtn.addEventListener("click", async function () {
        const input = threatInput ? threatInput.value.trim() : "";
        const uploadedFile = qrFileInput && qrFileInput.files ? qrFileInput.files[0] : null;

        if (input === "" && !uploadedFile) {
            riskScore.innerHTML = "Risk Score: <strong>--/100</strong>";
            if (meterBar) meterBar.style.width = "0%";
            threatStatus.textContent = "⚠️ Please enter text/URL or attach a QR screenshot.";
            explanation.textContent = "Enter a URL, SMS, email or attach a file.";
            if (severityBadge) severityBadge.style.display = "none";
            if (forensicsWrapper) forensicsWrapper.style.display = "none";
            return;
        }

        analyzeBtn.disabled = true;
        analyzeBtn.textContent = "Analyzing Threat Vector...";
        threatStatus.textContent = "Running heuristic and deep-packet intelligence...";

        try {
            let response;
            if (uploadedFile) {
                const formData = new FormData();
                formData.append("file", uploadedFile);
                response = await fetch(`${BACKEND_API}/scan/quishing`, {
                    method: "POST",
                    body: formData
                });
            } else {
                const formData = new FormData();
                formData.append("target_url", input);
                response = await fetch(`${BACKEND_API}/scan/url`, {
                    method: "POST",
                    body: formData
                });
            }

            if (!response.ok) throw new Error("API Offline");
            const data = await response.json();
            renderBackendResult(data, input);

        } catch (err) {
            runAdvancedLocalAnalysis(input, uploadedFile);
        } finally {
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = "Analyze Threat";
        }
    });

    function renderBackendResult(data, input) {
        const assessment = data.assessment || {};
        const score = assessment.risk_score || 0;
        const severity = assessment.severity || "LOW";
        const trace = data.trace || {};

        lastScanReport = {
            dossier_id: "CGX-" + Math.floor(100000 + Math.random() * 900000),
            timestamp_utc: new Date().toISOString(),
            evaluator: "CYBERGUARD X Multi-Signal Engine v2.4",
            entry_input: input,
            assessment: assessment,
            trace: trace
        };

        updateUI(score, severity, assessment.xai_breakdown || []);

        if (trace.hops_detail && trace.hops_detail.length > 0 && hopChainWrapper && hopChainLogs) {
            hopChainWrapper.style.display = "block";
            let logs = trace.hops_detail.map((h, i) => `[Hop ${i+1}] (${h.status}) ➔ ${h.url}`).join("\n");
            logs += `\n[Final Destination] ➔ ${trace.final_url}`;
            hopChainLogs.textContent = logs;
        } else if (hopChainWrapper) {
            hopChainWrapper.style.display = "none";
        }
    }

    function runAdvancedLocalAnalysis(input, uploadedFile) {
        if (uploadedFile && !input) {
            const reasons = [
                "Quishing Payload: Image file attached for QR matrix extraction.",
                "Backend offline: Quarantined pending headless browser unpack."
            ];
            buildLocalDossier(75, "HIGH", reasons, "Uploaded Image / QR Code");
            updateUI(75, "HIGH", reasons);
            return;
        }

        let score = 0;
        let reasons = [];
        const lower = input.toLowerCase();

        // 1. UPI & Financial KYC Vectors
        const isUPI = lower.includes("upi://") || lower.includes("@ok") || lower.includes("@paytm") || lower.includes("@apl");
        if (isUPI) {
            score += 25;
            reasons.push("Financial Vector: Embedded UPI transaction handle/scheme identified.");

            if (lower.includes("collect") || !lower.includes("am=")) {
                score += 30;
                reasons.push("Reverse-Charge Fraud: Potential UPI collect request masked as credit/refund.");
            }
            if (lower.includes("kyc") || lower.includes("support") || lower.includes("refund")) {
                score += 25;
                reasons.push("VPA Impersonation: Handle contains administrative pretexting terms.");
            }
        }

        // 2. Behavioral Urgency & Pretexting NLP Triggers
        const urgencyKeywords = [
            "urgent", "immediately", "verify", "password", "kyc", "winner", 
            "prize", "otp", "account suspended", "blocked", "electricity bill", "refund"
        ];
        urgencyKeywords.forEach(function (word) {
            if (lower.includes(word)) {
                score += 12;
                reasons.push("Social Engineering Trigger: Pretexting marker detected ('" + word + "').");
            }
        });

        // 3. Obfuscation & Infrastructure
        if (lower.includes("http://")) {
            score += 20;
            reasons.push("Transport Security: Unencrypted HTTP protocol origin.");
        }

        if (lower.includes("bit.ly") || lower.includes("tinyurl.com") || lower.includes("t.co") || lower.includes("cutt.ly")) {
            score += 25;
            reasons.push("Infrastructure Cloaking: Shortener used to obscure destination endpoint.");
        }

        const highRiskTLDs = [".su", ".top", ".xyz", ".click", ".work", ".me", ".online", ".link"];
        if (highRiskTLDs.some(tld => lower.includes(tld))) {
            score += 20;
            reasons.push("Registrar Anomaly: Destination resolves under a high-abuse TLD.");
        }

        if (lower.includes("xn--")) {
            score += 35;
            reasons.push("Evasion Vector: Punycode homoglyph detected (visual deception).");
        }

        const targets = ["sbi", "hdfc", "microsoft", "google", "paytm", "netflix", "incometax"];
        targets.forEach(brand => {
            if (lower.includes(brand) && !lower.includes(brand + ".com") && !lower.includes(brand + ".co.in")) {
                score += 30;
                reasons.push("Identity Impersonation: Unauthorized brand mimicry target: '" + brand + "'.");
            }
        });

        score = Math.min(score, 100);
        const severity = score >= 75 ? "CRITICAL" : score >= 50 ? "HIGH" : score >= 25 ? "MEDIUM" : "LOW";

        buildLocalDossier(score, severity, reasons, input);
        updateUI(score, severity, reasons);
    }

    function buildLocalDossier(score, severity, reasons, input) {
        lastScanReport = {
            dossier_id: "CGX-" + Math.floor(100000 + Math.random() * 900000),
            timestamp_utc: new Date().toISOString(),
            evaluator: "CYBERGUARD X Multi-Signal Engine v2.4 (Client Sandbox)",
            entry_input: input,
            assessment: {
                risk_score: score,
                severity: severity,
                xai_breakdown: reasons
            }
        };
    }

    function updateUI(score, severity, reasons) {
        riskScore.innerHTML = `Risk Score: <strong>${score}/100</strong>`;

        if (meterBar) {
            meterBar.style.width = `${score}%`;
            meterBar.style.background = score >= 75 ? "#f44336" : score >= 50 ? "#ff9800" : score >= 25 ? "#ffc107" : "#4caf50";
        }

        if (severityBadge) {
            severityBadge.style.display = "inline-block";
            severityBadge.className = "badge";
            severityBadge.classList.add(`badge-${severity.toLowerCase()}`);
            severityBadge.textContent = severity;
        }

        if (score >= 75) {
            threatStatus.textContent = "🔴 CRITICAL — Severe Attack Vector Detected";
        } else if (score >= 50) {
            threatStatus.textContent = "🟠 HIGH RISK — Malicious Signatures Present";
        } else if (score >= 25) {
            threatStatus.textContent = "🟡 SUSPICIOUS — Elevated Anomaly Signals";
        } else {
            threatStatus.textContent = "🟢 LOW RISK — No Known Exploit Patterns";
        }

        if (forensicsWrapper && xaiList) {
            forensicsWrapper.style.display = "block";
            xaiList.innerHTML = "";

            if (reasons.length > 0) {
                explanation.textContent = "Granular Explainability (XAI) Attribution Breakdown:";
                reasons.forEach(r => {
                    const li = document.createElement("li");
                    li.textContent = r;
                    xaiList.appendChild(li);
                });
            } else {
                explanation.textContent = "Payload integrity verified. No anomalous structural markers found.";
                const li = document.createElement("li");
                li.textContent = "Origin protocol and semantic markers within baseline security thresholds.";
                xaiList.appendChild(li);
            }
        }
    }
});
        
