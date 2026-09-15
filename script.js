/* =========================================================
   CYBERGUARD X — Frontend Controller
   ========================================================= */

"use strict";

/* =========================================================
   CONFIGURATION
   ========================================================= */

const BACKEND_API = "https://cyberguard-x-backend.onrender.com";

/* =========================================================
   DOM ELEMENTS
   ========================================================= */

const threatInput = document.getElementById("threatInput");
const qrFileInput = document.getElementById("qrFileInput");
const fileNameDisplay = document.getElementById("fileNameDisplay");
const analyzeBtn = document.getElementById("analyzeBtn");

const severityBadge = document.getElementById("severityBadge");
const riskScore = document.getElementById("riskScore");
const meterBar = document.getElementById("meterBar");
const threatStatus = document.getElementById("threatStatus");
const explanation = document.getElementById("explanation");

const forensicsWrapper = document.getElementById("forensicsWrapper");
const xaiList = document.getElementById("xaiList");

const hopChainWrapper = document.getElementById("hopChainWrapper");
const hopChainLogs = document.getElementById("hopChainLogs");

const downloadReportBtn = document.getElementById("downloadReportBtn");

/* =========================================================
   STATE
   ========================================================= */

let lastScanResult = null;

/* =========================================================
   INITIAL UI STATE
   ========================================================= */

function resetResults() {
    if (severityBadge) {
        severityBadge.className = "badge";
        severityBadge.textContent = "Waiting";
    }

    if (riskScore) {
        riskScore.textContent = "—";
    }

    if (meterBar) {
        meterBar.style.width = "0%";
        meterBar.style.background = "";
    }

    if (threatStatus) {
        threatStatus.textContent = "No scan performed";
    }

    if (explanation) {
        explanation.textContent =
            "Enter a URL, message, SMS/email text, or upload a QR image.";
    }

    if (xaiList) {
        xaiList.innerHTML = "";
    }

    if (hopChainLogs) {
        hopChainLogs.innerHTML = "";
    }

    if (forensicsWrapper) {
        forensicsWrapper.style.display = "none";
    }

    if (hopChainWrapper) {
        hopChainWrapper.style.display = "none";
    }

    lastScanResult = null;
}

resetResults();

/* =========================================================
   FILE INPUT
   ========================================================= */

if (qrFileInput) {
    qrFileInput.addEventListener("change", () => {
        const file = qrFileInput.files && qrFileInput.files[0];

        if (!file) {
            fileNameDisplay.textContent = "No QR image selected.";
            return;
        }

        fileNameDisplay.textContent = `Selected: ${file.name}`;
    });
}

/* =========================================================
   HELPERS
   ========================================================= */

function clampScore(value) {
    const numericValue = Number(value);

    if (!Number.isFinite(numericValue)) {
        return 0;
    }

    return Math.max(0, Math.min(100, Math.round(numericValue)));
}

function getSeverityClass(severity) {
    const normalized = String(severity || "").toLowerCase();

    if (normalized === "low") {
        return "badge-low";
    }

    if (normalized === "medium") {
        return "badge-medium";
    }

    if (normalized === "high") {
        return "badge-high";
    }

    if (normalized === "critical") {
        return "badge-critical";
    }

    return "";
}

function getMeterColor(score) {
    if (score >= 90) {
        return "#dc2626";
    }

    if (score >= 70) {
        return "#fb923c";
    }

    if (score >= 40) {
        return "#f59e0b";
    }

    return "#22c55e";
}

function getThreatLabel(severity, score) {
    const normalized = String(severity || "").toLowerCase();

    if (normalized === "critical" || score >= 90) {
        return "Critical Threat Detected";
    }

    if (normalized === "high" || score >= 70) {
        return "High Risk Threat Detected";
    }

    if (normalized === "medium" || score >= 40) {
        return "Suspicious Activity Detected";
    }

    return "Low Risk / No Major Threat Detected";
}

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/* =========================================================
   INPUT CLASSIFICATION
   ========================================================= */

function isLikelyUrl(text) {
    const value = String(text || "").trim();

    if (!value) {
        return false;
    }

    try {
        const url = new URL(value);

        return (
            url.protocol === "http:" ||
            url.protocol === "https:"
        );
    } catch {
        return false;
    }
}

/* =========================================================
   API REQUEST
   ========================================================= */

async function fetchJson(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        headers: {
            Accept: "application/json",
            ...(options.headers || {})
        }
    });

    let data = null;

    try {
        data = await response.json();
    } catch {
        data = null;
    }

    if (!response.ok) {
        const message =
            data?.detail ||
            data?.message ||
            `Backend request failed with status ${response.status}.`;

        throw new Error(message);
    }

    return data;
}

/* =========================================================
   URL SCAN
   ========================================================= */

async function scanUrl(url) {
    return fetchJson(`${BACKEND_API}/scan/url`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            url: url
        })
    });
}

/* =========================================================
   TEXT SCAN
   ========================================================= */

async function scanText(text) {
    return fetchJson(`${BACKEND_API}/scan/text`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            text: text
        })
    });
}

/* =========================================================
   QR SCAN
   ========================================================= */

async function scanQr(file) {
    const formData = new FormData();

    formData.append("file", file);

    return fetchJson(`${BACKEND_API}/scan/quishing`, {
        method: "POST",
        body: formData
    });
}

/* =========================================================
   RENDER XAI
   ========================================================= */

function renderXai(xai) {
    if (!xaiList) {
        return;
    }

    xaiList.innerHTML = "";

    if (!Array.isArray(xai) || xai.length === 0) {
        const li = document.createElement("li");
        li.textContent = "No explainable risk factors were returned.";
        xaiList.appendChild(li);
        return;
    }

    xai.forEach((item) => {
        const li = document.createElement("li");

        if (typeof item === "string") {
            li.textContent = item;
        } else {
            const feature =
                item?.feature ||
                item?.name ||
                item?.signal ||
                "Risk factor";

            const contribution =
                item?.contribution ??
                item?.value ??
                item?.impact;

            li.innerHTML =
                `<strong>${escapeHtml(feature)}</strong>` +
                (
                    contribution !== undefined
                        ? ` — ${escapeHtml(contribution)}`
                        : ""
                );
        }

        xaiList.appendChild(li);
    });
}

/* =========================================================
   RENDER REDIRECT CHAIN
   ========================================================= */

function renderRedirectChain(trace) {
    if (!hopChainWrapper || !hopChainLogs) {
        return;
    }

    hopChainLogs.innerHTML = "";

    if (!Array.isArray(trace) || trace.length === 0) {
        hopChainWrapper.style.display = "none";
        return;
    }

    hopChainWrapper.style.display = "block";

    trace.forEach((item, index) => {
        const div = document.createElement("div");

        div.className = "hop-item";

        if (typeof item === "string") {
            div.textContent = `${index + 1}. ${item}`;
        } else {
            const status =
                item?.status ??
                item?.status_code ??
                "";

            const url =
                item?.url ||
                item?.location ||
                item?.target ||
                JSON.stringify(item);

            div.innerHTML =
                `<strong>Hop ${index + 1}</strong>` +
                `${status ? ` [${escapeHtml(status)}]` : ""}` +
                ` — ${escapeHtml(url)}`;
        }

        hopChainLogs.appendChild(div);
    });
}

/* =========================================================
   EXTRACT ASSESSMENT
   ========================================================= */

function getAssessment(data) {
    if (data?.assessment) {
        return data.assessment;
    }

    if (data?.result) {
        return data.result;
    }

    return data || {};
}

/* =========================================================
   RENDER RESULT
   ========================================================= */

function renderResult(data) {
    const assessment = getAssessment(data);

    const score = clampScore(
        assessment.score ??
        assessment.risk_score ??
        data?.risk_score ??
        data?.score
    );

    const severity =
        assessment.severity ??
        data?.severity ??
        "low";

    const xai =
        assessment.xai ??
        assessment.explainability ??
        data?.xai ??
        [];

    const trace =
        data?.trace ??
        data?.redirect_chain ??
        data?.hops ??
        [];

    const explanationText =
        assessment.explanation ??
        data?.explanation ??
        `Risk assessment completed with a score of ${score}/100.`;

    lastScanResult = data;

    if (severityBadge) {
        severityBadge.className = `badge ${getSeverityClass(severity)}`;
        severityBadge.textContent = String(severity).toUpperCase();
    }

    if (riskScore) {
        riskScore.textContent = String(score);
    }

    if (meterBar) {
        meterBar.style.width = `${score}%`;
        meterBar.style.background = getMeterColor(score);
    }

    if (threatStatus) {
        threatStatus.textContent = getThreatLabel(severity, score);
    }

    if (explanation) {
        explanation.textContent = explanationText;
    }

    if (forensicsWrapper) {
        forensicsWrapper.style.display = "block";
    }

    renderXai(xai);
    renderRedirectChain(trace);

    if (meterBar) {
        meterBar.setAttribute("aria-valuenow", String(score));
    }
}

/* =========================================================
   LOCAL FALLBACK
   =========================================================
   This is NOT the main AI engine.
   It only provides a basic result if the backend is
   temporarily unreachable.
   ========================================================= */

function localFallbackAnalysis(input) {
    const text = String(input || "").toLowerCase();

    let score = 5;
    const reasons = [];

    const urgentWords = [
        "urgent",
        "immediately",
        "verify now",
        "account blocked",
        "account suspended",
        "act now",
        "otp",
        "kyc",
        "refund",
        "winner",
        "prize"
    ];

    const suspiciousTlds = [
        ".xyz",
        ".top",
        ".click",
        ".shop",
        ".work",
        ".zip"
    ];

    const shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd"
    ];

    if (urgentWords.some((word) => text.includes(word))) {
        score += 25;
        reasons.push("Urgency or scam-related language detected.");
    }

    if (text.includes("upi")) {
        score += 20;
        reasons.push("UPI/payment-related content detected.");
    }

    if (text.includes("kyc")) {
        score += 15;
        reasons.push("KYC-related request detected.");
    }

    if (text.includes("http://")) {
        score += 15;
        reasons.push("Unencrypted HTTP URL detected.");
    }

    if (shorteners.some((domain) => text.includes(domain))) {
        score += 20;
        reasons.push("URL-shortening service detected.");
    }

    if (suspiciousTlds.some((tld) => text.includes(tld))) {
        score += 20;
        reasons.push("Potentially suspicious domain extension detected.");
    }

    score = clampScore(score);

    let severity = "low";

    if (score >= 90) {
        severity = "critical";
    } else if (score >= 70) {
        severity = "high";
    } else if (score >= 40) {
        severity = "medium";
    }

    return {
        status: "fallback",
        input_type: "local_heuristic",
        assessment: {
            score: score,
            severity: severity,
            explanation:
                "Backend AI analysis was unavailable. A basic local heuristic assessment was used.",
            xai:
                reasons.length > 0
                    ? reasons
                    : ["No major suspicious pattern detected by the local fallback."]
        },
        trace: []
    };
}

/* =========================================================
   MAIN SCAN FUNCTION
   ========================================================= */

async function analyzeThreat() {
    const text = String(threatInput?.value || "").trim();
    const qrFile = qrFileInput?.files?.[0] || null;

    if (!text && !qrFile) {
        alert("Please enter a URL/message or upload a QR image.");
        return;
    }

    if (!analyzeBtn) {
        return;
    }

    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "Analyzing...";

    if (explanation) {
        explanation.textContent =
            "CyberGuard X is analyzing the submitted threat...";
    }

    try {
        let data;

        if (qrFile) {
            data = await scanQr(qrFile);
        } else if (isLikelyUrl(text)) {
            data = await scanUrl(text);
        } else {
            data = await scanText(text);
        }

        renderResult(data);
    } catch (error) {
        console.error("CyberGuard X scan error:", error);

        const fallbackInput = qrFile
            ? `QR image: ${qrFile.name}`
            : text;

        const fallbackResult =
            localFallbackAnalysis(fallbackInput);

        renderResult(fallbackResult);

        if (explanation) {
            explanation.textContent =
                `${fallbackResult.assessment.explanation} ` +
                `Backend message: ${error.message}`;
        }
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = "Analyze Threat";
    }
}

/* =========================================================
   REPORT DOWNLOAD
   ========================================================= */

function downloadReport() {
    if (!lastScanResult) {
        alert("Please perform a scan first.");
        return;
    }

    const report = {
        product: "CYBERGUARD X",
        generated_at: new Date().toISOString(),
        result: lastScanResult
    };

    const blob = new Blob(
        [JSON.stringify(report, null, 2)],
        {
            type: "application/json"
        }
    );

    const url = URL.createObjectURL(blob);

    const anchor = document.createElement("a");

    anchor.href = url;
    anchor.download =
        `cyberguard-x-report-${Date.now()}.json`;

    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();

    URL.revokeObjectURL(url);
}

/* =========================================================
   EVENT LISTENERS
   ========================================================= */

if (analyzeBtn) {
    analyzeBtn.addEventListener("click", analyzeThreat);
}

if (downloadReportBtn) {
    downloadReportBtn.addEventListener(
        "click",
        downloadReport
    );
}

/* =========================================================
   ENTER KEY SUPPORT
   ========================================================= */

if (threatInput) {
    threatInput.addEventListener("keydown", (event) => {
        if (
            event.key === "Enter" &&
            (event.ctrlKey || event.metaKey)
        ) {
            event.preventDefault();
            analyzeThreat();
        }
    });
}

/* =========================================================
   BACKEND HEALTH CHECK
   ========================================================= */

async function checkBackendHealth() {
    try {
        const response = await fetch(
            `${BACKEND_API}/health`,
            {
                method: "GET"
            }
        );

        if (!response.ok) {
            throw new Error(
                `Health check failed: ${response.status}`
            );
        }

        const data = await response.json();

        console.log(
            "CyberGuard X backend:",
            data
        );
    } catch (error) {
        console.warn(
            "CyberGuard X backend is not currently reachable.",
            error
        );
    }
}

checkBackendHealth();
