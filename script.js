/* ============================================================
   CYBERGUARD X — Professional Frontend Controller
   ============================================================
   Responsibilities
   ------------------------------------------------------------
   - API configuration + resilient requests
   - URL / text / QR scanning
   - Risk score + severity rendering
   - Explainable AI + redirect-chain rendering
   - Local activity history and dashboard metrics
   - Backend health monitoring
   - Navigation + scroll-state management
   - Responsive mobile sidebar
   - Profile modal
   - Loading and toast feedback
   - QR drag/drop and file validation
   - Secure local fallback heuristics
   - JSON evidence export

   Backend contract currently used
   ------------------------------------------------------------
   POST /scan/url        { "url": string }
   POST /scan/text       { "text": string }
   POST /scan/quishing   multipart/form-data, field "file"
   GET  /health

   The frontend deliberately avoids inventing undocumented
   backend routes. Local history is stored in localStorage until
   a dedicated history API is wired to the console.
   ============================================================ */

"use strict";


/* ============================================================
   01. CONFIGURATION
   ============================================================ */

const CONFIG = Object.freeze({
    BACKEND_API:
        "https://cybernexus-ai-td68.onrender.com",

    HEALTH_TIMEOUT_MS: 8000,

    REQUEST_TIMEOUT_MS: 30000,

    HISTORY_STORAGE_KEY:
        "cyberguard_x_scan_history_v1",

    MAX_HISTORY_ITEMS: 40,

    MAX_LOCAL_PREVIEW_LENGTH: 110,

    MAX_INPUT_LENGTH: 20000,

    MAX_QR_FILE_SIZE: 8 * 1024 * 1024,

    ALLOWED_QR_TYPES: [
        "image/png",
        "image/jpeg",
        "image/webp"
    ]
});


/* ============================================================
   02. DOM REFERENCES
   ============================================================ */

const DOM = {
    /* Shell */
    appShell:
        document.getElementById("appShell"),

    sidebar:
        document.getElementById("sidebar"),

    mobileMenuBtn:
        document.getElementById("mobileMenuBtn"),

    refreshBtn:
        document.getElementById("refreshBtn"),

    /* Profile */
    profileBtn:
        document.getElementById("profileBtn"),

    profileModal:
        document.getElementById("profileModal"),

    closeProfileModal:
        document.getElementById("closeProfileModal"),

    profileEmail:
        document.getElementById("profileEmail"),

    /* Inputs */
    threatInput:
        document.getElementById("threatInput"),

    qrFileInput:
        document.getElementById("qrFileInput"),

    qrUploadSection:
        document.getElementById("qrUploadSection"),

    fileNameDisplay:
        document.getElementById("fileNameDisplay"),

    characterCount:
        document.getElementById("characterCount"),

    inputHint:
        document.getElementById("inputHint"),

    analyzeBtn:
        document.getElementById("analyzeBtn"),

    /* Loading / notifications */
    loadingOverlay:
        document.getElementById("loadingOverlay"),

    toastContainer:
        document.getElementById("toastContainer"),

    /* Result state */
    severityBadge:
        document.getElementById("severityBadge"),

    riskScore:
        document.getElementById("riskScore"),

    threatStatus:
        document.getElementById("threatStatus"),

    meterBar:
        document.getElementById("meterBar"),

    meterContainer:
        document.querySelector(".meter-container"),

    riskGauge:
        document.querySelector(".risk-gauge"),

    explanation:
        document.getElementById("explanation"),

    forensicsWrapper:
        document.getElementById("forensicsWrapper"),

    xaiList:
        document.getElementById("xaiList"),

    hopChainWrapper:
        document.getElementById("hopChainWrapper"),

    hopChainLogs:
        document.getElementById("hopChainLogs"),

    redirectEmpty:
        document.getElementById("redirectEmpty"),

    downloadReportBtn:
        document.getElementById("downloadReportBtn"),

    /* Metrics */
    totalScans:
        document.getElementById("totalScans"),

    threatsDetected:
        document.getElementById("threatsDetected"),

    lowRiskCount:
        document.getElementById("lowRiskCount"),

    /* Health */
    apiStatus:
        document.getElementById("apiStatus"),

    engineStatus:
        document.getElementById("engineStatus"),

    /* History */
    loadHistoryBtn:
        document.getElementById("loadHistoryBtn"),

    historyTableBody:
        document.getElementById("historyTableBody"),

    /* Navigation */
    navItems:
        Array.from(
            document.querySelectorAll(".nav-item")
        ),

    pageSections:
        Array.from(
            document.querySelectorAll("[data-page-section]")
        )
};


/* ============================================================
   03. APPLICATION STATE
   ============================================================ */

const state = {
    lastScanResult: null,

    lastScanMeta: null,

    lastInputType: null,

    lastInputPreview: "",

    lastScanAt: null,

    backendOnline: false,

    scanInProgress: false,

    navigationObserver: null,

    loadingTimer: null,

    history: [],

    activeMobileNav: false,

    droppedQrFile: null
};


/* ============================================================
   04. BASIC HELPERS
   ============================================================ */

function clampScore(value) {
    const numericValue = Number(value);

    if (!Number.isFinite(numericValue)) {
        return null;
    }

    return Math.max(
        0,
        Math.min(
            100,
            Math.round(numericValue)
        )
    );
}


function normalizeSeverity(value, score = null) {
    const normalized =
        String(value || "")
            .trim()
            .toLowerCase();

    if (
        normalized === "critical" ||
        normalized === "severe"
    ) {
        return "critical";
    }

    if (
        normalized === "high" ||
        normalized === "danger"
    ) {
        return "high";
    }

    if (
        normalized === "medium" ||
        normalized === "moderate" ||
        normalized === "suspicious"
    ) {
        return "medium";
    }

    if (
        normalized === "low" ||
        normalized === "safe"
    ) {
        return "low";
    }

    if (score !== null) {
        if (score >= 90) {
            return "critical";
        }

        if (score >= 70) {
            return "high";
        }

        if (score >= 40) {
            return "medium";
        }

        return "low";
    }

    return "unknown";
}


function getSeverityClass(severity) {
    const normalized =
        normalizeSeverity(severity);

    switch (normalized) {
        case "low":
            return "badge-low";

        case "medium":
            return "badge-medium";

        case "high":
            return "badge-high";

        case "critical":
            return "badge-critical";

        default:
            return "";
    }
}


function getSeverityLabel(severity) {
    switch (
        normalizeSeverity(severity)
    ) {
        case "low":
            return "LOW";

        case "medium":
            return "MEDIUM";

        case "high":
            return "HIGH";

        case "critical":
            return "CRITICAL";

        default:
            return "UNKNOWN";
    }
}


function getThreatLabel(severity, score) {
    const normalized =
        normalizeSeverity(
            severity,
            score
        );

    switch (normalized) {
        case "critical":
            return "Critical threat indicators detected";

        case "high":
            return "High-risk indicators detected";

        case "medium":
            return "Suspicious activity detected";

        case "low":
            return "Low-risk assessment";

        default:
            return "Assessment unavailable";
    }
}


function getMeterGradient(score) {
    if (score === null) {
        return "linear-gradient(90deg, #56626e, #56626e)";
    }

    if (score >= 90) {
        return "linear-gradient(90deg, #ff7a78, #ff3b5c)";
    }

    if (score >= 70) {
        return "linear-gradient(90deg, #ffb020, #ff805d)";
    }

    if (score >= 40) {
        return "linear-gradient(90deg, #ffd166, #ffb020)";
    }

    return "linear-gradient(90deg, #00e5a0, #38bdf8)";
}


function getGaugeGradient(score) {
    if (score === null) {
        return [
            "conic-gradient(",
            "rgba(86, 98, 110, 0.8) 0deg,",
            "rgba(255,255,255,0.04) 0deg 360deg",
            ")"
        ].join("");
    }

    const filledAngle =
        `${Math.max(
            0,
            Math.min(
                360,
                score * 3.6
            )
        )}deg`;

    let accent =
        "var(--green)";

    if (score >= 90) {
        accent =
            "var(--red)";
    } else if (score >= 70) {
        accent =
            "#ff805d";
    } else if (score >= 40) {
        accent =
            "var(--amber)";
    }

    return [
        "conic-gradient(",
        `from 218deg, ${accent} 0deg, `,
        `rgba(255,255,255,0.045) ${filledAngle}, `,
        `rgba(255,255,255,0.045) 360deg`,
        ")"
    ].join("");
}


function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function truncate(value, maxLength) {
    const text =
        String(value ?? "");

    if (text.length <= maxLength) {
        return text;
    }

    return `${text.slice(
        0,
        maxLength - 1
    )}…`;
}


function formatDate(dateValue) {
    const date =
        new Date(dateValue);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return "—";
    }

    return new Intl.DateTimeFormat(
        undefined,
        {
            year: "numeric",
            month: "short",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit"
        }
    ).format(date);
}


function safeJson(value) {
    try {
        return JSON.stringify(
            value,
            null,
            2
        );
    } catch {
        return "{}";
    }
}


function generateId() {
    if (
        typeof crypto !== "undefined" &&
        typeof crypto.randomUUID === "function"
    ) {
        return crypto.randomUUID();
    }

    return [
        Date.now().toString(36),
        Math.random()
            .toString(36)
            .slice(2, 10)
    ].join("-");
}


/* ============================================================
   05. TOAST SYSTEM
   ============================================================ */

function showToast(
    message,
    type = "info",
    duration = 3600
) {
    if (!DOM.toastContainer) {
        return;
    }

    const toast =
        document.createElement("div");

    toast.className =
        "toast";

    const accentMap = {
        success: "var(--green)",
        warning: "var(--amber)",
        error: "var(--red)",
        info: "var(--blue)"
    };

    const accent =
        accentMap[type] ||
        accentMap.info;

    toast.style.borderLeft =
        `2px solid ${accent}`;

    toast.textContent =
        String(message);

    DOM.toastContainer.appendChild(
        toast
    );

    window.setTimeout(() => {
        toast.style.opacity =
            "0";

        toast.style.transform =
            "translateY(5px)";

        window.setTimeout(() => {
            toast.remove();
        }, 180);
    }, duration);
}


/* ============================================================
   06. LOADING STATE
   ============================================================ */

function startLoading(
    message =
        "Running multi-signal security checks..."
) {
    if (
        !DOM.loadingOverlay
    ) {
        return;
    }

    const paragraph =
        DOM.loadingOverlay.querySelector(
            ".loading-panel p"
        );

    if (paragraph) {
        paragraph.textContent =
            message;
    }

    DOM.loadingOverlay.hidden =
        false;

    state.scanInProgress =
        true;

    if (DOM.analyzeBtn) {
        DOM.analyzeBtn.disabled =
            true;

        DOM.analyzeBtn.setAttribute(
            "aria-busy",
            "true"
        );

        const label =
            DOM.analyzeBtn.querySelector(
                "span:nth-child(2)"
            );

        if (label) {
            label.textContent =
                "Analyzing...";
        }
    }

    DOM.loadingOverlay.setAttribute(
        "aria-busy",
        "true"
    );
}


function stopLoading() {
    if (state.loadingTimer) {
        window.clearTimeout(
            state.loadingTimer
        );

        state.loadingTimer =
            null;
    }

    state.scanInProgress =
        false;

    if (DOM.loadingOverlay) {
        DOM.loadingOverlay.hidden =
            true;

        DOM.loadingOverlay.setAttribute(
            "aria-busy",
            "false"
        );
    }

    if (DOM.analyzeBtn) {
        DOM.analyzeBtn.disabled =
            false;

        DOM.analyzeBtn.removeAttribute(
            "aria-busy"
        );

        const label =
            DOM.analyzeBtn.querySelector(
                "span:nth-child(2)"
            );

        if (label) {
            label.textContent =
                "Analyze Threat";
        }
    }
}


/* ============================================================
   07. API REQUEST LAYER
   ============================================================ */

async function fetchWithTimeout(
    url,
    options = {},
    timeoutMs =
        CONFIG.REQUEST_TIMEOUT_MS
) {
    const controller =
        new AbortController();

    const timeoutId =
        window.setTimeout(
            () => {
                controller.abort();
            },
            timeoutMs
        );

    try {
        return await fetch(
            url,
            {
                ...options,
                signal:
                    controller.signal
            }
        );
    } finally {
        window.clearTimeout(
            timeoutId
        );
    }
}


async function fetchJson(
    url,
    options = {},
    timeoutMs =
        CONFIG.REQUEST_TIMEOUT_MS
) {
    let response;

    try {
        response =
            await fetchWithTimeout(
                url,
                {
                    ...options,
                    headers: {
                        Accept:
                            "application/json",
                        ...(options.headers || {})
                    }
                },
                timeoutMs
            );
    } catch (error) {
        if (
            error?.name ===
            "AbortError"
        ) {
            throw new Error(
                "The security service took too long to respond."
            );
        }

        throw new Error(
            "The security service could not be reached."
        );
    }

    const contentType =
        response.headers.get(
            "content-type"
        ) || "";

    let data = null;

    if (
        contentType.includes(
            "application/json"
        )
    ) {
        try {
            data =
                await response.json();
        } catch {
            data = null;
        }
    } else {
        try {
            const text =
                await response.text();

            data = text
                ? { message: text }
                : null;
        } catch {
            data = null;
        }
    }

    if (!response.ok) {
        const detail =
            data?.detail ||
            data?.message ||
            `Request failed with status ${response.status}.`;

        throw new Error(
            typeof detail === "string"
                ? detail
                : safeJson(detail)
        );
    }

    return data;
}


/* ============================================================
   08. BACKEND CONTRACTS
   ============================================================ */

async function scanUrl(url) {
    return fetchJson(
        `${CONFIG.BACKEND_API}/scan/url`,
        {
            method: "POST",

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({
                url
            })
        }
    );
}


async function scanText(text) {
    return fetchJson(
        `${CONFIG.BACKEND_API}/scan/text`,
        {
            method: "POST",

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({
                text
            })
        }
    );
}


async function scanQr(file) {
    const formData =
        new FormData();

    formData.append(
        "file",
        file
    );

    return fetchJson(
        `${CONFIG.BACKEND_API}/scan/quishing`,
        {
            method: "POST",
            body: formData
        }
    );
}


async function checkBackendHealth() {
    try {
        const data =
            await fetchJson(
                `${CONFIG.BACKEND_API}/health`,
                {
                    method: "GET",
                    cache: "no-store"
                },
                CONFIG.HEALTH_TIMEOUT_MS
            );

        state.backendOnline =
            true;

        updateHealthUI(
            true,
            data
        );

        return data;
    } catch {
        state.backendOnline =
            false;

        updateHealthUI(
            false,
            null
        );

        return null;
    }
}


/* ============================================================
   09. HEALTH UI
   ============================================================ */

function updateHealthUI(
    online,
    healthData = null
) {
    if (DOM.apiStatus) {
        DOM.apiStatus.textContent =
            online
                ? "ONLINE"
                : "OFFLINE";

        DOM.apiStatus.style.color =
            online
                ? "var(--green)"
                : "var(--red)";
    }

    if (DOM.engineStatus) {
        const engineValue =
            healthData?.engine ||
            healthData?.model_status ||
            healthData?.ai_status ||
            healthData?.status;

        DOM.engineStatus.textContent =
            online
                ? String(
                    engineValue ||
                    "READY"
                )
                    .slice(0, 18)
                    .toUpperCase()
                : "DEGRADED";

        DOM.engineStatus.style.color =
            online
                ? "var(--green)"
                : "var(--amber)";
    }
}


/* ============================================================
   10. INPUT CLASSIFICATION
   ============================================================ */

function isLikelyUrl(value) {
    const text =
        String(value || "")
            .trim();

    if (!text) {
        return false;
    }

    try {
        const url =
            new URL(text);

        return (
            url.protocol === "http:" ||
            url.protocol === "https:"
        );
    } catch {
        return false;
    }
}


function classifyInput(
    text,
    qrFile = null
) {
    if (qrFile) {
        return "qr";
    }

    if (isLikelyUrl(text)) {
        return "url";
    }

    return "text";
}


function getInputLabel(type) {
    switch (type) {
        case "url":
            return "URL";

        case "qr":
            return "QR";

        case "text":
            return "TEXT";

        default:
            return "INPUT";
    }
}


/* ============================================================
   11. INPUT VALIDATION
   ============================================================ */

function validateTextInput(text) {
    if (!text) {
        return {
            valid: false,
            message:
                "Enter a URL or message to analyze."
        };
    }

    if (
        text.length >
        CONFIG.MAX_INPUT_LENGTH
    ) {
        return {
            valid: false,
            message:
                `Input is too long. Limit: ${CONFIG.MAX_INPUT_LENGTH.toLocaleString()} characters.`
        };
    }

    return {
        valid: true
    };
}


function validateQrFile(file) {
    if (!file) {
        return {
            valid: false,
            message:
                "Select a QR image first."
        };
    }

    if (
        !CONFIG.ALLOWED_QR_TYPES
            .includes(file.type)
    ) {
        return {
            valid: false,
            message:
                "Use a PNG, JPG or WEBP image."
        };
    }

    if (
        file.size >
        CONFIG.MAX_QR_FILE_SIZE
    ) {
        return {
            valid: false,
            message:
                "QR image is too large. Maximum size is 8 MB."
        };
    }

    return {
        valid: true
    };
}


/* ============================================================
   12. FILE / QR UI
   ============================================================ */

function setSelectedQrFile(file) {
    if (
        !DOM.qrFileInput ||
        !DOM.fileNameDisplay
    ) {
        return;
    }

    if (!file) {
        DOM.fileNameDisplay.textContent =
            "";

        state.droppedQrFile =
            null;

        return;
    }

    const validation =
        validateQrFile(
            file
        );

    if (!validation.valid) {
        DOM.qrFileInput.value =
            "";

        DOM.fileNameDisplay.textContent =
            "";

        state.droppedQrFile =
            null;

        showToast(
            validation.message,
            "warning"
        );

        return;
    }

    DOM.fileNameDisplay.textContent =
        `Selected: ${file.name}`;

    DOM.fileNameDisplay.style.color =
        "var(--green)";

    /*
     * Keep the dropped File in state.
     * Native file-input changes are still read directly
     * from DOM.qrFileInput.files.
     */
    state.droppedQrFile =
        DOM.qrFileInput.files?.[0]
            ? null
            : file;

    if (DOM.threatInput) {
        DOM.threatInput.value =
            "";

        updateCharacterCount();
    }

    showToast(
        "QR image attached for analysis.",
        "success",
        2500
    );
}


function getActiveQrFile() {
    return (
        DOM.qrFileInput?.files?.[0] ||
        state.droppedQrFile ||
        null
    );
}


/* ============================================================
   13. CHARACTER COUNT
   ============================================================ */

function updateCharacterCount() {
    if (
        !DOM.characterCount ||
        !DOM.threatInput
    ) {
        return;
    }

    const count =
        DOM.threatInput.value.length;

    DOM.characterCount.textContent =
        `${count.toLocaleString()} characters`;

    if (
        count >
        CONFIG.MAX_INPUT_LENGTH
    ) {
        DOM.characterCount.style.color =
            "var(--red)";
    } else {
        DOM.characterCount.style.color =
            "";
    }
}


/* ============================================================
   14. INITIAL RESULT STATE
   ============================================================ */

function resetResultUI() {
    state.lastScanResult =
        null;

    state.lastScanMeta =
        null;

    state.lastInputType =
        null;

    state.lastInputPreview =
        "";

    state.lastScanAt =
        null;

    if (DOM.severityBadge) {
        DOM.severityBadge.className =
            "badge";

        DOM.severityBadge.textContent =
            "WAITING";
    }

    if (DOM.riskScore) {
        DOM.riskScore.textContent =
            "—";
    }

    if (DOM.threatStatus) {
        DOM.threatStatus.textContent =
            "No scan performed";
    }

    if (DOM.meterBar) {
        DOM.meterBar.style.width =
            "0%";

        DOM.meterBar.style.background =
            getMeterGradient(null);
    }

    if (DOM.meterContainer) {
        DOM.meterContainer.setAttribute(
            "aria-valuenow",
            "0"
        );
    }

    if (DOM.riskGauge) {
        DOM.riskGauge.style.background =
            getGaugeGradient(null);
    }

    if (DOM.explanation) {
        DOM.explanation.innerHTML = `
            <div class="analysis-empty">

                <div class="analysis-empty-icon">
                    ✦
                </div>

                <strong>
                    Awaiting security analysis
                </strong>

                <p>
                    Submit a target above to see the
                    reasoning behind the score, including
                    contributing indicators and model context.
                </p>

            </div>
        `;
    }

    if (DOM.forensicsWrapper) {
        DOM.forensicsWrapper.hidden =
            true;
    }

    if (DOM.xaiList) {
        DOM.xaiList.innerHTML =
            "";
    }

    if (DOM.hopChainWrapper) {
        DOM.hopChainWrapper.hidden =
            true;
    }

    if (DOM.hopChainLogs) {
        DOM.hopChainLogs.innerHTML =
            "";
    }

    if (DOM.redirectEmpty) {
        DOM.redirectEmpty.hidden =
            false;
    }
}


/* ============================================================
   15. ASSESSMENT EXTRACTION
   ============================================================ */

function getAssessment(data) {
    if (
        data &&
        typeof data === "object"
    ) {
        if (
            data.assessment &&
            typeof data.assessment ===
                "object"
        ) {
            return data.assessment;
        }

        if (
            data.result &&
            typeof data.result ===
                "object"
        ) {
            return data.result;
        }
    }

    return (
        data &&
        typeof data === "object"
            ? data
            : {}
    );
}


function getScoreFromAssessment(
    assessment,
    data
) {
    const candidates = [
        assessment?.score,
        assessment?.risk_score,
        assessment?.riskScore,
        data?.risk_score,
        data?.riskScore,
        data?.score
    ];

    for (
        const candidate of candidates
    ) {
        const score =
            clampScore(candidate);

        if (score !== null) {
            return score;
        }
    }

    return null;
}


function getXaiFromAssessment(
    assessment,
    data
) {
    const candidates = [
        assessment?.xai,
        assessment?.explainability,
        assessment?.signals,
        data?.xai,
        data?.explainability,
        data?.signals
    ];

    for (
        const candidate of candidates
    ) {
        if (
            Array.isArray(candidate)
        ) {
            return candidate;
        }
    }

    return [];
}


function getTraceFromData(
    data,
    assessment
) {
    const candidates = [
        assessment?.trace,
        assessment?.redirect_chain,
        assessment?.hops,
        data?.trace,
        data?.redirect_chain,
        data?.hops
    ];

    for (
        const candidate of candidates
    ) {
        if (
            Array.isArray(candidate)
        ) {
            return candidate;
        }
    }

    return [];
}


function getExplanationFromAssessment(
    assessment,
    data,
    score
) {
    const candidates = [
        assessment?.explanation,
        assessment?.summary,
        assessment?.reasoning,
        data?.explanation,
        data?.summary
    ];

    for (
        const candidate of candidates
    ) {
        if (
            typeof candidate ===
                "string" &&
            candidate.trim()
        ) {
            return candidate.trim();
        }
    }

    if (score !== null) {
        return (
            `Risk assessment completed with a score of ${score}/100.`
        );
    }

    return (
        "The security service did not return a usable risk score."
    );
}


/* ============================================================
   16. XAI RENDERING
   ============================================================ */

function normalizeXaiItem(item) {
    if (
        typeof item ===
        "string"
    ) {
        return {
            title: item,
            detail: "",
            impact: null
        };
    }

    if (
        !item ||
        typeof item !==
            "object"
    ) {
        return {
            title: "Risk signal",
            detail: "",
            impact: null
        };
    }

    const title =
        item.feature ||
        item.name ||
        item.signal ||
        item.factor ||
        item.title ||
        "Risk signal";

    const contribution =
        item.contribution ??
        item.impact ??
        item.value ??
        item.weight ??
        null;

    const detail =
        item.description ||
        item.detail ||
        item.reason ||
        "";

    return {
        title:
            String(title),

        detail:
            String(detail || ""),

        impact:
            contribution === null
                ? null
                : String(contribution)
    };
}


function renderXai(items) {
    if (!DOM.xaiList) {
        return;
    }

    DOM.xaiList.innerHTML =
        "";

    if (
        !Array.isArray(items) ||
        items.length === 0
    ) {
        const li =
            document.createElement(
                "li"
            );

        li.textContent =
            "No explainable risk factors were returned.";

        DOM.xaiList.appendChild(
            li
        );

        return;
    }

    items.forEach(
        (item) => {
            const normalized =
                normalizeXaiItem(
                    item
                );

            const li =
                document.createElement(
                    "li"
                );

            const title =
                document.createElement(
                    "strong"
                );

            title.textContent =
                normalized.title;

            li.appendChild(
                title
            );

            if (
                normalized.detail
            ) {
                const detail =
                    document.createElement(
                        "span"
                    );

                detail.textContent =
                    ` — ${normalized.detail}`;

                li.appendChild(
                    detail
                );
            }

            if (
                normalized.impact !==
                null
            ) {
                const impact =
                    document.createElement(
                        "span"
                    );

                impact.textContent =
                    ` [${normalized.impact}]`;

                impact.style.color =
                    "var(--purple)";

                li.appendChild(
                    impact
                );
            }

            DOM.xaiList.appendChild(
                li
            );
        }
    );
}


/* ============================================================
   17. REDIRECT CHAIN RENDERING
   ============================================================ */

function normalizeTraceItem(
    item,
    index
) {
    if (
        typeof item ===
        "string"
    ) {
        return {
            hop:
                index + 1,

            status:
                "",

            url:
                item
        };
    }

    if (
        !item ||
        typeof item !==
            "object"
    ) {
        return {
            hop:
                index + 1,

            status:
                "",

            url:
                JSON.stringify(item)
        };
    }

    return {
        hop:
            item.hop ??
            item.index ??
            index + 1,

        status:
            item.status ??
            item.status_code ??
            item.code ??
            "",

        url:
            item.url ??
            item.location ??
            item.target ??
            item.destination ??
            JSON.stringify(item)
    };
}


function renderRedirectChain(
    trace
) {
    if (
        !DOM.hopChainLogs ||
        !DOM.hopChainWrapper
    ) {
        return;
    }

    DOM.hopChainLogs.innerHTML =
        "";

    if (
        !Array.isArray(trace) ||
        trace.length === 0
    ) {
        DOM.hopChainWrapper.hidden =
            true;

        if (DOM.redirectEmpty) {
            DOM.redirectEmpty.hidden =
                false;
        }

        return;
    }

    DOM.hopChainWrapper.hidden =
        false;

    if (DOM.redirectEmpty) {
        DOM.redirectEmpty.hidden =
            true;
    }

    trace.forEach(
        (item, index) => {
            const row =
                normalizeTraceItem(
                    item,
                    index
                );

            const div =
                document.createElement(
                    "div"
                );

            div.className =
                "hop-item";

            const strong =
                document.createElement(
                    "strong"
                );

            strong.textContent =
                `Hop ${row.hop}`;

            div.appendChild(
                strong
            );

            if (row.status) {
                const status =
                    document.createTextNode(
                        ` [${row.status}]`
                    );

                div.appendChild(
                    status
                );
            }

            const separator =
                document.createTextNode(
                    " — "
                );

            div.appendChild(
                separator
            );

            const url =
                document.createTextNode(
                    String(row.url)
                );

            div.appendChild(
                url
            );

            DOM.hopChainLogs.appendChild(
                div
            );
        }
    );
}


/* ============================================================
   18. RESULT RENDERING
   ============================================================ */

function renderResult(
    data,
    meta = {}
) {
    const assessment =
        getAssessment(data);

    const score =
        getScoreFromAssessment(
            assessment,
            data
        );

    const severity =
        normalizeSeverity(
            assessment?.severity ??
            data?.severity,
            score
        );

    const xai =
        getXaiFromAssessment(
            assessment,
            data
        );

    const trace =
        getTraceFromData(
            data,
            assessment
        );

    const explanationText =
        getExplanationFromAssessment(
            assessment,
            data,
            score
        );

    const isUnavailable =
        score === null ||
        assessment?.unavailable ===
            true ||
        data?.status ===
            "unavailable";

    state.lastScanResult =
        data;

    state.lastScanMeta = {
        ...meta,

        score,

        severity,

        unavailable:
            isUnavailable
    };

    state.lastInputType =
        meta.inputType ||
        state.lastInputType ||
        "text";

    state.lastInputPreview =
        meta.inputPreview ||
        state.lastInputPreview ||
        "";

    state.lastScanAt =
        new Date().toISOString();


    /* -----------------------------------------
       Severity badge
       ----------------------------------------- */

    if (DOM.severityBadge) {
        if (isUnavailable) {
            DOM.severityBadge.className =
                "badge";

            DOM.severityBadge.textContent =
                "UNAVAILABLE";
        } else {
            const severityClass =
                getSeverityClass(
                    severity
                );

            DOM.severityBadge.className =
                `badge ${severityClass}`.trim();

            DOM.severityBadge.textContent =
                getSeverityLabel(
                    severity
                );
        }
    }


    /* -----------------------------------------
       Risk score
       ----------------------------------------- */

    if (DOM.riskScore) {
        DOM.riskScore.textContent =
            score === null
                ? "—"
                : String(score);
    }


    /* -----------------------------------------
       Threat status
       ----------------------------------------- */

    if (DOM.threatStatus) {
        DOM.threatStatus.textContent =
            isUnavailable
                ? "Analysis unavailable"
                : getThreatLabel(
                    severity,
                    score
                );
    }


    /* -----------------------------------------
       Meter
       ----------------------------------------- */

    if (DOM.meterBar) {
        DOM.meterBar.style.width =
            score === null
                ? "0%"
                : `${score}%`;

        DOM.meterBar.style.background =
            getMeterGradient(
                score
            );
    }

    if (DOM.meterContainer) {
        DOM.meterContainer.setAttribute(
            "aria-valuenow",
            score === null
                ? "0"
                : String(score)
        );
    }


    /* -----------------------------------------
       Gauge
       ----------------------------------------- */

    if (DOM.riskGauge) {
        DOM.riskGauge.style.background =
            getGaugeGradient(
                score
            );
    }


    /* -----------------------------------------
       Explanation
       ----------------------------------------- */

    if (DOM.explanation) {
        if (isUnavailable) {
            DOM.explanation.innerHTML = `
                <div class="analysis-empty">

                    <div class="analysis-empty-icon">
                        !
                    </div>

                    <strong>
                        Analysis unavailable
                    </strong>

                    <p>
                        ${escapeHtml(
                            explanationText
                        )}
                    </p>

                </div>
            `;
        } else {
            DOM.explanation.textContent =
                explanationText;
        }
    }


    /* -----------------------------------------
       Forensics
       ----------------------------------------- */

    if (DOM.forensicsWrapper) {
        DOM.forensicsWrapper.hidden =
            false;
    }

    renderXai(
        xai
    );

    renderRedirectChain(
        trace
    );


    /* -----------------------------------------
       Result visibility
       ----------------------------------------- */

    const analysisSection =
        document.getElementById(
            "analysis"
        );

    if (analysisSection) {
        analysisSection.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    }
}


/* ============================================================
   19. LOCAL FALLBACK ANALYSIS
   ============================================================
   This is intentionally conservative.

   It is NOT the primary AI engine.
   It is used only when the backend is unreachable or
   temporarily unavailable for URL/text input.

   QR files are not decoded locally here. A QR fallback
   never pretends that an image was safely analyzed.
   ============================================================ */

function localFallbackTextAnalysis(
    input
) {
    const text =
        String(input || "")
            .trim();

    const normalized =
        text.toLowerCase();

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
        "prize",
        "limited time",
        "final warning"
    ];

    const paymentWords = [
        "upi",
        "bank transfer",
        "payment",
        "card",
        "wallet",
        "refund",
        "transaction"
    ];

    const credentialWords = [
        "password",
        "passcode",
        "login",
        "username",
        "credential",
        "verify your account",
        "security code"
    ];

    const shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "ow.ly",
        "buff.ly"
    ];

    const suspiciousTlds = [
        ".xyz",
        ".top",
        ".click",
        ".work",
        ".zip",
        ".mov",
        ".shop",
        ".live"
    ];


    if (
        urgentWords.some(
            (word) =>
                normalized.includes(
                    word
                )
        )
    ) {
        score += 25;

        reasons.push(
            "Urgency or account-pressure language detected."
        );
    }


    if (
        paymentWords.some(
            (word) =>
                normalized.includes(
                    word
                )
        )
    ) {
        score += 16;

        reasons.push(
            "Payment or transaction-related language detected."
        );
    }


    if (
        credentialWords.some(
            (word) =>
                normalized.includes(
                    word
                )
        )
    ) {
        score += 17;

        reasons.push(
            "Credential or account-verification language detected."
        );
    }


    if (
        normalized.includes(
            "http://"
        )
    ) {
        score += 14;

        reasons.push(
            "Unencrypted HTTP URL detected."
        );
    }


    if (
        shorteners.some(
            (domain) =>
                normalized.includes(
                    domain
                )
        )
    ) {
        score += 19;

        reasons.push(
            "URL-shortening service detected."
        );
    }


    if (
        suspiciousTlds.some(
            (tld) =>
                normalized.includes(
                    tld
                )
        )
    ) {
        score += 18;

        reasons.push(
            "Potentially suspicious domain extension detected."
        );
    }


    if (
        normalized.includes(
            "click here"
        ) &&
        normalized.includes(
            "verify"
        )
    ) {
        score += 12;

        reasons.push(
            "Call-to-action and verification language appear together."
        );
    }


    score =
        clampScore(
            score
        ) ?? 0;


    const severity =
        normalizeSeverity(
            null,
            score
        );


    if (
        reasons.length === 0
    ) {
        reasons.push(
            "No major suspicious pattern was identified by the local fallback."
        );
    }


    return {
        status:
            "fallback",

        input_type:
            "local_heuristic",

        assessment: {
            score,

            severity,

            explanation:
                "Backend analysis was unavailable. A limited local heuristic assessment was used and should not be treated as a substitute for the security engine.",

            xai:
                reasons
        },

        trace:
            []
    };
}


function localFallbackQrAnalysis(
    file
) {
    return {
        status:
            "unavailable",

        input_type:
            "qr_unavailable",

        assessment: {
            score:
                null,

            severity:
                "unknown",

            unavailable:
                true,

            explanation:
                `The QR analysis service was unavailable for "${file?.name || "the selected image"}". The image was not decoded locally, so CyberGuard X is not assigning a safety score.`,

            xai: [
                "QR decoding requires the security service.",
                "No safety verdict was inferred from the filename or image metadata."
            ]
        },

        trace:
            []
    };
}


/* ============================================================
   20. SCAN ORCHESTRATION
   ============================================================ */

async function performScan({
    text = "",
    qrFile = null
} = {}) {
    if (
        state.scanInProgress
    ) {
        return;
    }

    const normalizedText =
        String(text || "")
            .trim();

    const inputType =
        classifyInput(
            normalizedText,
            qrFile
        );


    /* Validate */

    if (qrFile) {
        const validation =
            validateQrFile(
                qrFile
            );

        if (!validation.valid) {
            showToast(
                validation.message,
                "warning"
            );

            return;
        }
    } else {
        const validation =
            validateTextInput(
                normalizedText
            );

        if (!validation.valid) {
            showToast(
                validation.message,
                "warning"
            );

            DOM.threatInput?.focus();

            return;
        }
    }


    const inputPreview =
        qrFile
            ? qrFile.name
            : truncate(
                normalizedText,
                CONFIG.MAX_LOCAL_PREVIEW_LENGTH
            );


    startLoading(
        qrFile
            ? "Decoding and analyzing the QR destination..."
            : isLikelyUrl(
                normalizedText
            )
                ? "Inspecting URL structure, intelligence and risk signals..."
                : "Analyzing content, language and threat indicators..."
    );


    let data = null;

    let usedFallback =
        false;

    let requestError =
        null;


    try {
        if (qrFile) {
            data =
                await scanQr(
                    qrFile
                );
        } else if (
            inputType ===
            "url"
        ) {
            data =
                await scanUrl(
                    normalizedText
                );
        } else {
            data =
                await scanText(
                    normalizedText
                );
        }

    } catch (error) {
        requestError =
            error;

        /*
         * URL / text can use a limited local fallback.
         * QR must never be represented as successfully scanned
         * without actual QR decoding.
         */

        if (!qrFile) {
            usedFallback =
                true;

            data =
                localFallbackTextAnalysis(
                    normalizedText
                );
        } else {
            usedFallback =
                true;

            data =
                localFallbackQrAnalysis(
                    qrFile
                );
        }
    }


    try {
        renderResult(
            data,
            {
                inputType,

                inputPreview,

                source:
                    usedFallback
                        ? "local_fallback"
                        : "backend",

                error:
                    requestError
                        ? requestError.message
                        : null
            }
        );


        const assessment =
            getAssessment(
                data
            );

        const score =
            getScoreFromAssessment(
                assessment,
                data
            );

        const severity =
            normalizeSeverity(
                assessment?.severity ??
                data?.severity,
                score
            );

        const resultStatus =
            state.lastScanMeta?.unavailable
                ? "UNAVAILABLE"
                : usedFallback
                    ? "FALLBACK"
                    : "COMPLETE";


        addHistoryItem({
            id:
                generateId(),

            timestamp:
                new Date().toISOString(),

            type:
                inputType,

            preview:
                inputPreview,

            score,

            severity:
                state.lastScanMeta?.unavailable
                    ? "unknown"
                    : severity,

            status:
                resultStatus,

            source:
                usedFallback
                    ? "local"
                    : "backend"
        });


        updateDashboardMetrics();


        if (usedFallback) {
            if (qrFile) {
                showToast(
                    "QR service unavailable. No QR safety verdict was inferred.",
                    "warning",
                    4800
                );
            } else {
                showToast(
                    "Security service unavailable. Limited local analysis was used.",
                    "warning",
                    4800
                );
            }
        } else {
            showToast(
                "Security analysis completed.",
                "success"
            );
        }

    } finally {
        stopLoading();
    }
}


async function analyzeThreat() {
    if (
        state.scanInProgress
    ) {
        return;
    }

    const text =
        String(
            DOM.threatInput?.value ||
            ""
        ).trim();

    const qrFile =
        getActiveQrFile();


    if (
        !text &&
        !qrFile
    ) {
        showToast(
            "Enter a URL or message, or attach a QR image.",
            "warning"
        );

        DOM.threatInput?.focus();

        return;
    }


    await performScan({
        text,
        qrFile
    });
}


/* ============================================================
   21. LOCAL HISTORY
   ============================================================ */

function loadHistory() {
    try {
        const raw =
            localStorage.getItem(
                CONFIG.HISTORY_STORAGE_KEY
            );

        if (!raw) {
            state.history =
                [];

            return;
        }

        const parsed =
            JSON.parse(
                raw
            );

        if (
            Array.isArray(parsed)
        ) {
            state.history =
                parsed.slice(
                    0,
                    CONFIG.MAX_HISTORY_ITEMS
                );
        } else {
            state.history =
                [];
        }

    } catch {
        state.history =
            [];
    }
}


function persistHistory() {
    try {
        localStorage.setItem(
            CONFIG.HISTORY_STORAGE_KEY,

            JSON.stringify(
                state.history.slice(
                    0,
                    CONFIG.MAX_HISTORY_ITEMS
                )
            )
        );
    } catch {
        /*
         * Storage can be disabled in private browsing or
         * constrained environments. The console continues to work.
         */
    }
}


function addHistoryItem(item) {
    state.history.unshift(
        item
    );

    state.history =
        state.history.slice(
            0,
            CONFIG.MAX_HISTORY_ITEMS
        );

    persistHistory();

    renderHistory();
}


function clearHistory() {
    state.history =
        [];

    persistHistory();

    renderHistory();

    updateDashboardMetrics();

    showToast(
        "Local scan history cleared.",
        "success"
    );
}


function getHistorySeverity(
    severity
) {
    switch (
        normalizeSeverity(
            severity
        )
    ) {
        case "critical":
            return "CRITICAL";

        case "high":
            return "HIGH";

        case "medium":
            return "MEDIUM";

        case "low":
            return "LOW";

        default:
            return "UNKNOWN";
    }
}


function renderHistory() {
    if (
        !DOM.historyTableBody
    ) {
        return;
    }

    if (
        state.history.length === 0
    ) {
        DOM.historyTableBody.innerHTML = `
            <tr class="empty-history">
                <td colspan="6">

                    <div class="history-empty">

                        <span class="history-empty-mark">
                            ◷
                        </span>

                        <strong>
                            No scan history available
                        </strong>

                        <p>
                            Completed assessments will appear here.
                        </p>

                    </div>

                </td>
            </tr>
        `;

        return;
    }


    const rows =
        state.history.map(
            (item) => {
                const type =
                    getInputLabel(
                        item.type
                    );

                const scoreText =
                    item.score === null ||
                    item.score === undefined
                        ? "—"
                        : `${item.score}/100`;

                const severity =
                    getHistorySeverity(
                        item.severity
                    );

                const status =
                    String(
                        item.status ||
                        "COMPLETE"
                    ).toUpperCase();

                return `
                    <tr>

                        <td>
                            ${escapeHtml(type)}
                        </td>

                        <td>
                            ${escapeHtml(
                                truncate(
                                    item.preview,
                                    95
                                )
                            )}
                        </td>

                        <td>
                            ${escapeHtml(
                                scoreText
                            )}
                        </td>

                        <td>
                            ${escapeHtml(
                                severity
                            )}
                        </td>

                        <td>
                            ${escapeHtml(
                                formatDate(
                                    item.timestamp
                                )
                            )}
                        </td>

                        <td>
                            ${escapeHtml(
                                status
                            )}
                        </td>

                    </tr>
                `;
            }
        );


    DOM.historyTableBody.innerHTML =
        rows.join("");
}


/* ============================================================
   22. DASHBOARD METRICS
   ============================================================ */

function updateDashboardMetrics() {
    const total =
        state.history.length;

    const lowRisk =
        state.history.filter(
            (item) =>
                normalizeSeverity(
                    item.severity
                ) === "low"
        ).length;

    const threats =
        state.history.filter(
            (item) => {
                const score =
                    clampScore(
                        item.score
                    );

                const severity =
                    normalizeSeverity(
                        item.severity,
                        score
                    );

                return (
                    severity === "medium" ||
                    severity === "high" ||
                    severity === "critical"
                );
            }
        ).length;


    if (DOM.totalScans) {
        DOM.totalScans.textContent =
            total.toLocaleString();
    }

    if (DOM.threatsDetected) {
        DOM.threatsDetected.textContent =
            threats.toLocaleString();
    }

    if (DOM.lowRiskCount) {
        DOM.lowRiskCount.textContent =
            lowRisk.toLocaleString();
    }
}


/* ============================================================
   23. NAVIGATION
   ============================================================ */

function closeMobileSidebar() {
    if (!DOM.sidebar) {
        return;
    }

    DOM.sidebar.classList.remove(
        "open"
    );

    state.activeMobileNav =
        false;
}


function openMobileSidebar() {
    if (!DOM.sidebar) {
        return;
    }

    DOM.sidebar.classList.add(
        "open"
    );

    state.activeMobileNav =
        true;
}


function updateActiveNavigation(
    sectionId
) {
    DOM.navItems.forEach(
        (item) => {
            const target =
                String(
                    item.dataset.section ||
                    ""
                );

            item.classList.toggle(
                "active",
                target === sectionId
            );
        }
    );
}


function navigateToSection(
    sectionId
) {
    const section =
        document.getElementById(
            sectionId
        );

    if (!section) {
        return;
    }

    section.scrollIntoView({
        behavior:
            "smooth",

        block:
            "start"
    });

    updateActiveNavigation(
        sectionId
    );

    closeMobileSidebar();
}


function setupNavigation() {
    DOM.navItems.forEach(
        (item) => {
            item.addEventListener(
                "click",
                (event) => {
                    const href =
                        item.getAttribute(
                            "href"
                        );

                    if (
                        !href ||
                        !href.startsWith("#")
                    ) {
                        return;
                    }

                    const sectionId =
                        href.slice(1);

                    const section =
                        document.getElementById(
                            sectionId
                        );

                    if (!section) {
                        return;
                    }

                    event.preventDefault();

                    navigateToSection(
                        sectionId
                    );

                    window.history.replaceState(
                        null,
                        "",
                        `#${sectionId}`
                    );
                }
            );
        }
    );


    if (
        "IntersectionObserver" in
        window
    ) {
        state.navigationObserver =
            new IntersectionObserver(
                (entries) => {
                    const visible =
                        entries
                            .filter(
                                (entry) =>
                                    entry.isIntersecting
                            )
                            .sort(
                                (
                                    a,
                                    b
                                ) =>
                                    b.intersectionRatio -
                                    a.intersectionRatio
                            )[0];

                    if (
                        visible?.target?.id
                    ) {
                        updateActiveNavigation(
                            visible.target.id
                        );
                    }
                },
                {
                    rootMargin:
                        "-20% 0px -62% 0px",

                    threshold: [
                        0,
                        0.1,
                        0.25,
                        0.5
                    ]
                }
            );

        DOM.pageSections.forEach(
            (section) => {
                state.navigationObserver.observe(
                    section
                );
            }
        );
    }
}


/* ============================================================
   24. MOBILE SIDEBAR
   ============================================================ */

function setupMobileNavigation() {
    DOM.mobileMenuBtn?.addEventListener(
        "click",
        () => {
            if (
                state.activeMobileNav
            ) {
                closeMobileSidebar();
            } else {
                openMobileSidebar();
            }
        }
    );


    document.addEventListener(
        "keydown",
        (event) => {
            if (
                event.key === "Escape"
            ) {
                closeMobileSidebar();

                closeProfileModal();
            }
        }
    );


    document.addEventListener(
        "click",
        (event) => {
            if (
                !state.activeMobileNav ||
                !DOM.sidebar ||
                !DOM.mobileMenuBtn
            ) {
                return;
            }

            const target =
                event.target;

            if (
                DOM.sidebar.contains(
                    target
                ) ||
                DOM.mobileMenuBtn.contains(
                    target
                )
            ) {
                return;
            }

            closeMobileSidebar();
        }
    );
}


/* ============================================================
   25. PROFILE MODAL
   ============================================================ */

function openProfileModal() {
    if (
        !DOM.profileModal
    ) {
        return;
    }

    DOM.profileModal.hidden =
        false;

    document.body.dataset.modalOpen =
        "true";

    DOM.closeProfileModal?.focus();
}


function closeProfileModal() {
    if (
        !DOM.profileModal
    ) {
        return;
    }

    DOM.profileModal.hidden =
        true;

    delete document.body
        .dataset
        .modalOpen;
}


function setupProfileModal() {
    DOM.profileBtn?.addEventListener(
        "click",
        openProfileModal
    );

    DOM.closeProfileModal?.addEventListener(
        "click",
        closeProfileModal
    );

    DOM.profileModal
        ?.querySelector(
            ".modal-backdrop"
        )
        ?.addEventListener(
            "click",
            closeProfileModal
        );
}


/* ============================================================
   26. QR DRAG / DROP
   ============================================================ */

function setupQrDropzone() {
    if (
        !DOM.qrUploadSection
    ) {
        return;
    }

    const dropzone =
        DOM.qrUploadSection;


    [
        "dragenter",
        "dragover"
    ].forEach(
        (eventName) => {
            dropzone.addEventListener(
                eventName,
                (event) => {
                    event.preventDefault();

                    dropzone.style.borderColor =
                        "rgba(0, 229, 160, 0.35)";

                    dropzone.style.background =
                        "rgba(0, 229, 160, 0.035)";
                }
            );
        }
    );


    [
        "dragleave",
        "drop"
    ].forEach(
        (eventName) => {
            dropzone.addEventListener(
                eventName,
                (event) => {
                    event.preventDefault();

                    dropzone.style.borderColor =
                        "";

                    dropzone.style.background =
                        "";
                }
            );
        }
    );


    dropzone.addEventListener(
        "drop",
        (event) => {
            const file =
                event
                    .dataTransfer
                    ?.files?.[0];

            if (!file) {
                return;
            }

            setSelectedQrFile(
                file
            );

            state.droppedQrFile =
                file;
        }
    );
}


/* ============================================================
   27. INPUT EVENTS
   ============================================================ */

function setupInputEvents() {
    DOM.threatInput?.addEventListener(
        "input",
        () => {
            updateCharacterCount();

            /*
             * If the user types a new message after selecting a QR,
             * clear the QR source so there is no ambiguous scan target.
             */
            if (
                DOM.qrFileInput?.files?.length
            ) {
                DOM.qrFileInput.value =
                    "";

                state.droppedQrFile =
                    null;

                if (DOM.fileNameDisplay) {
                    DOM.fileNameDisplay.textContent =
                        "";

                    DOM.fileNameDisplay.style.color =
                        "";
                }
            }
        }
    );


    DOM.qrFileInput?.addEventListener(
        "change",
        () => {
            const file =
                DOM.qrFileInput.files?.[0] ||
                null;

            state.droppedQrFile =
                null;

            setSelectedQrFile(
                file
            );
        }
    );


    DOM.threatInput?.addEventListener(
        "keydown",
        (event) => {
            /*
             * Ctrl+Enter / Cmd+Enter starts a scan.
             */
            if (
                event.key === "Enter" &&
                (
                    event.ctrlKey ||
                    event.metaKey
                )
            ) {
                event.preventDefault();

                analyzeThreat();
            }
        }
    );
}


/* ============================================================
   28. SCANNER SETUP
   ============================================================ */

function setupScanner() {
    DOM.analyzeBtn?.addEventListener(
        "click",
        analyzeThreat
    );
}


/* ============================================================
   29. REPORT EXPORT
   ============================================================ */

function buildReportPayload() {
    return {
        product:
            "CYBERGUARD X",

        version:
            "1.0",

        generated_at:
            new Date().toISOString(),

        assessment_source:
            state.lastScanMeta?.source ||
            "unknown",

        input: {
            type:
                state.lastInputType ||
                "unknown",

            preview:
                state.lastInputPreview ||
                ""
        },

        assessment:
            state.lastScanResult ||
            null
    };
}


function downloadReport() {
    if (
        !state.lastScanResult
    ) {
        showToast(
            "Run a security scan before exporting a report.",
            "warning"
        );

        return;
    }


    const report =
        buildReportPayload();

    const blob =
        new Blob(
            [
                JSON.stringify(
                    report,
                    null,
                    2
                )
            ],
            {
                type:
                    "application/json;charset=utf-8"
            }
        );


    const url =
        URL.createObjectURL(
            blob
        );

    const anchor =
        document.createElement(
            "a"
        );

    anchor.href =
        url;

    anchor.download =
        `cyberguard-x-report-${Date.now()}.json`;

    document.body.appendChild(
        anchor
    );

    anchor.click();

    anchor.remove();

    window.setTimeout(
        () => {
            URL.revokeObjectURL(
                url
            );
        },
        300
    );


    showToast(
        "JSON security dossier exported.",
        "success"
    );
}


function setupReportExport() {
    DOM.downloadReportBtn?.addEventListener(
        "click",
        downloadReport
    );
}


/* ============================================================
   30. REFRESH
   ============================================================ */

async function refreshConsole() {
    if (
        state.scanInProgress
    ) {
        return;
    }

    if (DOM.refreshBtn) {
        DOM.refreshBtn.disabled =
            true;

        DOM.refreshBtn.style.transform =
            "rotate(180deg)";
    }


    try {
        await Promise.all([
            checkBackendHealth(),

            Promise.resolve(
                loadHistory()
            )
        ]);

        renderHistory();

        updateDashboardMetrics();

        showToast(
            state.backendOnline
                ? "Console refreshed."
                : "Console refreshed. Backend is currently offline.",

            state.backendOnline
                ? "success"
                : "warning"
        );

    } finally {
        if (DOM.refreshBtn) {
            DOM.refreshBtn.disabled =
                false;

            window.setTimeout(
                () => {
                    DOM.refreshBtn.style.transform =
                        "";
                },
                220
            );
        }
    }
}


function setupRefreshControls() {
    DOM.refreshBtn?.addEventListener(
        "click",
        refreshConsole
    );


    DOM.loadHistoryBtn?.addEventListener(
        "click",
        () => {
            loadHistory();

            renderHistory();

            updateDashboardMetrics();

            showToast(
                "Local scan history refreshed.",
                "success",
                2500
            );
        }
    );
}


/* ============================================================
   31. KEYBOARD SHORTCUTS
   ============================================================ */

function setupKeyboardShortcuts() {
    document.addEventListener(
        "keydown",
        (event) => {
            /*
             * Press "/" to focus the scanner.
             */
            if (
                event.key === "/" &&
                !event.ctrlKey &&
                !event.metaKey &&
                !event.altKey
            ) {
                const target =
                    event.target;

                const isTyping =
                    target instanceof
                        HTMLInputElement ||
                    target instanceof
                        HTMLTextAreaElement ||
                    target instanceof
                        HTMLSelectElement;

                if (!isTyping) {
                    event.preventDefault();

                    DOM.threatInput?.focus();
                }
            }
        }
    );
}


/* ============================================================
   32. OPTIONAL WINDOW RESIZE HANDLING
   ============================================================ */

function setupResizeHandling() {
    window.addEventListener(
        "resize",
        () => {
            /*
             * Automatically close the mobile sidebar once
             * desktop width is restored.
             */
            if (
                window.innerWidth > 980 &&
                state.activeMobileNav
            ) {
                closeMobileSidebar();
            }
        }
    );
}


/* ============================================================
   33. PAGE STARTUP
   ============================================================ */

async function initializeCyberGuard() {
    resetResultUI();

    loadHistory();

    renderHistory();

    updateDashboardMetrics();

    updateCharacterCount();

    setupNavigation();

    setupMobileNavigation();

    setupProfileModal();

    setupQrDropzone();

    setupInputEvents();

    setupScanner();

    setupReportExport();

    setupRefreshControls();

    setupKeyboardShortcuts();

    setupResizeHandling();

    /*
     * Check the backend once during startup.
     * The rest of the console remains usable even when
     * the service is temporarily unavailable.
     */
    await checkBackendHealth();
}


/* ============================================================
   34. START APPLICATION
   ============================================================ */

if (
    document.readyState ===
    "loading"
) {
    document.addEventListener(
        "DOMContentLoaded",
        initializeCyberGuard,
        {
            once: true
        }
    );
} else {
    initializeCyberGuard();
}


/* ============================================================
   35. NAMESPACED PUBLIC API
   ============================================================
   Useful for future modular frontend code and debugging.
   ============================================================ */

window.CyberGuardX = Object.freeze({
    version:
        "1.0",

    analyze:
        analyzeThreat,

    refresh:
        refreshConsole,

    clearHistory:
        clearHistory,

    getState() {
        return {
            backendOnline:
                state.backendOnline,

            scanInProgress:
                state.scanInProgress,

            historyCount:
                state.history.length,

            lastInputType:
                state.lastInputType,

            lastScanAt:
                state.lastScanAt
        };
    },

    getLastResult() {
        return state.lastScanResult;
    }
});
