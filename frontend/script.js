const analyzeBtn = document.getElementById("analyzeBtn");
const threatInput = document.getElementById("threatInput");
const riskScore = document.getElementById("riskScore");
const threatStatus = document.getElementById("threatStatus");
const explanation = document.getElementById("explanation");

analyzeBtn.addEventListener("click", function () {

    const input = threatInput.value.trim();

    if (input === "") {
        riskScore.innerHTML = "Risk Score: <strong>--/100</strong>";
        threatStatus.textContent = "⚠️ Please enter something to analyze.";
        explanation.textContent = "Enter a URL, SMS, email or suspicious content.";
        return;
    }

    let score = 0;
    let reasons = [];

    // Basic suspicious keyword detection
    const suspiciousWords = [
        "urgent",
        "verify",
        "password",
        "kyc",
        "winner",
        "prize",
        "otp",
        "click here",
        "account suspended"
    ];

    const lowerInput = input.toLowerCase();

    suspiciousWords.forEach(function (word) {
        if (lowerInput.includes(word)) {
            score += 10;
            reasons.push("Suspicious keyword detected: " + word);
        }
    });

    // Basic URL detection
    if (lowerInput.includes("http://")) {
        score += 15;
        reasons.push("Unencrypted HTTP URL detected");
    }

    if (lowerInput.includes("bit.ly") || lowerInput.includes("tinyurl")) {
        score += 20;
        reasons.push("URL shortener detected");
    }

    // Limit score to 100
    score = Math.min(score, 100);

    riskScore.innerHTML =
        "Risk Score: <strong>" + score + "/100</strong>";

    if (score >= 70) {
        threatStatus.textContent = "🔴 CRITICAL — High Risk Threat";
    } else if (score >= 40) {
        threatStatus.textContent = "🟠 WARNING — Suspicious Activity";
    } else if (score > 0) {
        threatStatus.textContent = "🟡 LOW RISK — Some Suspicious Signals";
    } else {
        threatStatus.textContent = "🟢 No obvious threat detected";
    }

    if (reasons.length > 0) {
        explanation.innerHTML =
            "<strong>Detection Signals:</strong><br>" +
            reasons.join("<br>");
    } else {
        explanation.textContent =
            "No obvious suspicious signals were detected by the basic scanner.";
    }
});
