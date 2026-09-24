"""
CYBERGUARD X — Hybrid Cybersecurity Risk Engine
================================================

Purpose
-------
Combines:

1. Deterministic security signals
2. Optional LightGBM model
3. Optional SHAP explanations
4. High-confidence security rules
5. Optional VirusTotal URL reputation
6. Confidence estimation
7. Evidence/source tracking
8. Stable API output for FastAPI

IMPORTANT
---------
The LightGBM model included here is still a calibration/prototype model
unless you replace it with a production-trained cybersecurity model.

Therefore:

    risk_score != probability of compromise

The score is an internal CYBERGUARD X risk score from 0-100.

VirusTotal is an external reputation source. A positive VT detection
should be treated as evidence, not as an absolute verdict.

Environment variables
---------------------
VIRUSTOTAL_API_KEY
    Optional VirusTotal API key.

CYBERGUARD_ENABLE_VT
    true/false. Default: true when an API key exists.

CYBERGUARD_VT_TIMEOUT
    HTTP timeout in seconds. Default: 8.

CYBERGUARD_VT_POLL_SECONDS
    Seconds between VT analysis polling attempts. Default: 2.

CYBERGUARD_VT_MAX_POLLS
    Maximum VT analysis polling attempts. Default: 4.

CYBERGUARD_ENABLE_LIGHTGBM
    true/false. Default: true.

CYBERGUARD_ENABLE_SHAP
    true/false. Default: true.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

try:
    import lightgbm as lgb
except ImportError:
    lgb = None

try:
    import shap
except ImportError:
    shap = None

import requests


# ============================================================
# ENVIRONMENT CONFIGURATION
# ============================================================

def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY",
    "",
).strip()

ENABLE_VT = _env_bool(
    "CYBERGUARD_ENABLE_VT",
    bool(VIRUSTOTAL_API_KEY),
)

VT_TIMEOUT = _env_float(
    "CYBERGUARD_VT_TIMEOUT",
    8.0,
)

VT_POLL_SECONDS = _env_float(
    "CYBERGUARD_VT_POLL_SECONDS",
    2.0,
)

VT_MAX_POLLS = _env_int(
    "CYBERGUARD_VT_MAX_POLLS",
    4,
)

ENABLE_LIGHTGBM = _env_bool(
    "CYBERGUARD_ENABLE_LIGHTGBM",
    True,
)

ENABLE_SHAP = _env_bool(
    "CYBERGUARD_ENABLE_SHAP",
    True,
)

VT_BASE_URL = (
    "https://www.virustotal.com/api/v3"
)


# ============================================================
# THREAT SIGNAL SCHEMA
# ============================================================

@dataclass
class ThreatSignals:
    """
    Normalized security evidence.

    All continuous signals should be between 0 and 1.

    Compatibility note
    ------------------
    `domain_age_days` is retained for compatibility with the current
    FastAPI backend.

    In the current architecture it means:

        domain novelty score

    NOT literal domain age in days.

    A future API revision should rename this to:

        domain_novelty
    """

    domain_age_days: float = 0.0

    redirect_hops: int = 0

    typosquat_similarity: float = 0.0

    nlp_urgency_score: float = 0.0

    auth_failure_flag: int = 0

    visual_brand_spoof: float = 0.0

    external_ioc_hits: int = 0

    upi_anomaly_flag: int = 0


# ============================================================
# EXTERNAL REPUTATION
# ============================================================

@dataclass
class ReputationResult:
    """
    Normalized external reputation result.

    score
        0.0 = no malicious evidence
        1.0 = strong malicious evidence
    """

    provider: str = "unknown"

    available: bool = False

    scanned: bool = False

    malicious_votes: int = 0

    suspicious_votes: int = 0

    harmless_votes: int = 0

    undetected_votes: int = 0

    timeout_votes: int = 0

    total_engines: int = 0

    reputation_score: float = 0.0

    confidence: float = 0.0

    source_url: Optional[str] = None

    analysis_id: Optional[str] = None

    status: str = "unavailable"

    reason: Optional[str] = None

    raw_stats: Dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================
# ENGINE
# ============================================================

class CyberGuardRiskEngine:
    """
    CYBERGUARD X hybrid risk engine.

    Architecture:

        Raw security evidence
                |
                v
        Feature normalization
                |
          +-----+------+
          |            |
          v            v
       LightGBM    Deterministic
        + SHAP        scoring
          |            |
          +-----+------+
                |
                v
        Security rule layer
                |
                v
        External reputation
                |
                v
        Confidence estimation
                |
                v
        Final 0-100 risk score
                |
                v
        XAI + evidence
    """

    # ========================================================
    # FEATURES
    # ========================================================

    FEATURE_NAMES = [
        "domain_novelty",
        "redirect_chain_depth",
        "typosquat_index",
        "semantic_urgency",
        "auth_protocol_failure",
        "brand_spoof_similarity",
        "threat_feed_reputation",
        "financial_upi_tampering",
    ]

    FEATURE_LABELS = {
        "domain_novelty":
            "Domain novelty",

        "redirect_chain_depth":
            "Redirect chain depth",

        "typosquat_index":
            "Typosquatting similarity",

        "semantic_urgency":
            "Urgency / social-engineering language",

        "auth_protocol_failure":
            "Insecure protocol condition",

        "brand_spoof_similarity":
            "Brand spoof similarity",

        "threat_feed_reputation":
            "External threat intelligence",

        "financial_upi_tampering":
            "UPI / financial anomaly",
    }

    # ========================================================
    # DETERMINISTIC WEIGHTS
    # ========================================================

    FEATURE_WEIGHTS = {
        "domain_novelty": 0.16,
        "redirect_chain_depth": 0.10,
        "typosquat_index": 0.17,
        "semantic_urgency": 0.12,
        "auth_protocol_failure": 0.08,
        "brand_spoof_similarity": 0.14,
        "threat_feed_reputation": 0.18,
        "financial_upi_tampering": 0.05,
    }

    # ========================================================
    # INITIALIZATION
    # ========================================================

    def __init__(self) -> None:

        self.feature_names = list(
            self.FEATURE_NAMES
        )

        self.model: Any = None

        self.explainer: Any = None

        self.model_available = False

        self.shap_available = False

        self._init_model()

    # ========================================================
    # MODEL INITIALIZATION
    # ========================================================

    def _init_model(self) -> None:
        """
        Initialize prototype LightGBM calibration model.

        This is NOT a production cybersecurity classifier.

        If LightGBM is unavailable, the engine continues using
        deterministic scoring.
        """

        if not ENABLE_LIGHTGBM:
            return

        if lgb is None:
            return

        try:

            rng = np.random.default_rng(42)

            sample_count = 1500

            feature_count = len(
                self.feature_names
            )

            X = rng.random(
                (
                    sample_count,
                    feature_count,
                )
            ).astype(np.float32)

            weights = np.array(
                [
                    self.FEATURE_WEIGHTS[name]
                    for name in self.feature_names
                ],
                dtype=np.float32,
            )

            # Add small nonlinear interactions so the
            # prototype model is not purely linear.
            base_score = (
                np.sum(
                    X * weights,
                    axis=1,
                )
                * 100.0
            )

            interaction_bonus = (
                (X[:, 2] * X[:, 5]) * 12.0
                + (X[:, 6] ** 2) * 8.0
                + (X[:, 3] * X[:, 7]) * 6.0
            )

            y = np.clip(
                base_score + interaction_bonus,
                0.0,
                100.0,
            ).astype(np.float32)

            train_data = lgb.Dataset(
                X,
                label=y,
                feature_name=self.feature_names,
                free_raw_data=False,
            )

            params = {
                "objective": "regression",
                "metric": "rmse",
                "verbosity": -1,
                "max_depth": 5,
                "num_leaves": 20,
                "learning_rate": 0.04,
                "feature_fraction": 0.95,
                "bagging_fraction": 0.95,
                "bagging_freq": 1,
                "min_data_in_leaf": 12,
                "seed": 42,
                "feature_fraction_seed": 42,
                "bagging_seed": 42,
                "data_random_seed": 42,
            }

            self.model = lgb.train(
                params,
                train_data,
                num_boost_round=80,
            )

            self.model_available = True

            if ENABLE_SHAP and shap is not None:

                try:

                    self.explainer = (
                        shap.TreeExplainer(
                            self.model
                        )
                    )

                    self.shap_available = True

                except Exception:

                    self.explainer = None

                    self.shap_available = False

        except Exception:

            self.model = None

            self.explainer = None

            self.model_available = False

            self.shap_available = False

    # ========================================================
    # SAFE NUMERIC HELPERS
    # ========================================================

    @staticmethod
    def _safe_float(
        value: Any,
        default: float = 0.0,
    ) -> float:

        try:

            number = float(value)

            if not np.isfinite(number):
                return default

            return number

        except (
            TypeError,
            ValueError,
        ):

            return default

    @staticmethod
    def _safe_int(
        value: Any,
        default: int = 0,
    ) -> int:

        try:

            return int(value)

        except (
            TypeError,
            ValueError,
        ):

            return default

    @staticmethod
    def _clamp(
        value: Any,
        minimum: float = 0.0,
        maximum: float = 1.0,
    ) -> float:

        numeric = (
            CyberGuardRiskEngine
            ._safe_float(value)
        )

        return max(
            minimum,
            min(
                numeric,
                maximum,
            ),
        )

    @staticmethod
    def _unique(
        items: List[str],
    ) -> List[str]:

        output = []

        seen = set()

        for item in items:

            item = str(item).strip()

            if not item:
                continue

            if item in seen:
                continue

            seen.add(item)

            output.append(item)

        return output

    # ========================================================
    # FEATURE VECTOR
    # ========================================================

    def _build_feature_vector(
        self,
        signals: ThreatSignals,
        reputation_score: float = 0.0,
    ) -> np.ndarray:
        """
        Convert normalized threat signals to model features.
        """

        domain_novelty = self._clamp(
            signals.domain_age_days
        )

        redirects = max(
            0,
            self._safe_int(
                signals.redirect_hops
            ),
        )

        redirect_depth = self._clamp(
            redirects / 5.0
        )

        typosquat = self._clamp(
            signals.typosquat_similarity
        )

        urgency = self._clamp(
            signals.nlp_urgency_score
        )

        auth_failure = self._clamp(
            1.0
            if self._safe_int(
                signals.auth_failure_flag
            )
            else 0.0
        )

        visual_spoof = self._clamp(
            signals.visual_brand_spoof
        )

        if reputation_score > 0:
            threat_reputation = (
                self._clamp(
                    reputation_score
                )
            )
        else:
            ioc_hits = max(
                0,
                self._safe_int(
                    signals.external_ioc_hits
                ),
            )

            threat_reputation = self._clamp(
                ioc_hits / 3.0
            )

        upi_anomaly = self._clamp(
            1.0
            if self._safe_int(
                signals.upi_anomaly_flag
            )
            else 0.0
        )

        return np.array(
            [[
                domain_novelty,
                redirect_depth,
                typosquat,
                urgency,
                auth_failure,
                visual_spoof,
                threat_reputation,
                upi_anomaly,
            ]],
            dtype=np.float32,
        )

    # ========================================================
    # DETERMINISTIC BASE SCORE
    # ========================================================

    def _calculate_weighted_score(
        self,
        feature_vector: np.ndarray,
    ) -> float:
        """
        Calculate transparent weighted score.

        This acts as the primary explainable baseline.
        """

        values = feature_vector[0]

        weighted = 0.0

        for index, feature_name in enumerate(
            self.feature_names
        ):

            value = self._clamp(
                values[index]
            )

            weight = (
                self.FEATURE_WEIGHTS[
                    feature_name
                ]
            )

            weighted += (
                value * weight * 100.0
            )

        return self._normalize_score(
            weighted
        )

    # ========================================================
    # LIGHTGBM SCORE
    # ========================================================

    def _calculate_model_score(
        self,
        feature_vector: np.ndarray,
    ) -> Optional[float]:

        if (
            self.model is None
            or not self.model_available
        ):
            return None

        try:

            prediction = self.model.predict(
                feature_vector
            )

            if not prediction:
                return None

            return self._normalize_score(
                prediction[0]
            )

        except Exception:

            return None

    # ========================================================
    # HYBRID SCORE
    # ========================================================

    def _calculate_hybrid_score(
        self,
        deterministic_score: float,
        model_score: Optional[float],
    ) -> float:
        """
        Combine transparent deterministic score with
        prototype ML score.

        Deterministic score receives greater weight because
        it is directly interpretable.
        """

        if model_score is None:

            return deterministic_score

        score = (
            deterministic_score * 0.65
            + model_score * 0.35
        )

        return self._normalize_score(
            score
        )

    # ========================================================
    # SHAP
    # ========================================================

    def _get_shap_values(
        self,
        feature_vector: np.ndarray,
    ) -> np.ndarray:

        if (
            self.explainer is None
            or not self.shap_available
        ):

            return np.zeros(
                len(self.feature_names),
                dtype=float,
            )

        try:

            raw = (
                self.explainer.shap_values(
                    feature_vector
                )
            )

            if isinstance(raw, list):

                if not raw:
                    return np.zeros(
                        len(self.feature_names),
                        dtype=float,
                    )

                raw = raw[0]

            values = np.asarray(
                raw,
                dtype=float,
            )

            if values.ndim == 2:
                values = values[0]

            values = values.reshape(-1)

            if len(values) != len(
                self.feature_names
            ):

                return np.zeros(
                    len(self.feature_names),
                    dtype=float,
                )

            return np.nan_to_num(
                values,
                nan=0.0,
                posinf=0.0,
                neginf=0.0,
            )

        except Exception:

            return np.zeros(
                len(self.feature_names),
                dtype=float,
            )

    # ========================================================
    # MODEL XAI
    # ========================================================

    def _build_model_xai(
        self,
        feature_vector: np.ndarray,
    ) -> List[str]:

        shap_values = (
            self._get_shap_values(
                feature_vector
            )
        )

        contributions = []

        for index, value in enumerate(
            shap_values
        ):

            if value <= 0:
                continue

            name = (
                self.feature_names[index]
            )

            contributions.append(
                (
                    name,
                    float(value),
                )
            )

        contributions.sort(
            key=lambda item: item[1],
            reverse=True,
        )

        findings = []

        for name, contribution in (
            contributions[:5]
        ):

            label = (
                self.FEATURE_LABELS.get(
                    name,
                    name.replace(
                        "_",
                        " ",
                    ).title(),
                )
            )

            findings.append(
                f"ML evidence: {label} "
                f"contributed positively "
                f"({contribution:+.2f})."
            )

        if not findings:

            if self.model_available:

                findings.append(
                    "The ML calibration model did not produce a positive feature contribution."
                )

            else:

                findings.append(
                    "ML model explanation unavailable; deterministic evidence was used."
                )

        return findings

    # ========================================================
    # SIGNAL XAI
    # ========================================================

    def _build_signal_xai(
        self,
        signals: ThreatSignals,
        reputation: Optional[
            ReputationResult
        ] = None,
    ) -> List[str]:

        findings: List[str] = []

        novelty = self._clamp(
            signals.domain_age_days
        )

        redirects = max(
            0,
            self._safe_int(
                signals.redirect_hops
            ),
        )

        typosquat = self._clamp(
            signals.typosquat_similarity
        )

        urgency = self._clamp(
            signals.nlp_urgency_score
        )

        auth = self._safe_int(
            signals.auth_failure_flag
        )

        visual = self._clamp(
            signals.visual_brand_spoof
        )

        ioc_hits = max(
            0,
            self._safe_int(
                signals.external_ioc_hits
            ),
        )

        upi = self._safe_int(
            signals.upi_anomaly_flag
        )

        # ----------------------------------------------------
        # Novelty
        # ----------------------------------------------------

        if novelty >= 0.80:

            findings.append(
                "High domain-novelty signal detected."
            )

        elif novelty >= 0.50:

            findings.append(
                "Moderate domain-novelty signal detected."
            )

        # ----------------------------------------------------
        # Redirects
        # ----------------------------------------------------

        if redirects >= 5:

            findings.append(
                f"Very long redirect chain detected: {redirects} hops."
            )

        elif redirects >= 3:

            findings.append(
                f"Multiple redirects detected: {redirects} hops."
            )

        elif redirects == 2:

            findings.append(
                "Two redirects were observed."
            )

        elif redirects == 1:

            findings.append(
                "One redirect was observed."
            )

        # ----------------------------------------------------
        # Typosquatting
        # ----------------------------------------------------

        if typosquat >= 0.90:

            findings.append(
                "Very high brand/domain similarity detected."
            )

        elif typosquat >= 0.75:

            findings.append(
                "High brand/domain similarity detected."
            )

        elif typosquat >= 0.65:

            findings.append(
                "Potential brand-impersonation similarity detected."
            )

        # ----------------------------------------------------
        # Urgency
        # ----------------------------------------------------

        if urgency >= 0.75:

            findings.append(
                "Strong social-engineering urgency signal detected."
            )

        elif urgency >= 0.40:

            findings.append(
                "Moderate social-engineering urgency signal detected."
            )

        # ----------------------------------------------------
        # HTTP
        # ----------------------------------------------------

        if auth:

            findings.append(
                "Insecure HTTP transport condition detected."
            )

        # ----------------------------------------------------
        # Visual
        # ----------------------------------------------------

        if visual >= 0.75:

            findings.append(
                "High visual/brand spoof similarity detected."
            )

        elif visual >= 0.50:

            findings.append(
                "Moderate visual/brand spoof similarity detected."
            )

        # ----------------------------------------------------
        # IOC
        # ----------------------------------------------------

        if ioc_hits >= 3:

            findings.append(
                f"{ioc_hits} external threat indicators were detected."
            )

        elif ioc_hits > 0:

            findings.append(
                f"{ioc_hits} external threat indicator(s) were detected."
            )

        # ----------------------------------------------------
        # UPI
        # ----------------------------------------------------

        if upi:

            findings.append(
                "UPI/financial anomaly signal detected."
            )

        # ----------------------------------------------------
        # External reputation
        # ----------------------------------------------------

        if reputation is not None:

            if reputation.available:

                if reputation.malicious_votes > 0:

                    findings.append(
                        "External reputation service reported malicious detections."
                    )

                elif reputation.suspicious_votes > 0:

                    findings.append(
                        "External reputation service reported suspicious detections."
                    )

                else:

                    findings.append(
                        "External reputation service returned no malicious detections in the available report."
                    )

        return findings

    # ========================================================
    # SECURITY RULES
    # ========================================================

    def _apply_security_rules(
        self,
        signals: ThreatSignals,
        score: float,
        reputation: Optional[
            ReputationResult
        ] = None,
    ) -> Tuple[float, List[str]]:

        adjusted = score

        findings: List[str] = []

        redirects = max(
            0,
            self._safe_int(
                signals.redirect_hops
            ),
        )

        typo = self._clamp(
            signals.typosquat_similarity
        )

        urgency = self._clamp(
            signals.nlp_urgency_score
        )

        auth = self._safe_int(
            signals.auth_failure_flag
        )

        ioc = max(
            0,
            self._safe_int(
                signals.external_ioc_hits
            ),
        )

        upi = self._safe_int(
            signals.upi_anomaly_flag
        )

        # ----------------------------------------------------
        # External malicious reputation
        # ----------------------------------------------------

        if reputation is not None:

            malicious = (
                reputation.malicious_votes
            )

            suspicious = (
                reputation.suspicious_votes
            )

            if malicious >= 5:

                adjusted = max(
                    adjusted,
                    92.0,
                )

                findings.append(
                    "Security rule: strong external malicious reputation triggered a critical-risk floor."
                )

            elif malicious >= 2:

                adjusted = max(
                    adjusted,
                    85.0,
                )

                findings.append(
                    "Security rule: multiple external malicious detections triggered a high-risk floor."
                )

            elif malicious == 1:

                adjusted = max(
                    adjusted,
                    70.0,
                )

                findings.append(
                    "Security rule: one external malicious detection increased the minimum risk level."
                )

            elif suspicious >= 3:

                adjusted = max(
                    adjusted,
                    65.0,
                )

                findings.append(
                    "Security rule: multiple suspicious external detections increased the minimum risk level."
                )

        # ----------------------------------------------------
        # Multiple independent indicators
        # ----------------------------------------------------

        if ioc >= 2:

            adjusted = max(
                adjusted,
                88.0,
            )

            findings.append(
                "Security rule: multiple external indicators triggered a high-confidence risk floor."
            )

        # ----------------------------------------------------
        # Brand spoof + HTTP
        # ----------------------------------------------------

        if (
            auth
            and typo >= 0.85
        ):

            adjusted = max(
                adjusted,
                88.0,
            )

            findings.append(
                "Security rule: strong brand similarity combined with HTTP transport increased risk."
            )

        # ----------------------------------------------------
        # Strong typosquatting
        # ----------------------------------------------------

        if typo >= 0.92:

            adjusted = max(
                adjusted,
                78.0,
            )

            findings.append(
                "Security rule: very high domain similarity triggered a high-risk floor."
            )

        # ----------------------------------------------------
        # Redirect + impersonation
        # ----------------------------------------------------

        if (
            redirects >= 3
            and typo >= 0.70
        ):

            adjusted = max(
                adjusted,
                78.0,
            )

            findings.append(
                "Security rule: redirect chain combined with brand similarity increased risk."
            )

        # ----------------------------------------------------
        # Financial social engineering
        # ----------------------------------------------------

        if (
            urgency >= 0.75
            and upi
        ):

            adjusted = max(
                adjusted,
                84.0,
            )

            findings.append(
                "Security rule: strong urgency combined with a financial signal increased risk."
            )

        # ----------------------------------------------------
        # UPI anomaly
        # ----------------------------------------------------

        if upi:

            adjusted = max(
                adjusted,
                72.0,
            )

            findings.append(
                "Security rule: financial/UPI anomaly increased the minimum risk level."
            )

        return (
            self._normalize_score(
                adjusted
            ),
            findings,
        )

    # ========================================================
    # SEVERITY
    # ========================================================

    @staticmethod
    def _get_severity(
        score: float,
    ) -> str:

        if score >= 90:

            return "CRITICAL"

        if score >= 70:

            return "HIGH"

        if score >= 40:

            return "MEDIUM"

        return "LOW"

    # ========================================================
    # SCORE NORMALIZATION
    # ========================================================

    @staticmethod
    def _normalize_score(
        score: Any,
    ) -> float:

        try:

            score = float(score)

        except (
            TypeError,
            ValueError,
        ):

            score = 0.0

        if not np.isfinite(score):

            score = 0.0

        return round(
            max(
                0.0,
                min(
                    score,
                    100.0,
                ),
            ),
            1,
        )

    # ========================================================
    # CONFIDENCE
    # ========================================================

    def _calculate_confidence(
        self,
        signals: ThreatSignals,
        reputation: Optional[
            ReputationResult
        ],
        model_available: bool,
    ) -> float:
        """
        Confidence is NOT probability of maliciousness.

        It represents how much usable evidence the engine had.
        """

        confidence = 0.25

        evidence_count = 0

        if (
            signals.typosquat_similarity
            >= 0.65
        ):
            evidence_count += 1

        if (
            signals.nlp_urgency_score
            >= 0.40
        ):
            evidence_count += 1

        if (
            signals.redirect_hops
            >= 2
        ):
            evidence_count += 1

        if (
            signals.external_ioc_hits
            > 0
        ):
            evidence_count += 1

        if (
            signals.upi_anomaly_flag
        ):
            evidence_count += 1

        if (
            signals.auth_failure_flag
        ):
            evidence_count += 1

        if (
            signals.visual_brand_spoof
            >= 0.50
        ):
            evidence_count += 1

        confidence += min(
            evidence_count * 0.07,
            0.35,
        )

        if model_available:

            confidence += 0.10

        if (
            reputation is not None
            and reputation.available
        ):

            confidence += (
                0.20
                * reputation.confidence
            )

        return round(
            max(
                0.0,
                min(
                    confidence,
                    1.0,
                ),
            ),
            3,
        )

    # ========================================================
    # SUMMARY
    # ========================================================

    @staticmethod
    def _build_summary(
        score: float,
        severity: str,
        confidence: float,
    ) -> str:

        if severity == "CRITICAL":

            prefix = (
                "Critical-risk indicators were identified."
            )

        elif severity == "HIGH":

            prefix = (
                "High-risk indicators were identified."
            )

        elif severity == "MEDIUM":

            prefix = (
                "Suspicious indicators were identified."
            )

        else:

            prefix = (
                "No major high-confidence risk indicators were identified."
            )

        return (
            f"{prefix} "
            f"CYBERGUARD X risk score: "
            f"{score:.1f}/100. "
            f"Evidence confidence: "
            f"{confidence * 100:.0f}%."
        )

    # ========================================================
    # VIRUSTOTAL HELPERS
    # ========================================================

    @staticmethod
    def _vt_headers() -> Dict[str, str]:

        return {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "Accept": "application/json",
        }

    @staticmethod
    def _url_identifier(
        target_url: str,
    ) -> str:

        return (
            base64.urlsafe_b64encode(
                target_url.encode(
                    "utf-8"
                )
            )
            .decode(
                "ascii"
            )
            .rstrip("=")
        )

    @staticmethod
    def _url_hash(
        target_url: str,
    ) -> str:

        return hashlib.sha256(
            target_url.encode(
                "utf-8"
            )
        ).hexdigest()

    @staticmethod
    def _parse_vt_stats(
        stats: Dict[str, Any],
    ) -> ReputationResult:

        malicious = int(
            stats.get(
                "malicious",
                0,
            )
            or 0
        )

        suspicious = int(
            stats.get(
                "suspicious",
                0,
            )
            or 0
        )

        harmless = int(
            stats.get(
                "harmless",
                0,
            )
            or 0
        )

        undetected = int(
            stats.get(
                "undetected",
                0,
            )
            or 0
        )

        timeout = int(
            stats.get(
                "timeout",
                0,
            )
            or 0
        )

        total = (
            malicious
            + suspicious
            + harmless
            + undetected
            + timeout
        )

        if total <= 0:

            reputation_score = 0.0

            confidence = 0.0

        else:

            # Malicious results receive full weight.
            # Suspicious results receive half weight.
            weighted_bad = (
                malicious
                + suspicious * 0.5
            )

            reputation_score = min(
                weighted_bad / total,
                1.0,
            )

            # More scanners = stronger evidence.
            confidence = min(
                total / 20.0,
                1.0,
            )

        return ReputationResult(
            provider="VirusTotal",
            available=True,
            scanned=True,
            malicious_votes=malicious,
            suspicious_votes=suspicious,
            harmless_votes=harmless,
            undetected_votes=undetected,
            timeout_votes=timeout,
            total_engines=total,
            reputation_score=round(
                reputation_score,
                4,
            ),
            confidence=round(
                confidence,
                4,
            ),
            raw_stats=dict(stats),
            status="completed",
        )

    # ========================================================
    # VIRUSTOTAL SYNC OPERATIONS
    # ========================================================

    def _vt_get_url_report_sync(
        self,
        target_url: str,
    ) -> ReputationResult:

        if not ENABLE_VT:

            return ReputationResult(
                provider="VirusTotal",
                available=False,
                reason=(
                    "VirusTotal integration disabled."
                ),
                status="disabled",
            )

        if not VIRUSTOTAL_API_KEY:

            return ReputationResult(
                provider="VirusTotal",
                available=False,
                reason=(
                    "VIRUSTOTAL_API_KEY is not configured."
                ),
                status="not_configured",
            )

        url_id = self._url_identifier(
            target_url
        )

        endpoint = (
            f"{VT_BASE_URL}/urls/"
            f"{url_id}"
        )

        try:

            response = requests.get(
                endpoint,
                headers=self._vt_headers(),
                timeout=VT_TIMEOUT,
            )

        except requests.RequestException as exc:

            return ReputationResult(
                provider="VirusTotal",
                available=False,
                reason=(
                    f"VirusTotal request failed: {exc}"
                ),
                status="network_error",
            )

        if response.status_code == 200:

            try:

                payload = response.json()

                attributes = (
                    payload
                    .get("data", {})
                    .get("attributes", {})
                )

                stats = (
                    attributes
                    .get(
                        "last_analysis_stats",
                        {},
                    )
                )

                result = (
                    self._parse_vt_stats(
                        stats
                    )
                )

                result.source_url = endpoint

                return result

            except Exception as exc:

                return ReputationResult(
                    provider="VirusTotal",
                    available=False,
                    reason=(
                        f"Invalid VirusTotal response: {exc}"
                    ),
                    status="invalid_response",
                )

        if response.status_code == 404:

            return ReputationResult(
                provider="VirusTotal",
                available=True,
                scanned=False,
                source_url=endpoint,
                status="not_found",
                reason=(
                    "URL does not currently have a retrievable VirusTotal report."
                ),
            )

        if response.status_code == 401:

            return ReputationResult(
                provider="VirusTotal",
                available=False,
                source_url=endpoint,
                status="unauthorized",
                reason=(
                    "VirusTotal API key was rejected."
                ),
            )

        if response.status_code == 429:

            return ReputationResult(
                provider="VirusTotal",
                available=False,
                source_url=endpoint,
                status="rate_limited",
                reason=(
                    "VirusTotal API rate limit was reached."
                ),
            )

        return ReputationResult(
            provider="VirusTotal",
            available=False,
            source_url=endpoint,
            status=f"http_{response.status_code}",
            reason=(
                f"VirusTotal returned HTTP {response.status_code}."
            ),
        )

    # ========================================================
    # VIRUSTOTAL SUBMIT URL
    # ========================================================

    def _vt_submit_url_sync(
        self,
        target_url: str,
    ) -> Tuple[Optional[str], Optional[str]]:

        if not ENABLE_VT:
            return None, "VirusTotal integration disabled."

        if not VIRUSTOTAL_API_KEY:
            return None, "VirusTotal API key not configured."

        endpoint = (
            f"{VT_BASE_URL}/urls"
        )

        try:

            response = requests.post(
                endpoint,
                headers={
                    "x-apikey":
                        VIRUSTOTAL_API_KEY,
                },
                data={
                    "url": target_url,
                },
                timeout=VT_TIMEOUT,
            )

        except requests.RequestException as exc:

            return None, str(exc)

        if response.status_code not in {
            200,
            201,
        }:

            if response.status_code == 429:

                return (
                    None,
                    "VirusTotal rate limit reached.",
                )

            if response.status_code == 401:

                return (
                    None,
                    "VirusTotal API key rejected.",
                )

            return (
                None,
                f"VirusTotal submission failed with HTTP {response.status_code}.",
            )

        try:

            payload = response.json()

            analysis_id = (
                payload
                .get("data", {})
                .get("id")
            )

            return (
                analysis_id,
                None,
            )

        except Exception as exc:

            return (
                None,
                f"Invalid VirusTotal submission response: {exc}",
            )

    # ========================================================
    # VIRUSTOTAL ANALYSIS STATUS
    # ========================================================

    def _vt_get_analysis_sync(
        self,
        analysis_id: str,
    ) -> Optional[Dict[str, Any]]:

        endpoint = (
            f"{VT_BASE_URL}/analyses/"
            f"{analysis_id}"
        )

        try:

            response = requests.get(
                endpoint,
                headers=self._vt_headers(),
                timeout=VT_TIMEOUT,
            )

            if response.status_code != 200:

                return None

            return response.json()

        except (
            requests.RequestException,
            ValueError,
        ):

            return None

    # ========================================================
    # VIRUSTOTAL POLLING
    # ========================================================

    def _vt_poll_analysis_sync(
        self,
        analysis_id: str,
    ) -> Optional[Dict[str, Any]]:

        for attempt in range(
            VT_MAX_POLLS
        ):

            result = (
                self._vt_get_analysis_sync(
                    analysis_id
                )
            )

            if not result:
                return None

            attributes = (
                result
                .get("data", {})
                .get("attributes", {})
            )

            status = attributes.get(
                "status"
            )

            if status == "completed":

                return result

            if attempt < (
                VT_MAX_POLLS - 1
            ):

                time.sleep(
                    VT_POLL_SECONDS
                )

        return None

    # ========================================================
    # VIRUSTOTAL COMPLETE CHECK
    # ========================================================

    def _check_virustotal_sync(
        self,
        target_url: str,
        submit_if_missing: bool = True,
    ) -> ReputationResult:

        # ----------------------------------------------------
        # First try existing report.
        # ----------------------------------------------------

        existing = (
            self._vt_get_url_report_sync(
                target_url
            )
        )

        if existing.scanned:

            return existing

        if (
            not submit_if_missing
            or existing.status != "not_found"
        ):

            return existing

        # ----------------------------------------------------
        # Submit URL for analysis.
        # ----------------------------------------------------

        analysis_id, error = (
            self._vt_submit_url_sync(
                target_url
            )
        )

        if not analysis_id:

            existing.reason = (
                error
                or existing.reason
                or "VirusTotal submission failed."
            )

            existing.status = (
                "submission_failed"
            )

            return existing

        # ----------------------------------------------------
        # Poll analysis.
        # ----------------------------------------------------

        analysis = (
            self._vt_poll_analysis_sync(
                analysis_id
            )
        )

        if not analysis:

            return ReputationResult(
                provider="VirusTotal",
                available=True,
                scanned=False,
                analysis_id=analysis_id,
                status="analysis_pending",
                reason=(
                    "VirusTotal analysis was submitted but did not complete within the configured polling window."
                ),
            )

        attributes = (
            analysis
            .get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "stats",
            {}
        )

        result = (
            self._parse_vt_stats(
                stats
            )
        )

        result.analysis_id = (
            analysis_id
        )

        result.status = "completed"

        result.source_url = (
            f"{VT_BASE_URL}/analyses/"
            f"{analysis_id}"
        )

        return result

    # ========================================================
    # ASYNC VIRUSTOTAL
    # ========================================================

    async def check_virustotal_url(
        self,
        target_url: str,
        submit_if_missing: bool = True,
    ) -> Dict[str, Any]:
        """
        Async-safe VirusTotal URL reputation check.

        The underlying requests library is synchronous, so the network
        operation is moved to a worker thread and does not directly block
        the FastAPI event loop.
        """

        result = await asyncio.to_thread(
            self._check_virustotal_sync,
            target_url,
            submit_if_missing,
        )

        return result.to_dict()

    # ========================================================
    # EXTERNAL INTELLIGENCE NORMALIZATION
    # ========================================================

    @staticmethod
    def reputation_to_ioc_count(
        reputation: Optional[
            ReputationResult
        ],
    ) -> int:

        if reputation is None:
            return 0

        if reputation.malicious_votes >= 5:
            return 3

        if reputation.malicious_votes >= 2:
            return 2

        if (
            reputation.malicious_votes >= 1
            or reputation.suspicious_votes >= 3
        ):
            return 1

        return 0

    # ========================================================
    # MAIN EVALUATION
    # ========================================================

    def evaluate(
        self,
        signals: ThreatSignals,
        reputation: Optional[
            Dict[str, Any] | ReputationResult
        ] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate local security signals.

        This remains synchronous for compatibility with the current
        FastAPI backend.

        For VirusTotal-aware scanning use:

            await evaluate_with_external_intelligence(...)
        """

        if not isinstance(
            signals,
            ThreatSignals,
        ):

            raise TypeError(
                "signals must be a ThreatSignals instance."
            )

        reputation_object = (
            self._coerce_reputation(
                reputation
            )
        )

        # ----------------------------------------------------
        # Feature vector
        # ----------------------------------------------------

        reputation_score = (
            reputation_object.reputation_score
            if reputation_object is not None
            else 0.0
        )

        feature_vector = (
            self._build_feature_vector(
                signals,
                reputation_score,
            )
        )

        # ----------------------------------------------------
        # Transparent score
        # ----------------------------------------------------

        deterministic_score = (
            self._calculate_weighted_score(
                feature_vector
            )
        )

        # ----------------------------------------------------
        # ML score
        # ----------------------------------------------------

        model_score = (
            self._calculate_model_score(
                feature_vector
            )
        )

        # ----------------------------------------------------
        # Hybrid score
        # ----------------------------------------------------

        hybrid_score = (
            self._calculate_hybrid_score(
                deterministic_score,
                model_score,
            )
        )

        # ----------------------------------------------------
        # Security rules
        # ----------------------------------------------------

        final_score, rule_findings = (
            self._apply_security_rules(
                signals,
                hybrid_score,
                reputation_object,
            )
        )

        # ----------------------------------------------------
        # XAI
        # ----------------------------------------------------

        model_xai = (
            self._build_model_xai(
                feature_vector
            )
        )

        signal_xai = (
            self._build_signal_xai(
                signals,
                reputation_object,
            )
        )

        xai = self._unique(
            rule_findings
            + signal_xai
            + model_xai
        )[:12]

        # ----------------------------------------------------
        # Severity
        # ----------------------------------------------------

        severity = self._get_severity(
            final_score
        )

        # ----------------------------------------------------
        # Confidence
        # ----------------------------------------------------

        confidence = (
            self._calculate_confidence(
                signals,
                reputation_object,
                self.model_available,
            )
        )

        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        explanation = (
            self._build_summary(
                final_score,
                severity,
                confidence,
            )
        )

        # ----------------------------------------------------
        # Feature values
        # ----------------------------------------------------

        feature_values = {}

        for index, name in enumerate(
            self.feature_names
        ):

            feature_values[name] = round(
                float(
                    feature_vector[
                        0
                    ][
                        index
                    ]
                ),
                4,
            )

        # ----------------------------------------------------
        # Evidence
        # ----------------------------------------------------

        evidence = {
            "deterministic_score":
                deterministic_score,

            "model_score":
                model_score,

            "hybrid_score":
                hybrid_score,

            "rule_adjusted":
                final_score != hybrid_score,

            "external_reputation":
                (
                    reputation_object.to_dict()
                    if reputation_object
                    else None
                ),
        }

        # ----------------------------------------------------
        # Final result
        # ----------------------------------------------------

        return {
            "score": final_score,

            "risk_score": final_score,

            "severity": severity,

            "confidence": confidence,

            "confidence_percent": round(
                confidence * 100,
                1,
            ),

            "explanation": explanation,

            "xai": xai,

            "xai_breakdown": xai,

            "model_score": (
                model_score
                if model_score is not None
                else deterministic_score
            ),

            "deterministic_score":
                deterministic_score,

            "hybrid_score":
                hybrid_score,

            "rule_adjusted":
                final_score != hybrid_score,

            "features":
                feature_values,

            "evidence":
                evidence,

            "engine": {
                "version": "3.0.0",
                "lightgbm_available":
                    self.model_available,
                "shap_available":
                    self.shap_available,
                "virustotal_enabled":
                    ENABLE_VT,
                "score_type":
                    "hybrid_risk_score",
                "score_range":
                    "0-100",
                "score_semantics":
                    "risk score, not probability",
            },
        }

    # ========================================================
    # REPUTATION COERCION
    # ========================================================

    @staticmethod
    def _coerce_reputation(
        reputation: Optional[
            Dict[str, Any] | ReputationResult
        ],
    ) -> Optional[
        ReputationResult
    ]:

        if reputation is None:

            return None

        if isinstance(
            reputation,
            ReputationResult,
        ):

            return reputation

        if not isinstance(
            reputation,
            dict,
        ):

            return None

        try:

            return ReputationResult(
                provider=str(
                    reputation.get(
                        "provider",
                        "unknown",
                    )
                ),

                available=bool(
                    reputation.get(
                        "available",
                        False,
                    )
                ),

                scanned=bool(
                    reputation.get(
                        "scanned",
                        False,
                    )
                ),

                malicious_votes=int(
                    reputation.get(
                        "malicious_votes",
                        0,
                    )
                    or 0
                ),

                suspicious_votes=int(
                    reputation.get(
                        "suspicious_votes",
                        0,
                    )
                    or 0
                ),

                harmless_votes=int(
                    reputation.get(
                        "harmless_votes",
                        0,
                    )
                    or 0
                ),

                undetected_votes=int(
                    reputation.get(
                        "undetected_votes",
                        0,
                    )
                    or 0
                ),

                timeout_votes=int(
                    reputation.get(
                        "timeout_votes",
                        0,
                    )
                    or 0
                ),

                total_engines=int(
                    reputation.get(
                        "total_engines",
                        0,
                    )
                    or 0
                ),

                reputation_score=float(
                    reputation.get(
                        "reputation_score",
                        0.0,
                    )
                    or 0.0
                ),

                confidence=float(
                    reputation.get(
                        "confidence",
                        0.0,
                    )
                    or 0.0
                ),

                source_url=reputation.get(
                    "source_url"
                ),

                analysis_id=reputation.get(
                    "analysis_id"
                ),

                status=str(
                    reputation.get(
                        "status",
                        "unknown",
                    )
                ),

                reason=reputation.get(
                    "reason"
                ),

                raw_stats=dict(
                    reputation.get(
                        "raw_stats",
                        {},
                    )
                    or {}
                ),
            )

        except Exception:

            return None

    # ========================================================
    # COMPLETE EXTERNAL-INTELLIGENCE PIPELINE
    # ========================================================

    async def evaluate_with_external_intelligence(
        self,
        signals: ThreatSignals,
        target_url: Optional[str] = None,
        submit_if_missing: bool = True,
    ) -> Dict[str, Any]:
        """
        Full URL evaluation pipeline.

        1. Query VirusTotal if a URL is provided.
        2. Convert VT reputation into threat intelligence.
        3. Evaluate local signals.
        4. Return unified result.
        """

        reputation = None

        if (
            target_url
            and ENABLE_VT
        ):

            reputation = (
                await self.check_virustotal_url(
                    target_url,
                    submit_if_missing,
                )
            )

            vt_ioc_count = (
                self.reputation_to_ioc_count(
                    self._coerce_reputation(
                        reputation
                    )
                )
            )

            # Add external intelligence to the local
            # signal set without mutating the caller's object.
            signals = ThreatSignals(
                domain_age_days=
                    signals.domain_age_days,

                redirect_hops=
                    signals.redirect_hops,

                typosquat_similarity=
                    signals.typosquat_similarity,

                nlp_urgency_score=
                    signals.nlp_urgency_score,

                auth_failure_flag=
                    signals.auth_failure_flag,

                visual_brand_spoof=
                    signals.visual_brand_spoof,

                external_ioc_hits=max(
                    signals.external_ioc_hits,
                    vt_ioc_count,
                ),

                upi_anomaly_flag=
                    signals.upi_anomaly_flag,
            )

        result = self.evaluate(
            signals,
            reputation=reputation,
        )

        result["external_intelligence"] = {
            "virustotal":
                reputation
        }

        return result

    # ========================================================
    # HEALTH
    # ========================================================

    def health(self) -> Dict[str, Any]:

        return {
            "engine":
                "CyberGuardRiskEngine",

            "version":
                "3.0.0",

            "lightgbm":
                self.model_available,

            "shap":
                self.shap_available,

            "virustotal_enabled":
                ENABLE_VT,

            "virustotal_configured":
                bool(
                    VIRUSTOTAL_API_KEY
                ),

            "features":
                list(
                    self.feature_names
                ),

            "score_range":
                "0-100",

            "score_semantics":
                "hybrid cybersecurity risk score",
        }


# ============================================================
# GLOBAL ENGINE INSTANCE
# ============================================================

risk_engine = CyberGuardRiskEngine()


# ============================================================
# BACKWARD-COMPATIBLE FUNCTION
# ============================================================

async def check_virustotal_url(
    target_url: str,
    submit_if_missing: bool = True,
) -> Dict[str, Any]:
    """
    Backward-compatible helper.

    Existing backend code can import:

        from ai.risk_engine import check_virustotal_url
    """

    return await risk_engine.check_virustotal_url(
        target_url,
        submit_if_missing,
    )


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    engine = CyberGuardRiskEngine()

    signals = ThreatSignals(
        domain_age_days=0.80,
        redirect_hops=3,
        typosquat_similarity=0.86,
        nlp_urgency_score=0.75,
        auth_failure_flag=1,
        visual_brand_spoof=0.80,
        external_ioc_hits=1,
        upi_anomaly_flag=0,
    )

    result = engine.evaluate(
        signals
    )

    print()
    print(
        "CYBERGUARD X RISK ENGINE TEST"
    )
    print(
        "=============================="
    )

    print(
        f"Risk Score : "
        f"{result['risk_score']}/100"
    )

    print(
        f"Severity   : "
        f"{result['severity']}"
    )

    print(
        f"Confidence : "
        f"{result['confidence_percent']}%"
    )

    print(
        f"Explanation: "
        f"{result['explanation']}"
    )

    print()
    print("Features:")

    for key, value in (
        result["features"].items()
    ):

        print(
            f"  {key}: {value}"
        )

    print()
    print("XAI:")

    for item in result["xai"]:

        print(
            f"  - {item}"
        )
