"""
CYBERGUARD X — Multi-Signal AI Risk Engine

Responsibilities:
    - Normalize security signals
    - Generate a unified 0-100 risk score
    - Classify severity
    - Generate explainable AI (XAI) findings
    - Apply deterministic high-confidence security rules
    - Provide stable output for the FastAPI backend

IMPORTANT:
    The current LightGBM model is a synthetic/calibration model.
    It is NOT a production-trained cybersecurity classifier.

    Real threat-intelligence feeds, historical domain intelligence,
    production training data and calibrated validation should be
    integrated before treating the score as a real-world verdict.
"""

from dataclasses import dataclass
from typing import Any, Dict, List

import lightgbm as lgb
import numpy as np
import shap


# ============================================================
# THREAT SIGNAL SCHEMA
# ============================================================

@dataclass
class ThreatSignals:
    """
    Normalized security signals consumed by CYBERGUARD X.

    Continuous signals:
        0.0 = low/no signal
        1.0 = strong signal

    Important:
        domain_age_days is currently used by the application as a
        normalized novelty proxy, despite its historical name.
        It is NOT an actual domain-age measurement in the current MVP.
    """

    # Normalized domain novelty proxy.
    # 0.0 = low novelty
    # 1.0 = high novelty
    domain_age_days: float = 0.0

    # Number of observed HTTP redirects.
    redirect_hops: int = 0

    # Brand/domain similarity.
    # 0.0 = no meaningful similarity
    # 1.0 = very high similarity
    typosquat_similarity: float = 0.0

    # NLP urgency/social-engineering score.
    # 0.0 = no urgency
    # 1.0 = strong urgency
    nlp_urgency_score: float = 0.0

    # Current MVP meaning:
    # 1 = insecure transport/protocol condition
    # 0 = normal HTTPS condition
    #
    # This is NOT a DMARC/SPF result.
    auth_failure_flag: int = 0

    # Visual/brand spoof similarity.
    # 0.0 = low similarity
    # 1.0 = strong similarity
    visual_brand_spoof: float = 0.0

    # Number of external/proxy threat indicators.
    external_ioc_hits: int = 0

    # Suspicious UPI/financial pattern.
    # 1 = detected
    # 0 = not detected
    upi_anomaly_flag: int = 0


# ============================================================
# CYBERGUARD X RISK ENGINE
# ============================================================

class CyberGuardRiskEngine:
    """
    Hybrid CYBERGUARD X risk engine.

    Processing pipeline:

        Threat Signals
             ↓
        Input normalization
             ↓
        LightGBM model
             ↓
        Deterministic security rules
             ↓
        SHAP explainability
             ↓
        Human-readable XAI
             ↓
        0-100 risk score
             ↓
        Severity classification

    The model is intentionally deterministic for the current
    prototype so that repeated scans with identical signals produce
    consistent results.
    """

    # ------------------------------------------------------------
    # Model feature names
    # ------------------------------------------------------------

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

    # Human-readable names for XAI.
    FEATURE_LABELS = {
        "domain_novelty": "Domain novelty",
        "redirect_chain_depth": "Redirect chain depth",
        "typosquat_index": "Typosquatting similarity",
        "semantic_urgency": "Urgency / social-engineering language",
        "auth_protocol_failure": "Insecure protocol condition",
        "brand_spoof_similarity": "Brand spoof similarity",
        "threat_feed_reputation": "Threat intelligence indicators",
        "financial_upi_tampering": "UPI / financial anomaly",
    }

    def __init__(self) -> None:
        self.feature_names = list(self.FEATURE_NAMES)

        self.model: Any = None
        self.explainer: Any = None

        self._init_model()

    # ============================================================
    # MODEL INITIALIZATION
    # ============================================================

    def _init_model(self) -> None:
        """
        Create the deterministic synthetic baseline LightGBM model.

        This is a prototype calibration model.

        It must eventually be replaced or supplemented with a model
        trained on validated cybersecurity datasets.
        """

        rng = np.random.default_rng(42)

        sample_count = 1000
        feature_count = len(self.feature_names)

        # --------------------------------------------------------
        # Synthetic normalized feature matrix
        # --------------------------------------------------------

        X = rng.random(
            (
                sample_count,
                feature_count,
            )
        ).astype(np.float32)

        # --------------------------------------------------------
        # Prototype feature weights
        #
        # These weights represent relative importance only.
        # They are NOT learned from real-world attack data.
        # --------------------------------------------------------

        weights = np.array(
            [
                0.20,  # domain novelty
                0.10,  # redirect depth
                0.15,  # typosquatting
                0.10,  # urgency
                0.15,  # protocol condition
                0.10,  # brand spoof
                0.15,  # threat reputation
                0.05,  # UPI
            ],
            dtype=np.float32,
        )

        # --------------------------------------------------------
        # Synthetic risk target
        # --------------------------------------------------------

        y = (
            np.sum(
                X * weights,
                axis=1,
            )
            * 100.0
        )

        y = np.clip(
            y,
            0.0,
            100.0,
        ).astype(np.float32)

        # --------------------------------------------------------
        # LightGBM dataset
        # --------------------------------------------------------

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
            "max_depth": 4,
            "num_leaves": 15,
            "learning_rate": 0.05,
            "feature_fraction": 0.9,
            "bagging_fraction": 0.9,
            "bagging_freq": 1,
            "min_data_in_leaf": 10,
            "seed": 42,
            "feature_fraction_seed": 42,
            "bagging_seed": 42,
            "data_random_seed": 42,
        }

        self.model = lgb.train(
            params,
            train_data,
            num_boost_round=60,
        )

        # --------------------------------------------------------
        # SHAP explainer
        # --------------------------------------------------------

        try:
            self.explainer = shap.TreeExplainer(
                self.model
            )
        except Exception:
            self.explainer = None

    # ============================================================
    # NUMERIC SAFETY
    # ============================================================

    @staticmethod
    def _safe_float(
        value: Any,
        default: float = 0.0,
    ) -> float:
        """
        Safely convert a value to a finite float.
        """

        try:
            numeric = float(value)

            if not np.isfinite(numeric):
                return default

            return numeric

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
        """
        Safely convert a value to an integer.
        """

        try:
            numeric = int(value)
            return numeric

        except (
            TypeError,
            ValueError,
        ):
            return default

    @staticmethod
    def _clamp(
        value: float,
        minimum: float = 0.0,
        maximum: float = 1.0,
    ) -> float:
        """
        Keep a numeric feature inside a defined range.
        """

        numeric = CyberGuardRiskEngine._safe_float(
            value
        )

        return max(
            minimum,
            min(
                numeric,
                maximum,
            ),
        )

    # ============================================================
    # FEATURE VECTOR
    # ============================================================

    def _build_feature_vector(
        self,
        signals: ThreatSignals,
    ) -> np.ndarray:
        """
        Convert ThreatSignals into the normalized feature vector
        expected by LightGBM.
        """

        # --------------------------------------------------------
        # Domain novelty
        # --------------------------------------------------------

        domain_novelty = self._clamp(
            signals.domain_age_days
        )

        # --------------------------------------------------------
        # Redirect depth
        #
        # Five or more redirects saturates this feature at 1.0.
        # --------------------------------------------------------

        redirect_hops = max(
            0,
            self._safe_int(
                signals.redirect_hops
            ),
        )

        redirect_depth = self._clamp(
            redirect_hops / 5.0
        )

        # --------------------------------------------------------
        # Typosquatting
        # --------------------------------------------------------

        typosquat = self._clamp(
            signals.typosquat_similarity
        )

        # --------------------------------------------------------
        # NLP urgency
        # --------------------------------------------------------

        urgency = self._clamp(
            signals.nlp_urgency_score
        )

        # --------------------------------------------------------
        # Protocol/auth condition
        # --------------------------------------------------------

        auth_failure = self._clamp(
            float(
                1
                if self._safe_int(
                    signals.auth_failure_flag
                )
                else 0
            )
        )

        # --------------------------------------------------------
        # Visual brand spoof
        # --------------------------------------------------------

        visual_spoof = self._clamp(
            signals.visual_brand_spoof
        )

        # --------------------------------------------------------
        # External IOC count
        #
        # Three or more indicators saturates at 1.0.
        # --------------------------------------------------------

        ioc_hits = max(
            0,
            self._safe_int(
                signals.external_ioc_hits
            ),
        )

        threat_reputation = self._clamp(
            ioc_hits / 3.0
        )

        # --------------------------------------------------------
        # UPI anomaly
        # --------------------------------------------------------

        upi_anomaly = self._clamp(
            float(
                1
                if self._safe_int(
                    signals.upi_anomaly_flag
                )
                else 0
            )
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

    # ============================================================
    # SEVERITY
    # ============================================================

    @staticmethod
    def _get_severity(
        score: float,
    ) -> str:
        """
        Convert risk score into CYBERGUARD X severity.
        """

        if score >= 90.0:
            return "CRITICAL"

        if score >= 70.0:
            return "HIGH"

        if score >= 40.0:
            return "MEDIUM"

        return "LOW"

    # ============================================================
    # SCORE NORMALIZATION
    # ============================================================

    @staticmethod
    def _normalize_score(
        score: float,
    ) -> float:
        """
        Normalize final score into the official 0-100 range.
        """

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

    # ============================================================
    # SHAP VALUES
    # ============================================================

    def _get_shap_values(
        self,
        feature_vector: np.ndarray,
    ) -> np.ndarray:
        """
        Safely calculate SHAP values.

        Supports common SHAP return formats used across versions.
        """

        if self.explainer is None:
            return np.zeros(
                len(self.feature_names),
                dtype=float,
            )

        try:
            raw_values = self.explainer.shap_values(
                feature_vector
            )

            # Some SHAP versions return a list.
            if isinstance(
                raw_values,
                list,
            ):
                if not raw_values:
                    return np.zeros(
                        len(self.feature_names),
                        dtype=float,
                    )

                raw_values = raw_values[0]

            values = np.asarray(
                raw_values,
                dtype=float,
            )

            # Expected shape:
            # (1, feature_count)
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

            values = np.nan_to_num(
                values,
                nan=0.0,
                posinf=0.0,
                neginf=0.0,
            )

            return values

        except Exception:
            return np.zeros(
                len(self.feature_names),
                dtype=float,
            )

    # ============================================================
    # XAI — MODEL CONTRIBUTIONS
    # ============================================================

    def _build_model_xai(
        self,
        feature_vector: np.ndarray,
    ) -> List[str]:
        """
        Convert positive SHAP contributions into readable findings.
        """

        shap_values = self._get_shap_values(
            feature_vector
        )

        positive_features = []

        for index, value in enumerate(
            shap_values
        ):
            if value > 0:
                positive_features.append(
                    (
                        self.feature_names[index],
                        float(value),
                    )
                )

        positive_features.sort(
            key=lambda item: item[1],
            reverse=True,
        )

        if not positive_features:
            return [
                "Machine-learning baseline did not identify a positive risk contribution."
            ]

        explanations = []

        for (
            feature_name,
            contribution,
        ) in positive_features[:5]:

            label = self.FEATURE_LABELS.get(
                feature_name,
                feature_name.replace(
                    "_",
                    " ",
                ).title(),
            )

            explanations.append(
                f"{label}: "
                f"positive ML contribution "
                f"+{contribution:.2f}"
            )

        return explanations

    # ============================================================
    # XAI — SECURITY SIGNALS
    # ============================================================

    def _build_signal_xai(
        self,
        signals: ThreatSignals,
    ) -> List[str]:
        """
        Generate deterministic explanations directly from security
        signals.

        This complements SHAP because SHAP explains the model,
        while these messages explain the underlying security evidence.
        """

        findings: List[str] = []

        domain_novelty = self._clamp(
            signals.domain_age_days
        )

        redirect_hops = max(
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

        auth_failure = self._safe_int(
            signals.auth_failure_flag
        )

        visual_spoof = self._clamp(
            signals.visual_brand_spoof
        )

        ioc_hits = max(
            0,
            self._safe_int(
                signals.external_ioc_hits
            ),
        )

        upi_anomaly = self._safe_int(
            signals.upi_anomaly_flag
        )

        # --------------------------------------------------------
        # Domain novelty
        # --------------------------------------------------------

        if domain_novelty >= 0.75:
            findings.append(
                "High domain-novelty signal detected."
            )

        elif domain_novelty >= 0.45:
            findings.append(
                "Moderate domain-novelty signal detected."
            )

        # --------------------------------------------------------
        # Redirects
        # --------------------------------------------------------

        if redirect_hops >= 4:
            findings.append(
                f"Long redirect chain detected: {redirect_hops} hops."
            )

        elif redirect_hops >= 2:
            findings.append(
                f"Multiple redirects detected: {redirect_hops} hops."
            )

        elif redirect_hops == 1:
            findings.append(
                "One redirect was observed during navigation."
            )

        # --------------------------------------------------------
        # Typosquatting
        # --------------------------------------------------------

        if typosquat >= 0.90:
            findings.append(
                "Very high similarity to a monitored brand/domain."
            )

        elif typosquat >= 0.75:
            findings.append(
                "High similarity to a monitored brand/domain."
            )

        elif typosquat >= 0.65:
            findings.append(
                "Potential brand-impersonation similarity detected."
            )

        # --------------------------------------------------------
        # Urgency
        # --------------------------------------------------------

        if urgency >= 0.75:
            findings.append(
                "Strong urgency/social-engineering language signal detected."
            )

        elif urgency >= 0.40:
            findings.append(
                "Moderate urgency/social-engineering language signal detected."
            )

        # --------------------------------------------------------
        # Protocol
        # --------------------------------------------------------

        if auth_failure:
            findings.append(
                "Insecure HTTP transport condition detected."
            )

        # --------------------------------------------------------
        # Visual spoofing
        # --------------------------------------------------------

        if visual_spoof >= 0.75:
            findings.append(
                "High visual/brand spoof similarity signal detected."
            )

        elif visual_spoof >= 0.50:
            findings.append(
                "Moderate visual/brand spoof similarity detected."
            )

        # --------------------------------------------------------
        # Threat intelligence
        # --------------------------------------------------------

        if ioc_hits >= 3:
            findings.append(
                f"Multiple threat-intelligence indicators detected: {ioc_hits}."
            )

        elif ioc_hits > 0:
            findings.append(
                f"Threat-intelligence/proxy indicator detected: {ioc_hits}."
            )

        # --------------------------------------------------------
        # UPI
        # --------------------------------------------------------

        if upi_anomaly:
            findings.append(
                "UPI/financial anomaly signal detected."
            )

        return findings

    # ============================================================
    # DETERMINISTIC SECURITY RULES
    # ============================================================

    def _apply_security_rules(
        self,
        signals: ThreatSignals,
        model_score: float,
    ) -> tuple[float, List[str]]:
        """
        Apply high-confidence deterministic security rules.

        These rules do not replace the ML model. They provide
        security guardrails for combinations of strong indicators.
        """

        score = model_score
        rule_findings: List[str] = []

        redirect_hops = max(
            0,
            self._safe_int(
                signals.redirect_hops
            ),
        )

        typosquat = self._clamp(
            signals.typosquat_similarity
        )

        auth_failure = self._safe_int(
            signals.auth_failure_flag
        )

        ioc_hits = max(
            0,
            self._safe_int(
                signals.external_ioc_hits
            ),
        )

        upi_anomaly = self._safe_int(
            signals.upi_anomaly_flag
        )

        urgency = self._clamp(
            signals.nlp_urgency_score
        )

        # --------------------------------------------------------
        # Confirmed/multiple IOC rule
        # --------------------------------------------------------

        if ioc_hits >= 2:
            score = max(
                score,
                90.0,
            )

            rule_findings.append(
                "Security rule: multiple external/proxy threat indicators triggered a high-confidence risk floor."
            )

        # --------------------------------------------------------
        # Strong brand impersonation + HTTP
        # --------------------------------------------------------

        if (
            auth_failure
            and typosquat >= 0.85
        ):
            score = max(
                score,
                90.0,
            )

            rule_findings.append(
                "Security rule: strong brand similarity combined with insecure HTTP triggered a critical-risk floor."
            )

        # --------------------------------------------------------
        # UPI anomaly
        # --------------------------------------------------------

        if upi_anomaly:
            score = max(
                score,
                80.0,
            )

            rule_findings.append(
                "Security rule: UPI/financial anomaly triggered a high-risk floor."
            )

        # --------------------------------------------------------
        # Multiple redirects + suspicious domain
        # --------------------------------------------------------

        if (
            redirect_hops >= 3
            and typosquat >= 0.65
        ):
            score = max(
                score,
                75.0,
            )

            rule_findings.append(
                "Security rule: multiple redirects combined with brand similarity triggered a high-risk floor."
            )

        # --------------------------------------------------------
        # Strong social engineering + financial signal
        # --------------------------------------------------------

        if (
            urgency >= 0.75
            and upi_anomaly
        ):
            score = max(
                score,
                85.0,
            )

            rule_findings.append(
                "Security rule: strong urgency combined with a financial/UPI signal triggered an elevated risk floor."
            )

        # --------------------------------------------------------
        # Strong typosquatting
        # --------------------------------------------------------

        if typosquat >= 0.90:
            score = max(
                score,
                70.0,
            )

            rule_findings.append(
                "Security rule: very high brand/domain similarity triggered a high-risk floor."
            )

        return (
            self._normalize_score(score),
            rule_findings,
        )

    # ============================================================
    # FINAL XAI MERGE
    # ============================================================

    @staticmethod
    def _merge_xai(
        *groups: List[str],
    ) -> List[str]:
        """
        Merge XAI findings while preserving order and removing
        duplicate messages.
        """

        merged: List[str] = []
        seen = set()

        for group in groups:
            for item in group:

                item = str(item).strip()

                if not item:
                    continue

                if item in seen:
                    continue

                seen.add(item)
                merged.append(item)

        return merged

    # ============================================================
    # EXPLANATION
    # ============================================================

    @staticmethod
    def _build_summary(
        score: float,
        severity: str,
        xai: List[str],
    ) -> str:
        """
        Build a concise human-readable assessment summary.
        """

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

        if xai:
            return (
                f"{prefix} "
                f"Unified risk score: {score:.1f}/100."
            )

        return (
            f"{prefix} "
            f"Unified risk score: {score:.1f}/100."
        )

    # ============================================================
    # PUBLIC EVALUATION METHOD
    # ============================================================

    def evaluate(
        self,
        signals: ThreatSignals,
    ) -> Dict[str, Any]:
        """
        Evaluate security signals.

        Returns a stable API object containing:

            score
            risk_score
            severity
            explanation
            xai
            xai_breakdown
            model_score
            rule_adjusted
            features
        """

        if not isinstance(
            signals,
            ThreatSignals,
        ):
            raise TypeError(
                "signals must be an instance of ThreatSignals."
            )

        # --------------------------------------------------------
        # Build feature vector
        # --------------------------------------------------------

        feature_vector = self._build_feature_vector(
            signals
        )

        # --------------------------------------------------------
        # ML prediction
        # --------------------------------------------------------

        try:
            raw_prediction = self.model.predict(
                feature_vector
            )

            model_score = self._normalize_score(
                raw_prediction[0]
            )

        except Exception as exc:
            raise RuntimeError(
                "LightGBM risk prediction failed."
            ) from exc

        # --------------------------------------------------------
        # Deterministic security rules
        # --------------------------------------------------------

        final_score, rule_findings = (
            self._apply_security_rules(
                signals,
                model_score,
            )
        )

        # --------------------------------------------------------
        # SHAP model explanation
        # --------------------------------------------------------

        model_xai = self._build_model_xai(
            feature_vector
        )

        # --------------------------------------------------------
        # Direct security evidence explanation
        # --------------------------------------------------------

        signal_xai = self._build_signal_xai(
            signals
        )

        # --------------------------------------------------------
        # Merge XAI
        # --------------------------------------------------------

        xai = self._merge_xai(
            rule_findings,
            signal_xai,
            model_xai,
        )

        # Keep output manageable.
        xai = xai[:10]

        # --------------------------------------------------------
        # Severity
        # --------------------------------------------------------

        severity = self._get_severity(
            final_score
        )

        # --------------------------------------------------------
        # Explanation
        # --------------------------------------------------------

        explanation = self._build_summary(
            final_score,
            severity,
            xai,
        )

        # --------------------------------------------------------
        # Feature values
        # --------------------------------------------------------

        feature_values = {
            name: round(
                float(feature_vector[0][index]),
                4,
            )
            for index, name in enumerate(
                self.feature_names
            )
        }

        # --------------------------------------------------------
        # Final result
        # --------------------------------------------------------

        return {
            "score": final_score,
            "risk_score": final_score,
            "severity": severity,
            "explanation": explanation,
            "xai": xai,
            "xai_breakdown": xai,
            "model_score": model_score,
            "rule_adjusted": (
                final_score != model_score
            ),
            "features": feature_values,
        }


# ============================================================
# OPTIONAL LOCAL SELF-TEST
# ============================================================

if __name__ == "__main__":
    """
    Basic local sanity test.

    Run:

        python ai/risk_engine.py

    This does not contact external websites or threat feeds.
    """

    engine = CyberGuardRiskEngine()

    test_signals = ThreatSignals(
        domain_age_days=0.8,
        redirect_hops=2,
        typosquat_similarity=0.82,
        nlp_urgency_score=0.75,
        auth_failure_flag=1,
        visual_brand_spoof=0.80,
        external_ioc_hits=1,
        upi_anomaly_flag=0,
    )

    result = engine.evaluate(
        test_signals
    )

    print(
        "\nCYBERGUARD X Risk Engine Test"
    )
    print(
        "------------------------------"
    )
    print(
        f"Risk Score : {result['risk_score']}/100"
    )
    print(
        f"Severity   : {result['severity']}"
    )
    print(
        f"Explanation: {result['explanation']}"
    )

    print("\nXAI:")
    for item in result["xai"]:
        print(
            f" - {item}"
        )
