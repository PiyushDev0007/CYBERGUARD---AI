from dataclasses import dataclass
from typing import Any, Dict

import lightgbm as lgb
import numpy as np
import shap


# -------------------------------------------------------------------
# Threat Signal Schema
# -------------------------------------------------------------------

@dataclass
class ThreatSignals:
    """
    Normalized security signals consumed by the CYBERGUARD X
    multi-signal risk engine.

    Most continuous signals are expected to be between 0.0 and 1.0.
    """

    # 0.0 = low novelty / older-looking infrastructure
    # 1.0 = high novelty / suspiciously new-looking infrastructure
    domain_age_days: float

    # Number of observed HTTP redirects.
    redirect_hops: int

    # 0.0 = no meaningful brand similarity
    # 1.0 = very high similarity
    typosquat_similarity: float

    # 0.0 = low urgency
    # 1.0 = strong urgency/social-engineering signal
    nlp_urgency_score: float

    # Current MVP meaning:
    # 1 = insecure transport/protocol condition
    # 0 = normal HTTPS condition
    #
    # NOTE:
    # This is NOT a real DMARC/SPF result.
    auth_failure_flag: int

    # 0.0 = low visual/brand similarity
    # 1.0 = strong similarity
    visual_brand_spoof: float

    # Number of external/proxy threat indicators.
    external_ioc_hits: int

    # 1 = suspicious UPI/financial pattern detected
    # 0 = no such pattern detected
    upi_anomaly_flag: int


# -------------------------------------------------------------------
# CYBERGUARD X Risk Engine
# -------------------------------------------------------------------

class CyberGuardRiskEngine:
    """
    Hybrid cybersecurity risk engine.

    Architecture:
        Security Signals
              ↓
        Feature Normalization
              ↓
        LightGBM Risk Model
              ↓
        Deterministic Security Rules
              ↓
        SHAP Explainability
              ↓
        0–100 Risk Score
    """

    def __init__(self) -> None:

        self.feature_names = [
            "domain_novelty",
            "redirect_chain_depth",
            "typosquat_index",
            "semantic_urgency",
            "auth_protocol_failure",
            "brand_spoof_similarity",
            "threat_feed_reputation",
            "financial_upi_tampering",
        ]

        self.model = None
        self.explainer = None

        self._init_model()

    # ----------------------------------------------------------------
    # Model Initialization
    # ----------------------------------------------------------------

    def _init_model(self) -> None:
        """
        Creates a synthetic baseline model for the current prototype.

        IMPORTANT:
        This is a calibration/prototype model, not a production-trained
        cybersecurity classifier.
        """

        rng = np.random.default_rng(42)

        sample_count = 500
        feature_count = len(self.feature_names)

        # Synthetic normalized feature matrix.
        X = rng.random(
            (sample_count, feature_count)
        )

        # Prototype weighting for risk calibration.
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
            dtype=float,
        )

        # Synthetic continuous risk target.
        y = np.clip(
            np.sum(X * weights, axis=1) * 100.0,
            0.0,
            100.0,
        )

        train_data = lgb.Dataset(
            X,
            label=y,
            feature_name=self.feature_names,
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
            "seed": 42,
        }

        self.model = lgb.train(
            params,
            train_data,
            num_boost_round=40,
        )

        self.explainer = shap.TreeExplainer(
            self.model
        )

    # ----------------------------------------------------------------
    # Input Normalization
    # ----------------------------------------------------------------

    @staticmethod
    def _clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
        """Keeps a numeric feature inside the expected range."""

        return max(
            minimum,
            min(float(value), maximum),
        )

    def _build_feature_vector(
        self,
        signals: ThreatSignals,
    ) -> np.ndarray:
        """
        Converts ThreatSignals into the normalized feature vector
        expected by the LightGBM model.
        """

        feature_vector = np.array(
            [[
                self._clamp(
                    signals.domain_age_days
                ),

                self._clamp(
                    signals.redirect_hops / 5.0
                ),

                self._clamp(
                    signals.typosquat_similarity
                ),

                self._clamp(
                    signals.nlp_urgency_score
                ),

                self._clamp(
                    float(signals.auth_failure_flag)
                ),

                self._clamp(
                    signals.visual_brand_spoof
                ),

                self._clamp(
                    signals.external_ioc_hits / 3.0
                ),

                self._clamp(
                    float(signals.upi_anomaly_flag)
                ),
            ]],
            dtype=float,
        )

        return feature_vector

    # ----------------------------------------------------------------
    # Severity
    # ----------------------------------------------------------------

    @staticmethod
    def _get_severity(score: float) -> str:
        """Maps the final risk score to a severity level."""

        if score >= 75:
            return "CRITICAL"

        if score >= 50:
            return "HIGH"

        if score >= 25:
            return "MEDIUM"

        return "LOW"

    # ----------------------------------------------------------------
    # SHAP Explainability
    # ----------------------------------------------------------------

    def _build_xai_breakdown(
        self,
        feature_vector: np.ndarray,
    ) -> list[str]:
        """
        Generates human-readable positive-risk contributors.

        SHAP values indicate how each feature contributed to the
        model prediction relative to the model baseline.
        """

        if self.explainer is None:
            return [
                "Explainability engine unavailable."
            ]

        try:
            shap_raw = self.explainer.shap_values(
                feature_vector
            )

            shap_values = np.asarray(
                shap_raw,
                dtype=float,
            ).reshape(-1)

            positive_features = []

            for name, value in zip(
                self.feature_names,
                shap_values,
            ):
                if value > 0:
                    positive_features.append(
                        (
                            name,
                            float(value),
                        )
                    )

            # Highest positive contributors first.
            positive_features.sort(
                key=lambda item: item[1],
                reverse=True,
            )

            if not positive_features:
                return [
                    "Baseline Security: No positive ML risk contribution detected."
                ]

            explanations = []

            for name, value in positive_features[:5]:

                readable_name = (
                    name
                    .replace("_", " ")
                    .title()
                )

                explanations.append(
                    f"{readable_name}: "
                    f"Positive risk contribution "
                    f"+{value:.1f}"
                )

            return explanations

        except Exception:
            return [
                "XAI calculation completed with limited attribution detail."
            ]

    # ----------------------------------------------------------------
    # Risk Evaluation
    # ----------------------------------------------------------------

    def evaluate(
        self,
        signals: ThreatSignals,
    ) -> Dict[str, Any]:
        """
        Evaluates a set of security signals and returns:

        - risk_score
        - severity
        - XAI breakdown
        """

        feature_vector = self._build_feature_vector(
            signals
        )

        # ------------------------------------------------------------
        # ML Prediction
        # ------------------------------------------------------------

        raw_score = float(
            self.model.predict(
                feature_vector
            )[0]
        )

        raw_score = max(
            0.0,
            min(raw_score, 100.0),
        )

        final_score = raw_score

        # ------------------------------------------------------------
        # Deterministic Security Overrides
        # ------------------------------------------------------------
        #
        # These rules are intentionally kept outside the ML model.
        # In security systems, certain high-confidence indicators
        # can trigger a minimum risk threshold.
        # ------------------------------------------------------------

        if (
            signals.external_ioc_hits >= 2
            or (
                signals.auth_failure_flag
                and signals.typosquat_similarity > 0.85
            )
        ):
            final_score = max(
                final_score,
                90.0,
            )

        elif signals.upi_anomaly_flag == 1:
            final_score = max(
                final_score,
                80.0,
            )

        final_score = max(
            0.0,
            min(final_score, 100.0),
        )

        # ------------------------------------------------------------
        # Explainability
        # ------------------------------------------------------------

        xai_breakdown = self._build_xai_breakdown(
            feature_vector
        )

        # ------------------------------------------------------------
        # Severity
        # ------------------------------------------------------------

        severity = self._get_severity(
            final_score
        )

        # ------------------------------------------------------------
        # Final Response
        # ------------------------------------------------------------

        return {
            "risk_score": round(
                final_score,
                1,
            ),
            "severity": severity,
            "xai_breakdown": xai_breakdown,
    }
