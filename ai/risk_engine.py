import numpy as np
import shap
import lightgbm as lgb
from dataclasses import dataclass
from typing import Dict, List, Any

@dataclass
class ThreatSignals:
    domain_age_days: float          # Inverted: 1 (new < 7 days), 0 (old)
    redirect_hops: int              # min(hops / 5.0, 1.0)
    typosquat_similarity: float     # Levenshtein/Jaro score [0.0 - 1.0]
    nlp_urgency_score: float        # Semantic urgency [0.0 - 1.0]
    auth_failure_flag: int          # DMARC/SPF fail: 1, pass: 0
    visual_brand_spoof: float       # Visual brand similarity [0.0 - 1.0]
    external_ioc_hits: int          # min(hits / 3.0, 1.0)
    upi_anomaly_flag: int           # 1 if deceptive VPA/reverse charge, else 0

class CyberGuardRiskEngine:
    def __init__(self):
        self.feature_names = [
            "domain_novelty", "redirect_chain_depth", "typosquat_index",
            "semantic_urgency", "auth_protocol_failure", "brand_spoof_similarity",
            "threat_feed_reputation", "financial_upi_tampering"
        ]
        self._init_model()

    def _init_model(self):
        # Synthetic baseline dataset for risk calibration
        np.random.seed(42)
        X = np.random.rand(500, len(self.feature_names))
        weights = np.array([0.20, 0.10, 0.15, 0.10, 0.15, 0.10, 0.15, 0.05])
        y = np.clip(np.sum(X * weights, axis=1) * 100, 0, 100)

        train_data = lgb.Dataset(X, label=y)
        params = {
            "objective": "regression",
            "metric": "rmse",
            "verbosity": -1,
            "max_depth": 4,
            "learning_rate": 0.05
        }
        self.model = lgb.train(params, train_data, num_boost_round=30)
        self.explainer = shap.TreeExplainer(self.model)

    def evaluate(self, signals: ThreatSignals) -> Dict[str, Any]:
        feature_vector = np.array([[
            signals.domain_age_days,
            min(signals.redirect_hops / 5.0, 1.0),
            signals.typosquat_similarity,
            signals.nlp_urgency_score,
            float(signals.auth_failure_flag),
            signals.visual_brand_spoof,
            min(signals.external_ioc_hits / 3.0, 1.0),
            float(signals.upi_anomaly_flag)
        ]])

        # Predict Base Risk Score
        raw_score = float(self.model.predict(feature_vector)[0])

        # Critical Overrides
        if signals.external_ioc_hits >= 2 or (signals.auth_failure_flag and signals.typosquat_similarity > 0.85):
            final_score = max(raw_score, 90.0)
        elif signals.upi_anomaly_flag == 1:
            final_score = max(raw_score, 80.0)
        else:
            final_score = min(max(raw_score, 0.0), 100.0)

        # XAI Attribution via SHAP
        shap_values = self.explainer.shap_values(feature_vector)[0]
        attributions = [
            f"{name.replace('_', ' ').title()}: Impact +{round(float(val), 1)}"
            for name, val in zip(self.feature_names, shap_values)
            if val > 0.8
        ]

        severity = (
            "CRITICAL" if final_score >= 75 else
            "HIGH" if final_score >= 50 else
            "MEDIUM" if final_score >= 25 else "LOW"
        )

        return {
            "risk_score": round(final_score, 1),
            "severity": severity,
            "xai_breakdown": attributions
      }
              
