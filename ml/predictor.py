"""
🛡️ Cyber Sentinel - ML Prediction Engine
Loads trained model and provides real-time threat classification.
"""
import pickle, numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from ml.train_model import FEATURE_NAMES, ATTACK_TYPES

MODEL_DIR = Path(__file__).parent / "models"

class ThreatPredictor:
    """Real-time threat prediction engine using the trained ensemble model."""
    def __init__(self):
        self.model = None; self.scaler = None; self.label_encoder = None
        self.iso_forest = None; self.feature_importance = None
        self._loaded = False

    def load_model(self, path: str = None):
        mp = Path(path) if path else MODEL_DIR / "ensemble_model.pkl"
        if not mp.exists():
            print(f"[!] Model not found at {mp}. Run training first.")
            return False
        with open(mp, "rb") as f:
            bundle = pickle.load(f)
        self.model = bundle["ensemble"]
        self.scaler = bundle["scaler"]
        self.label_encoder = bundle["label_encoder"]
        self.iso_forest = bundle.get("isolation_forest")
        self.feature_importance = bundle.get("feature_importance", {})
        self.results = bundle.get("results", {})
        self._loaded = True
        print("[+] Model loaded successfully")
        return True

    @property
    def is_loaded(self): return self._loaded

    def predict(self, features: Dict) -> Dict:
        if not self._loaded:
            return {"error": "Model not loaded", "attack_type": "Unknown", "confidence": 0}
        vec = np.array([features.get(f, 0) for f in FEATURE_NAMES]).reshape(1, -1)
        vec_scaled = self.scaler.transform(vec)
        pred = self.model.predict(vec_scaled)[0]
        proba = self.model.predict_proba(vec_scaled)[0]
        label = self.label_encoder.inverse_transform([pred])[0]
        confidence = float(np.max(proba))
        # Anomaly score
        anomaly_score = 0.0
        if self.iso_forest:
            raw = self.iso_forest.decision_function(vec_scaled)[0]
            anomaly_score = float(max(0, min(1, (0.5 - raw))))
        # Severity
        severity_score = self._calc_severity(label, confidence, anomaly_score)
        severity = self._severity_label(severity_score)
        # Top features
        top_features = self._get_top_features(features)
        explanation = self._generate_explanation(label, confidence, top_features, features)
        return {
            "attack_type": label, "confidence": round(confidence, 4),
            "severity": severity, "severity_score": round(severity_score, 2),
            "anomaly_score": round(anomaly_score, 4),
            "all_probabilities": {self.label_encoder.inverse_transform([i])[0]: round(float(p), 4) for i, p in enumerate(proba)},
            "top_features": top_features, "explanation": explanation,
            "model_used": "Ensemble Hybrid"
        }

    def predict_batch(self, features_list: List[Dict]) -> List[Dict]:
        return [self.predict(f) for f in features_list]

    def _calc_severity(self, label, conf, anomaly):
        base = {"DDoS":85,"Port Scan":50,"Brute Force":70,"Botnet":90,"SQL Injection":80,"Web Attack":65,"DoS Slowloris":60,"Normal":5}
        s = base.get(label, 50) * conf
        s += anomaly * 20
        return min(100, max(0, s))

    def _severity_label(self, score):
        if score >= 80: return "critical"
        if score >= 60: return "high"
        if score >= 40: return "medium"
        if score >= 20: return "low"
        return "info"

    def _get_top_features(self, features, n=5):
        if not self.feature_importance: return {}
        sorted_f = sorted(self.feature_importance.items(), key=lambda x: x[1], reverse=True)[:n]
        return {k: {"importance": round(v, 4), "value": features.get(k, 0)} for k, v in sorted_f}

    def _generate_explanation(self, label, conf, top_feats, features):
        if label == "Normal":
            return f"Traffic classified as normal with {conf*100:.1f}% confidence."
        parts = [f"Detected {label} attack with {conf*100:.1f}% confidence."]
        if top_feats:
            key_f = list(top_feats.keys())[:3]
            parts.append(f"Key indicators: {', '.join(key_f)}.")
        if features.get("connection_rate", 0) > 100:
            parts.append(f"High connection rate: {features['connection_rate']:.0f}/sec.")
        if features.get("ip_reputation_score", 0) > 0.5:
            parts.append("Source IP has poor reputation score.")
        return " ".join(parts)

# Singleton
_predictor = None
def get_predictor() -> ThreatPredictor:
    global _predictor
    if _predictor is None:
        _predictor = ThreatPredictor()
        _predictor.load_model()
    return _predictor
