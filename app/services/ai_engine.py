"""
Edge AI service — loads the serialized Isolation Forest model and scores
7-feature telemetry vectors.

If no model file exists (first run / dev), a fresh untrained model is used
and a warning is logged. Run scripts/train_model.py to produce a proper model.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

import joblib
import numpy as np

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

FEATURE_ORDER = [
    "packet_count",
    "mean_payload_size",
    "unique_dst_ips",
    "auth_failure_rate",
    "protocol_entropy",
    "interarrival_variance",
    "payload_entropy",
]


class AIEngine:
    def __init__(self):
        self._model = None
        self._model_hash: Optional[str] = None
        self._loaded = False

    def _load(self):
        if self._loaded:
            return
        model_path = Path(settings.MODEL_PATH)
        if model_path.exists():
            try:
                self._model = joblib.load(model_path)
                raw = model_path.read_bytes()
                self._model_hash = hashlib.sha256(raw).hexdigest()
                logger.info("Isolation Forest model loaded", path=str(model_path), hash=self._model_hash[:16])
            except Exception as e:
                logger.error("Failed to load model", error=str(e))
                self._model = self._create_default_model()
        else:
            logger.warning("Model file not found — using untrained placeholder", path=str(model_path))
            self._model = self._create_default_model()
        self._loaded = True

    def _create_default_model(self):
        from sklearn.ensemble import IsolationForest

        model = IsolationForest(
            n_estimators=150,
            max_samples=512,
            contamination=0.05,
            random_state=42,
        )
        # Fit on synthetic normal data so the model is usable
        rng = np.random.default_rng(42)
        synthetic = rng.normal(loc=0.5, scale=0.15, size=(1000, len(FEATURE_ORDER)))
        synthetic = np.clip(synthetic, 0, 1)
        model.fit(synthetic)
        return model

    def score(self, features: Dict[str, float]) -> Tuple[float, float]:
        """
        Returns (anomaly_score, inference_ms).
        anomaly_score ∈ [0, 1] — higher means more anomalous.
        Threshold is 0.85 (settings.ANOMALY_THRESHOLD).
        """
        self._load()
        vector = np.array([[features.get(f, 0.0) for f in FEATURE_ORDER]], dtype=np.float32)

        t0 = time.perf_counter()
        raw_scores = self._model.score_samples(vector)   # negative: lower = more anomalous
        ms = (time.perf_counter() - t0) * 1000

        # Convert sklearn's decision function to [0, 1] where 1 = most anomalous
        # sklearn score_samples returns values roughly in [-0.5, 0.5]
        # We map: score = 0.5 - raw_score (so higher raw = less anomalous = lower sentinel score)
        sentinel_score = float(np.clip(0.5 - raw_scores[0], 0.0, 1.0))
        return sentinel_score, round(ms, 3)

    def is_alert(self, score: float) -> bool:
        return score >= settings.ANOMALY_THRESHOLD

    @property
    def model_hash(self) -> Optional[str]:
        self._load()
        return self._model_hash

    def save_model(self, model, path: Optional[str] = None) -> str:
        """Save a trained model and return its SHA-256 hash."""
        save_path = Path(path or settings.MODEL_PATH)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, save_path)
        raw = save_path.read_bytes()
        h = hashlib.sha256(raw).hexdigest()
        self._model = model
        self._model_hash = h
        self._loaded = True
        logger.info("Model saved", path=str(save_path), hash=h[:16])
        return h


ai_engine = AIEngine()
