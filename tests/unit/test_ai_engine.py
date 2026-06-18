"""Unit tests for the AI Engine (Isolation Forest scorer)."""
import numpy as np
import pytest

from app.services.ai_engine import AIEngine, FEATURE_ORDER


@pytest.fixture
def engine():
    e = AIEngine()
    e._load()  # trigger model init
    return e


def _normal_features():
    return {
        "packet_count": 50.0,
        "mean_payload_size": 150.0,
        "unique_dst_ips": 3,
        "auth_failure_rate": 0.01,
        "protocol_entropy": 1.2,
        "interarrival_variance": 0.05,
        "payload_entropy": 4.0,
    }


def _attack_features():
    return {
        "packet_count": 450.0,
        "mean_payload_size": 48.0,
        "unique_dst_ips": 1,
        "auth_failure_rate": 0.95,
        "protocol_entropy": 0.1,
        "interarrival_variance": 0.001,
        "payload_entropy": 0.9,
    }


class TestAIEngine:
    def test_score_returns_float_in_range(self, engine):
        score, ms = engine.score(_normal_features())
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0
        assert ms >= 0.0

    def test_normal_traffic_low_score(self, engine):
        score, _ = engine.score(_normal_features())
        assert score < 0.85, f"Normal traffic should not trigger alert, got {score}"

    def test_attack_traffic_higher_score(self, engine):
        normal_score, _ = engine.score(_normal_features())
        attack_score, _ = engine.score(_attack_features())
        assert attack_score > normal_score, "Attack traffic should score higher than normal"

    def test_is_alert_threshold(self, engine):
        assert not engine.is_alert(0.5)
        assert not engine.is_alert(0.84)
        assert engine.is_alert(0.85)
        assert engine.is_alert(0.99)

    def test_missing_features_defaults_to_zero(self, engine):
        score, _ = engine.score({})
        assert 0.0 <= score <= 1.0

    def test_feature_order_constant(self):
        assert len(FEATURE_ORDER) == 7
        assert "packet_count" in FEATURE_ORDER
        assert "auth_failure_rate" in FEATURE_ORDER
