#!/usr/bin/env python3
"""
Train the Isolation Forest model on synthetic data.
For production, replace synthetic data with CICIDS2017 dataset.

Run: python scripts/train_model.py
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

OUTPUT_PATH = Path("models/isolation_forest.pkl")


def generate_normal_traffic(n=5000, seed=42):
    rng = np.random.default_rng(seed)
    return np.column_stack([
        rng.normal(50, 15, n),          # packet_count
        rng.normal(150, 30, n),         # mean_payload_size
        rng.integers(1, 6, n),          # unique_dst_ips
        rng.uniform(0.0, 0.02, n),      # auth_failure_rate
        rng.uniform(0.8, 1.8, n),       # protocol_entropy
        rng.uniform(0.01, 0.1, n),      # interarrival_variance
        rng.uniform(3.5, 4.5, n),       # payload_entropy
    ])


def generate_attack_traffic(n=500, seed=99):
    rng = np.random.default_rng(seed)
    return np.column_stack([
        rng.normal(400, 50, n),         # high packet count (brute-force)
        rng.normal(48, 5, n),           # small payloads (auth packets)
        rng.integers(1, 2, n),          # single destination
        rng.uniform(0.8, 1.0, n),       # very high auth failure rate
        rng.uniform(0.1, 0.3, n),       # low protocol entropy
        rng.uniform(0.001, 0.005, n),   # very low interarrival variance
        rng.uniform(0.5, 1.5, n),       # low payload entropy
    ])


def main():
    print("Generating training data...")
    X_normal = generate_normal_traffic(5000)
    X_attack = generate_attack_traffic(500)
    X_train = X_normal  # Isolation Forest trains on normal only

    print("Training Isolation Forest (150 estimators, max_samples=512)...")
    model = IsolationForest(
        n_estimators=150,
        max_samples=512,
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train)

    # Evaluate on held-out data
    X_test = np.vstack([
        generate_normal_traffic(1000, seed=1),
        generate_attack_traffic(100, seed=2),
    ])
    y_true = np.array([0] * 1000 + [1] * 100)
    scores = -model.score_samples(X_test)  # higher = more anomalous
    auc = roc_auc_score(y_true, scores)
    print(f"Evaluation AUC-ROC: {auc:.4f}")

    # Save
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, OUTPUT_PATH)
    model_hash = hashlib.sha256(OUTPUT_PATH.read_bytes()).hexdigest()
    print(f"Model saved to {OUTPUT_PATH}")
    print(f"Model SHA-256: {model_hash}")
    print("\nAnchor this hash on the blockchain via:")
    print(f"  blockchain.anchorModel('{model_hash}')")


if __name__ == "__main__":
    main()
