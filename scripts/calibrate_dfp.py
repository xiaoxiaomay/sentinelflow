#!/usr/bin/env python3
"""
scripts/calibrate_dfp.py

Compute DFP baselines from the existing corpora:
  - Entropy/co-occurrence statistics from benign LLM outputs
  - Strategy cluster centroid from secrets.jsonl
  - Normal cluster centroid from public corpus samples

Updates recommended baseline values for config.yaml.

Usage:
    python scripts/calibrate_dfp.py --config config.yaml --sample_size 100
"""

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.dfp import (
    structural_entropy_score,
    cooccurrence_score,
    extract_feature_vector,
    build_cluster_centroids,
    save_centroids,
)


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_jsonl(path: str):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main():
    ap = argparse.ArgumentParser(description="Calibrate DFP baselines for SentinelFlow")
    ap.add_argument("--config", default="config.yaml", type=str)
    ap.add_argument("--sample_size", default=100, type=int, help="Max normal samples to use")
    ap.add_argument("--output_config", action="store_true", help="Print recommended config values")
    args = ap.parse_args()

    cfg = load_config(args.config)
    dfp_cfg = cfg.get("dfp", {}) or {}

    print("=== SentinelFlow DFP Calibration ===\n")

    # 1. Load secret texts
    paths_cfg = cfg.get("paths", {})
    secrets_path = "data/secrets/secrets.jsonl"
    secrets = load_jsonl(secrets_path)
    secret_texts = [s.get("text", "") for s in secrets if s.get("text")]
    print(f"Loaded {len(secret_texts)} secret texts from {secrets_path}")

    # 2. Load normal texts from public corpus
    corpus_path = "data/processed/public_corpus.jsonl"
    corpus = load_jsonl(corpus_path)
    normal_texts = [c.get("text", "") for c in corpus if c.get("text")]
    if len(normal_texts) > args.sample_size:
        import random
        random.seed(42)
        normal_texts = random.sample(normal_texts, args.sample_size)
    print(f"Loaded {len(normal_texts)} normal texts from {corpus_path}")

    if not secret_texts or not normal_texts:
        print("\n[ERROR] Need both secret and normal texts for calibration.")
        return

    # 3. Compute entropy baselines from normal texts
    print("\nComputing entropy baselines from normal corpus...")
    char_entropies = []
    word_entropies = []
    numeric_densities = []
    param_specificities = []

    for text in normal_texts:
        result = structural_entropy_score(text)
        char_entropies.append(result["char_entropy"])
        word_entropies.append(result["word_entropy"])
        numeric_densities.append(result["numeric_density"])
        param_specificities.append(result["param_specificity"])

    baselines = {
        "char_entropy_mean": round(float(np.mean(char_entropies)), 4),
        "char_entropy_std": round(float(np.std(char_entropies)), 4),
        "word_entropy_mean": round(float(np.mean(word_entropies)), 4),
        "word_entropy_std": round(float(np.std(word_entropies)), 4),
        "numeric_density_mean": round(float(np.mean(numeric_densities)), 4),
        "numeric_density_std": round(float(np.std(numeric_densities)), 4),
        "param_specificity_mean": round(float(np.mean(param_specificities)), 4),
        "param_specificity_std": round(float(np.std(param_specificities)), 4),
    }

    print(f"  Baselines: {json.dumps(baselines, indent=2)}")

    # 4. Compute co-occurrence baselines
    print("\nComputing co-occurrence baselines...")
    normal_cooc_scores = []
    secret_cooc_scores = []

    for text in normal_texts:
        result = cooccurrence_score(text)
        normal_cooc_scores.append(result["cooccurrence_anomaly_score"])

    for text in secret_texts:
        result = cooccurrence_score(text)
        secret_cooc_scores.append(result["cooccurrence_anomaly_score"])

    print(f"  Normal co-occurrence: mean={np.mean(normal_cooc_scores):.4f}, std={np.std(normal_cooc_scores):.4f}")
    print(f"  Secret co-occurrence: mean={np.mean(secret_cooc_scores):.4f}, std={np.std(secret_cooc_scores):.4f}")

    # 5. Build cluster centroids
    print("\nBuilding cluster centroids...")
    cluster_cfg = dfp_cfg.get("cluster", {})
    strat_path = cluster_cfg.get("strategy_centroid_path", "data/index/dfp_strategy_centroid.pkl")
    norm_path = cluster_cfg.get("normal_centroid_path", "data/index/dfp_normal_centroid.pkl")

    strat_centroid, norm_centroid, cov_inv = build_cluster_centroids(
        secret_texts, normal_texts
    )

    save_centroids(strat_centroid, norm_centroid, cov_inv, strat_path, norm_path)
    print(f"  Strategy centroid saved to {strat_path}")
    print(f"  Normal centroid saved to {norm_path}")

    # 6. Compute separation metrics
    from scripts.dfp import mahalanobis_distance

    strat_dists = [mahalanobis_distance(extract_feature_vector(t), norm_centroid, cov_inv) for t in secret_texts]
    norm_dists = [mahalanobis_distance(extract_feature_vector(t), strat_centroid, cov_inv) for t in normal_texts]

    print(f"\n  Secret distance from normal centroid: mean={np.mean(strat_dists):.4f}")
    print(f"  Normal distance from strategy centroid: mean={np.mean(norm_dists):.4f}")

    # 7. Output recommended config
    if args.output_config:
        print("\n=== Recommended config.yaml dfp.entropy_baselines: ===")
        print(yaml.dump({"entropy_baselines": baselines}, default_flow_style=False))

    print("\n=== Calibration Complete ===")
    print("Run with --output_config to see recommended config.yaml values")


if __name__ == "__main__":
    main()
