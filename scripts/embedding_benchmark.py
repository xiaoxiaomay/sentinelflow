#!/usr/bin/env python3
"""
scripts/embedding_benchmark.py

Side-by-side comparison of embedding models on secret discrimination task.
Tests how well each model separates L2/L3 secrets from L0/L1 hard negatives.

Usage:
    python scripts/embedding_benchmark.py
    python scripts/embedding_benchmark.py --secrets data/index/secrets_v2_meta.pkl
"""
import argparse
import json
import os
import pickle
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np

# Ensure repo root importable
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


MODELS = [
    ("all-MiniLM-L6-v2", "sentence-transformers/all-MiniLM-L6-v2"),
    ("bge-small-en-v1.5", "BAAI/bge-small-en-v1.5"),
    ("all-mpnet-base-v2", "sentence-transformers/all-mpnet-base-v2"),
]


def load_secrets_meta(meta_path: str) -> List[dict]:
    """Load secret metadata from pickle file."""
    with open(meta_path, "rb") as f:
        meta = pickle.load(f)

    # Normalize to list of dicts
    if isinstance(meta, list):
        return meta
    if isinstance(meta, dict):
        ids = meta.get("ids") or []
        titles = meta.get("titles") or []
        texts = meta.get("texts") or []
        categories = meta.get("categories") or meta.get("source_types") or []
        result = []
        for i in range(max(len(ids), len(titles), len(texts))):
            entry = {}
            if i < len(ids):
                entry["_id"] = ids[i]
            if i < len(titles):
                entry["title"] = titles[i]
            if i < len(texts):
                entry["text"] = texts[i]
            if i < len(categories):
                entry["category"] = categories[i]
            result.append(entry)
        return result
    return []


def classify_secrets(secrets: List[dict]) -> Tuple[List[dict], List[dict]]:
    """
    Classify secrets into high-sensitivity (L2/L3) and hard negatives (L0/L1).

    L2/L3: Actual confidential strategies, thresholds, parameters
    L0/L1: General financial knowledge, public information (hard negatives)
    """
    high_sensitivity = []
    hard_negatives = []

    secret_keywords = [
        "threshold", "parameter", "strategy", "proprietary", "confidential",
        "internal", "secret", "alpha", "signal", "rule", "limit", "cap",
        "drawdown", "circuit breaker", "rebalance", "leverage",
    ]

    for s in secrets:
        text = (s.get("text") or s.get("title") or "").lower()
        category = (s.get("category") or "").lower()

        is_secret = (
            category in ("secret", "l2", "l3", "confidential", "proprietary")
            or any(kw in text for kw in secret_keywords)
        )

        if is_secret:
            high_sensitivity.append(s)
        else:
            hard_negatives.append(s)

    # If classification produced empty sets, split roughly
    if not hard_negatives and len(high_sensitivity) > 5:
        split = max(1, len(high_sensitivity) // 5)
        hard_negatives = high_sensitivity[:split]
        high_sensitivity = high_sensitivity[split:]

    return high_sensitivity, hard_negatives


def benchmark_model(
    model_name: str,
    model_id: str,
    secrets: List[dict],
    hard_negatives: List[dict],
) -> Dict[str, Any]:
    """
    Benchmark a single embedding model on secret discrimination.

    Returns dict with discrimination gap and timing metrics.
    """
    from sentence_transformers import SentenceTransformer

    print(f"  Loading {model_name}...")
    model = SentenceTransformer(model_id)
    dim = model.get_sentence_embedding_dimension()

    secret_texts = [s.get("text") or s.get("title") or "" for s in secrets]
    negative_texts = [s.get("text") or s.get("title") or "" for s in hard_negatives]

    t0 = time.time()
    secret_embs = model.encode(secret_texts, normalize_embeddings=True)
    negative_embs = model.encode(negative_texts, normalize_embeddings=True)
    encode_ms = (time.time() - t0) * 1000

    secret_embs = np.asarray(secret_embs, dtype="float32")
    negative_embs = np.asarray(negative_embs, dtype="float32")

    # Mean within-class similarity for secrets
    if len(secret_embs) > 1:
        secret_sims = secret_embs @ secret_embs.T
        mask = ~np.eye(len(secret_embs), dtype=bool)
        mean_secret_sim = float(secret_sims[mask].mean())
    else:
        mean_secret_sim = 1.0

    # Mean max similarity of hard negatives to any secret
    if len(negative_embs) > 0 and len(secret_embs) > 0:
        cross_sims = negative_embs @ secret_embs.T
        negative_max_sims = cross_sims.max(axis=1)
        mean_negative_max = float(negative_max_sims.mean())
    else:
        mean_negative_max = 0.0

    gap = mean_secret_sim - mean_negative_max

    return {
        "model": model_name,
        "dim": dim,
        "mean_secret_self_sim": round(mean_secret_sim, 4),
        "mean_negative_max_sim": round(mean_negative_max, 4),
        "discrimination_gap": round(gap, 4),
        "encode_latency_ms": round(encode_ms, 1),
        "n_secrets": len(secret_texts),
        "n_negatives": len(negative_texts),
    }


def print_table(results: List[dict]):
    """Print a formatted comparison table."""
    print("\n" + "=" * 85)
    print(f"{'Model':<22} {'Dim':>5} {'Secret Self-Sim':>16} {'Neg Max-Sim':>13} {'Gap':>8} {'Latency':>10}")
    print("-" * 85)
    for r in results:
        print(
            f"{r['model']:<22} {r['dim']:>5} "
            f"{r['mean_secret_self_sim']:>16.4f} "
            f"{r['mean_negative_max_sim']:>13.4f} "
            f"{r['discrimination_gap']:>8.4f} "
            f"{r['encode_latency_ms']:>8.1f}ms"
        )
    print("=" * 85)
    print(f"\nInterpretation: Larger 'Gap' = better discrimination = lower FPR at same TPR")
    print(f"Secrets: {results[0]['n_secrets']}, Hard negatives: {results[0]['n_negatives']}")


def main():
    ap = argparse.ArgumentParser(description="Embedding model benchmark for secret discrimination")
    ap.add_argument("--secrets", default="data/index/secrets_v2_meta.pkl",
                    help="Path to secrets metadata pickle")
    ap.add_argument("--output", default="eval/results/embedding_benchmark.json",
                    help="Output JSON path")
    args = ap.parse_args()

    print("=== Embedding Model Benchmark ===\n")

    print(f"Loading secrets from {args.secrets}...")
    secrets = load_secrets_meta(args.secrets)
    print(f"  Loaded {len(secrets)} entries")

    high_sens, hard_neg = classify_secrets(secrets)
    print(f"  High-sensitivity (L2/L3): {len(high_sens)}")
    print(f"  Hard negatives (L0/L1):   {len(hard_neg)}")

    if not high_sens:
        print("ERROR: No high-sensitivity secrets found. Check classification logic.")
        sys.exit(1)

    # If no hard negatives found, use synthetic financial prompts
    if not hard_neg:
        print("  No hard negatives in meta — using synthetic financial prompts")
        hard_neg = [
            {"text": "What is the current price of AAPL stock?"},
            {"text": "Explain how RSI indicator works in technical analysis."},
            {"text": "What is the difference between MACD and SMA?"},
            {"text": "How does dollar-cost averaging work?"},
            {"text": "What are the main sectors in the S&P 500?"},
            {"text": "Explain the concept of Sharpe ratio in portfolio theory."},
            {"text": "What is EBITDA and why is it important?"},
            {"text": "How do ETFs differ from mutual funds?"},
            {"text": "What factors affect bond yields?"},
            {"text": "Explain the efficient market hypothesis."},
        ]

    results = []
    for name, model_id in MODELS:
        print(f"\nBenchmarking: {name}")
        try:
            r = benchmark_model(name, model_id, high_sens, hard_neg)
            results.append(r)
            print(f"  Gap: {r['discrimination_gap']:.4f} "
                  f"(self-sim={r['mean_secret_self_sim']:.4f}, "
                  f"neg-max={r['mean_negative_max_sim']:.4f})")
        except Exception as e:
            print(f"  ERROR: {e}")
            results.append({"model": name, "error": str(e)})

    valid = [r for r in results if "error" not in r]
    if valid:
        print_table(valid)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
