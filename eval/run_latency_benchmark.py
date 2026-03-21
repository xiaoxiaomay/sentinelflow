#!/usr/bin/env python3
"""
eval/run_latency_benchmark.py

Publication-quality latency measurements for each gate and end-to-end.

Tests 100 queries (50 benign + 50 attacks) through each gate independently.
Reports min, P50, P95, P99, max latency (ms).
Also tests scalability vs secrets index size (60, 120, 240, 480).

Inputs:  data/benchmark/normal_prompts.jsonl, data/attack_prompts_expanded.jsonl,
         data/secrets/secrets.jsonl, data/index/secrets.faiss
Outputs: eval/results/latency_benchmark.json
         eval/figures/latency_plot.pdf
"""

import argparse
import copy
import json
import os
import pickle
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import faiss
import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.run_rag_with_audit import (
    load_config, intent_precheck, hardblock_precheck,
    embedding_secret_precheck, rule_gate,
)
from scripts.leakage_scan import load_faiss_index, scan_text
from gates.gate_0_decode import decode_gate


def load_jsonl(path: str) -> List[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line.strip()))
    return rows


def percentile(values: List[float], p: float) -> float:
    """Compute percentile from a sorted list."""
    if not values:
        return 0.0
    sorted_v = sorted(values)
    idx = int(len(sorted_v) * p / 100.0)
    idx = min(idx, len(sorted_v) - 1)
    return sorted_v[idx]


def compute_stats(latencies: List[float]) -> Dict[str, float]:
    if not latencies:
        return {"min": 0, "p50": 0, "p95": 0, "p99": 0, "max": 0, "mean": 0, "count": 0}
    return {
        "min": round(min(latencies), 3),
        "p50": round(percentile(latencies, 50), 3),
        "p95": round(percentile(latencies, 95), 3),
        "p99": round(percentile(latencies, 99), 3),
        "max": round(max(latencies), 3),
        "mean": round(np.mean(latencies), 3),
        "count": len(latencies),
    }


def build_scaled_index(sec_index, sec_meta, scale_factor: int):
    """Create a larger FAISS index by duplicating entries."""
    if scale_factor <= 1:
        return sec_index, sec_meta

    d = sec_index.d
    n = sec_index.ntotal

    # Extract all vectors
    vectors = np.zeros((n, d), dtype="float32")
    for i in range(n):
        vectors[i] = sec_index.reconstruct(i)

    # Duplicate
    all_vectors = np.tile(vectors, (scale_factor, 1))

    new_index = faiss.IndexFlatIP(d)
    new_index.add(all_vectors)

    # Duplicate metadata
    if isinstance(sec_meta, dict):
        new_meta = {}
        for key, val in sec_meta.items():
            if isinstance(val, list):
                new_meta[key] = val * scale_factor
            else:
                new_meta[key] = val
    elif isinstance(sec_meta, list):
        new_meta = sec_meta * scale_factor
    else:
        new_meta = sec_meta

    return new_index, new_meta


def main():
    ap = argparse.ArgumentParser(description="SentinelFlow Latency Benchmark")
    ap.add_argument("--output", type=str, default="eval/results/latency_benchmark.json")
    ap.add_argument("--config", type=str, default="config.yaml")
    ap.add_argument("--n-queries", type=int, default=100, help="Total queries (half benign, half attack)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    paths = cfg.get("paths", {})

    print("Loading embedding model...")
    from sentence_transformers import SentenceTransformer
    emb_cfg = cfg.get("embedding", {})
    model_name = emb_cfg.get("model_name", "sentence-transformers/all-MiniLM-L6-v2")
    embed_model = SentenceTransformer(model_name)

    print("Loading FAISS index...")
    sec_index, sec_meta = load_faiss_index(paths["secret_index"], paths["secret_meta"])

    # Load queries
    n_each = args.n_queries // 2
    benign = load_jsonl(str(REPO_ROOT / "data" / "benchmark" / "normal_prompts.jsonl"))[:n_each]
    attack_path = REPO_ROOT / "data" / "attack_prompts_expanded.jsonl"
    if not attack_path.exists():
        attack_path = REPO_ROOT / "data" / "benchmark" / "attack_prompts.jsonl"
    attacks = load_jsonl(str(attack_path))[:n_each]

    queries = [p.get("query", "") for p in benign + attacks if p.get("query")]
    print(f"Benchmark queries: {len(queries)}")

    policy_cfg = cfg.get("policy", {})
    pre_cfg = cfg.get("query_precheck", {})
    leak_cfg = cfg.get("leakage", {})
    decode_cfg = cfg.get("gate_0_decode", {})

    # ---------------------------------------------------------------------------
    # Per-gate latency
    # ---------------------------------------------------------------------------
    gate_results = {}

    # Gate 0 Decode
    print("Benchmarking Gate 0 Decode...")
    lat = []
    for q in queries:
        t0 = time.perf_counter()
        decode_gate(q, decode_cfg)
        lat.append((time.perf_counter() - t0) * 1000)
    gate_results["gate_0_decode"] = compute_stats(lat)

    # Gate 0a (regex)
    print("Benchmarking Gate 0a (regex)...")
    lat = []
    intent_rules = policy_cfg.get("intent_rules", [])
    for q in queries:
        t0 = time.perf_counter()
        intent_precheck(q, intent_rules)
        lat.append((time.perf_counter() - t0) * 1000)
    gate_results["gate_0a_regex"] = compute_stats(lat)

    # Gate 0b (hard-block)
    print("Benchmarking Gate 0b (hard-block)...")
    lat = []
    for q in queries:
        t0 = time.perf_counter()
        hardblock_precheck(q, policy_cfg)
        lat.append((time.perf_counter() - t0) * 1000)
    gate_results["gate_0b_hardblock"] = compute_stats(lat)

    # Gate 0a+0b merged
    print("Benchmarking Gate 0 merged (0a+0b)...")
    lat = []
    for q in queries:
        t0 = time.perf_counter()
        rule_gate(q, policy_cfg)
        lat.append((time.perf_counter() - t0) * 1000)
    gate_results["gate_0_merged"] = compute_stats(lat)

    # Gate 1 (embedding precheck)
    print("Benchmarking Gate 1 (embedding)...")
    lat = []
    for q in queries:
        t0 = time.perf_counter()
        qv = embed_model.encode([q], normalize_embeddings=True).astype("float32")
        embedding_secret_precheck(
            embed_model, q, sec_index, sec_meta,
            threshold=0.75, top_k=3, query_vec=qv,
        )
        lat.append((time.perf_counter() - t0) * 1000)
    gate_results["gate_1_embedding"] = compute_stats(lat)

    # Embedding-only (no FAISS)
    print("Benchmarking embedding encode only...")
    lat = []
    for q in queries:
        t0 = time.perf_counter()
        embed_model.encode([q], normalize_embeddings=True)
        lat.append((time.perf_counter() - t0) * 1000)
    gate_results["embedding_encode_only"] = compute_stats(lat)

    # FAISS search only
    print("Benchmarking FAISS search only...")
    lat = []
    pre_encoded = [embed_model.encode([q], normalize_embeddings=True).astype("float32") for q in queries[:20]]
    for qv in pre_encoded:
        t0 = time.perf_counter()
        sec_index.search(qv, 3)
        lat.append((time.perf_counter() - t0) * 1000)
    gate_results["faiss_search_only"] = compute_stats(lat)

    # Leakage scan
    print("Benchmarking Leakage Scan...")
    lat = []
    for q in queries[:50]:  # use 50 for leakage (it embeds text)
        t0 = time.perf_counter()
        scan_text(
            text=q, model=embed_model,
            secret_index=sec_index, secret_meta=sec_meta,
            hard_threshold=0.70, soft_threshold=0.60,
            cascade_k=2, action="redact", top_k_secrets=1,
        )
        lat.append((time.perf_counter() - t0) * 1000)
    gate_results["leakage_scan"] = compute_stats(lat)

    # End-to-end (all gates, no LLM)
    print("Benchmarking end-to-end (gates only, no LLM)...")
    lat = []
    for q in queries[:50]:
        t0 = time.perf_counter()

        # Decode
        dr = decode_gate(q, decode_cfg)
        effective_q = dr["decoded_text"] if dr["encoding_detected"] else q

        # Gate 0
        g0 = rule_gate(effective_q, policy_cfg)
        if not g0["blocked"]:
            # Gate 1
            qv = embed_model.encode([effective_q], normalize_embeddings=True).astype("float32")
            g1 = embedding_secret_precheck(
                embed_model, effective_q, sec_index, sec_meta,
                threshold=0.75, top_k=3, query_vec=qv,
            )
            if not g1["blocked"]:
                # Leakage scan
                scan_text(
                    text=effective_q, model=embed_model,
                    secret_index=sec_index, secret_meta=sec_meta,
                    hard_threshold=0.70, soft_threshold=0.60,
                    cascade_k=2, action="redact", top_k_secrets=1,
                )

        lat.append((time.perf_counter() - t0) * 1000)
    gate_results["end_to_end_gates"] = compute_stats(lat)

    print("\nPer-gate latency results:")
    for gate, stats in gate_results.items():
        print(f"  {gate:<25} P50={stats['p50']:.2f}ms  P95={stats['p95']:.2f}ms  P99={stats['p99']:.2f}ms")

    # ---------------------------------------------------------------------------
    # Scalability test: varying secrets index size
    # ---------------------------------------------------------------------------
    print("\nScalability test (varying index size)...")
    scale_results = {}
    base_n = sec_index.ntotal

    for target_n in [60, 120, 240, 480]:
        scale_factor = max(1, target_n // base_n)
        scaled_index, scaled_meta = build_scaled_index(sec_index, sec_meta, scale_factor)
        actual_n = scaled_index.ntotal

        lat = []
        for q in queries[:30]:
            t0 = time.perf_counter()
            qv = embed_model.encode([q], normalize_embeddings=True).astype("float32")
            embedding_secret_precheck(
                embed_model, q, scaled_index, scaled_meta,
                threshold=0.75, top_k=3, query_vec=qv,
            )
            lat.append((time.perf_counter() - t0) * 1000)

        stats = compute_stats(lat)
        scale_results[str(actual_n)] = stats
        print(f"  N={actual_n}: P50={stats['p50']:.2f}ms  P95={stats['p95']:.2f}ms")

    # ---------------------------------------------------------------------------
    # Save results
    # ---------------------------------------------------------------------------
    all_results = {
        "per_gate": gate_results,
        "scalability": scale_results,
        "config": {
            "n_queries": len(queries),
            "model": model_name,
            "base_index_size": base_n,
        },
    }

    output_path = REPO_ROOT / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nSaved: {output_path}")

    # ---------------------------------------------------------------------------
    # Generate plot
    # ---------------------------------------------------------------------------
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

        # Bar chart: per-gate P95 latency
        gate_names = list(gate_results.keys())
        p95_values = [gate_results[g]["p95"] for g in gate_names]
        short_names = [g.replace("gate_", "G").replace("_", "\n") for g in gate_names]

        ax1.bar(range(len(gate_names)), p95_values, color="steelblue", edgecolor="navy", alpha=0.8)
        ax1.set_xticks(range(len(gate_names)))
        ax1.set_xticklabels(short_names, rotation=45, ha="right", fontsize=7)
        ax1.set_ylabel("P95 Latency (ms)")
        ax1.set_title("Per-Gate P95 Latency")
        ax1.grid(axis="y", alpha=0.3)

        # Line chart: scalability
        sizes = sorted([int(k) for k in scale_results.keys()])
        p50_scale = [scale_results[str(s)]["p50"] for s in sizes]
        p95_scale = [scale_results[str(s)]["p95"] for s in sizes]

        ax2.plot(sizes, p50_scale, "o-", label="P50", color="steelblue")
        ax2.plot(sizes, p95_scale, "s--", label="P95", color="darkorange")
        ax2.set_xlabel("Secrets Index Size")
        ax2.set_ylabel("Latency (ms)")
        ax2.set_title("Gate 1 Latency vs Index Size")
        ax2.legend()
        ax2.grid(alpha=0.3)

        plt.tight_layout()
        fig_path = REPO_ROOT / "eval" / "figures" / "latency_plot.pdf"
        fig_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(fig_path, dpi=150, bbox_inches="tight")
        print(f"Saved plot: {fig_path}")

    except ImportError:
        print("matplotlib not available — skipping plot generation")


if __name__ == "__main__":
    main()
