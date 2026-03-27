#!/usr/bin/env python3
"""
eval/run_statistical_eval.py

Runs B0 vs B2 comparison N times with different random seeds, then computes
mean ± std for ASR, FPR, TPR and McNemar's test for statistical significance.

Since pre-gate checks (regex, embedding) are deterministic, variance comes from:
  1. Shuffled prompt order (may affect cascade logic in leakage scan)
  2. Different random subsets when --sample is used

Inputs:  data/attack_prompts_expanded.jsonl, data/benchmark/normal_prompts.jsonl
Outputs: eval/results/statistical_eval.json

Usage:
    python eval/run_statistical_eval.py --runs 5
    python eval/run_statistical_eval.py --runs 3 --dry-run
"""

import argparse
import json
import os
import sys
import time
import random
from pathlib import Path
from typing import Dict, List, Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.run_rag_with_audit import (
    load_config, intent_precheck, hardblock_precheck,
    embedding_secret_precheck, rule_gate,
)
from scripts.leakage_scan import load_faiss_index, scan_text


def load_jsonl(path: str) -> List[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line.strip()))
    return rows


def evaluate_b0(query: str) -> bool:
    """B0: unprotected — always allows."""
    return False  # not blocked


def evaluate_b2(
    query: str, cfg: dict, embed_model, sec_index, sec_meta,
) -> bool:
    """B2: full SentinelFlow — returns True if blocked."""
    policy_cfg = cfg.get("policy", {})
    pre_cfg = cfg.get("query_precheck", {})
    leak_cfg = cfg.get("leakage", {})

    # Gate 0a + 0b (merged rule_gate)
    g0_res = rule_gate(query, policy_cfg)
    if g0_res["blocked"]:
        return True

    # Gate 1: tri-level threshold (ported from run_rag_with_audit.py)
    query_vec = embed_model.encode([query], normalize_embeddings=True).astype("float32")
    base_thr = float(pre_cfg.get("threshold", 0.75))
    sens_thr = float(pre_cfg.get("sensitive_threshold", base_thr))
    strict_thr = float(pre_cfg.get("strict_threshold", sens_thr - 0.05))
    amplifiers = pre_cfg.get("intent_amplifiers", [])
    q_lower = query.lower()
    has_intent = any(amp.lower() in q_lower for amp in amplifiers)
    flagged_strict = g0_res.get("flagged_for_strict", False)

    if flagged_strict:
        effective_threshold = strict_thr
    elif has_intent:
        effective_threshold = sens_thr
    else:
        effective_threshold = base_thr

    g1_res = embedding_secret_precheck(
        embed_model, query, sec_index, sec_meta,
        threshold=effective_threshold,
        top_k=int(pre_cfg.get("top_k_secrets", 3)),
        query_vec=query_vec,
    )
    if g1_res["blocked"]:
        return True

    # Leakage scan on simulated response
    leak_res = scan_text(
        text=query, model=embed_model,
        secret_index=sec_index, secret_meta=sec_meta,
        hard_threshold=float(leak_cfg.get("hard_threshold", 0.70)),
        soft_threshold=float(leak_cfg.get("soft_threshold", 0.60)),
        cascade_k=int(leak_cfg.get("cascade_k", 2)),
        action="redact", top_k_secrets=1,
    )
    if leak_res["summary"]["leakage_flag"]:
        return True

    return False


def run_single_eval(
    run_id: int, seed: int,
    attack_prompts: List[dict], benign_prompts: List[dict],
    cfg: dict, embed_model, sec_index, sec_meta,
) -> Dict[str, Any]:
    """Run one evaluation pass."""
    rng = random.Random(seed)

    # Shuffle prompts (order may affect cascade)
    attacks = list(attack_prompts)
    benign = list(benign_prompts)
    rng.shuffle(attacks)
    rng.shuffle(benign)

    # B0 results
    b0_attack_blocked = 0
    b0_benign_blocked = 0

    # B2 results
    b2_attack_blocked = 0
    b2_benign_blocked = 0

    # Per-prompt paired results for McNemar
    b0_outcomes = []
    b2_outcomes = []

    for p in attacks:
        query = p.get("query", "")
        if not query:
            continue
        b0_blocked = evaluate_b0(query)
        b2_blocked = evaluate_b2(query, cfg, embed_model, sec_index, sec_meta)

        b0_outcomes.append(b0_blocked)
        b2_outcomes.append(b2_blocked)

        if b0_blocked:
            b0_attack_blocked += 1
        if b2_blocked:
            b2_attack_blocked += 1

    for p in benign:
        query = p.get("query", "")
        if not query:
            continue
        b0_benign = evaluate_b0(query)
        b2_benign = evaluate_b2(query, cfg, embed_model, sec_index, sec_meta)

        if b0_benign:
            b0_benign_blocked += 1
        if b2_benign:
            b2_benign_blocked += 1

    n_attacks = len(attacks)
    n_benign = len(benign)

    b0_asr = 1.0 - (b0_attack_blocked / max(n_attacks, 1))
    b2_asr = 1.0 - (b2_attack_blocked / max(n_attacks, 1))
    b0_fpr = b0_benign_blocked / max(n_benign, 1)
    b2_fpr = b2_benign_blocked / max(n_benign, 1)
    b2_tpr = b2_attack_blocked / max(n_attacks, 1)

    return {
        "run_id": run_id,
        "seed": seed,
        "b0_asr": b0_asr, "b2_asr": b2_asr,
        "b0_fpr": b0_fpr, "b2_fpr": b2_fpr,
        "b2_tpr": b2_tpr,
        "b0_outcomes": b0_outcomes,
        "b2_outcomes": b2_outcomes,
        "n_attacks": n_attacks,
        "n_benign": n_benign,
    }


def compute_mcnemar(b0_outcomes: List[bool], b2_outcomes: List[bool]) -> Dict[str, Any]:
    """Compute McNemar's test for paired binary outcomes."""
    # Contingency: b0_correct vs b2_correct
    # For attacks: "correct" = blocked
    n01 = 0  # B0 allows, B2 blocks
    n10 = 0  # B0 blocks, B2 allows

    for b0, b2 in zip(b0_outcomes, b2_outcomes):
        if not b0 and b2:
            n01 += 1
        elif b0 and not b2:
            n10 += 1

    # McNemar chi-squared (with continuity correction)
    if n01 + n10 == 0:
        chi2 = 0.0
        p_value = 1.0
    else:
        chi2 = ((abs(n01 - n10) - 1) ** 2) / (n01 + n10)
        from scipy import stats
        p_value = 1.0 - stats.chi2.cdf(chi2, df=1)

    return {
        "n01_b0_miss_b2_block": n01,
        "n10_b0_block_b2_miss": n10,
        "chi2": round(chi2, 4),
        "p_value": round(p_value, 6),
        "significant_at_005": p_value < 0.05,
        "significant_at_001": p_value < 0.01,
    }


def main():
    ap = argparse.ArgumentParser(description="Statistical Evaluation (B0 vs B2)")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--output", type=str, default="eval/results/statistical_eval.json")
    ap.add_argument("--config", type=str, default="config.yaml")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.dry_run:
        attack_path = REPO_ROOT / "data" / "attack_prompts_expanded.jsonl"
        if not attack_path.exists():
            attack_path = REPO_ROOT / "data" / "benchmark" / "attack_prompts.jsonl"
        n_attacks = sum(1 for _ in open(attack_path))
        n_benign = sum(1 for _ in open(REPO_ROOT / "data" / "benchmark" / "normal_prompts.jsonl"))
        total_queries = args.runs * (n_attacks + n_benign) * 2  # B0 + B2
        print(f"=== Dry Run ===")
        print(f"Runs: {args.runs}")
        print(f"Queries per run: {n_attacks} attacks + {n_benign} benign = {n_attacks + n_benign}")
        print(f"Total evaluations: {total_queries}")
        print(f"Estimated LLM API calls: 0 (gate-level eval only)")
        print(f"Estimated cost: $0.00 (no LLM calls)")
        return

    cfg = load_config(args.config)
    paths = cfg.get("paths", {})

    print("Loading embedding model...")
    from sentence_transformers import SentenceTransformer
    emb_cfg = cfg.get("embedding", {})
    model_name = emb_cfg.get("model_name", "sentence-transformers/all-MiniLM-L6-v2")
    embed_model = SentenceTransformer(model_name)

    print("Loading FAISS index...")
    sec_index, sec_meta = load_faiss_index(paths["secret_index"], paths["secret_meta"])

    attack_path = REPO_ROOT / "data" / "attack_prompts_expanded.jsonl"
    if not attack_path.exists():
        attack_path = REPO_ROOT / "data" / "benchmark" / "attack_prompts.jsonl"
    attack_prompts = load_jsonl(str(attack_path))
    benign_prompts = load_jsonl(str(REPO_ROOT / "data" / "benchmark" / "normal_prompts.jsonl"))

    print(f"Attack prompts: {len(attack_prompts)}, Benign: {len(benign_prompts)}")
    print(f"Running {args.runs} evaluation passes...\n")

    all_runs = []
    all_b0_outcomes = []
    all_b2_outcomes = []

    for run_id in range(args.runs):
        seed = 42 + run_id * 7
        print(f"  Run {run_id + 1}/{args.runs} (seed={seed})...")
        t0 = time.time()
        result = run_single_eval(
            run_id, seed, attack_prompts, benign_prompts,
            cfg, embed_model, sec_index, sec_meta,
        )
        elapsed = time.time() - t0
        print(f"    B0 ASR: {result['b0_asr']:.2%} | B2 ASR: {result['b2_asr']:.2%} | "
              f"B2 FPR: {result['b2_fpr']:.2%} | B2 TPR: {result['b2_tpr']:.2%} | "
              f"Time: {elapsed:.1f}s")

        # Store without large outcome arrays for JSON
        run_summary = {k: v for k, v in result.items() if k not in ("b0_outcomes", "b2_outcomes")}
        all_runs.append(run_summary)
        all_b0_outcomes.extend(result["b0_outcomes"])
        all_b2_outcomes.extend(result["b2_outcomes"])

    # Compute statistics
    b2_asrs = [r["b2_asr"] for r in all_runs]
    b2_fprs = [r["b2_fpr"] for r in all_runs]
    b2_tprs = [r["b2_tpr"] for r in all_runs]

    mean_asr = np.mean(b2_asrs)
    std_asr = np.std(b2_asrs, ddof=1) if len(b2_asrs) > 1 else 0.0
    mean_fpr = np.mean(b2_fprs)
    std_fpr = np.std(b2_fprs, ddof=1) if len(b2_fprs) > 1 else 0.0
    mean_tpr = np.mean(b2_tprs)
    std_tpr = np.std(b2_tprs, ddof=1) if len(b2_tprs) > 1 else 0.0

    # 95% CI
    n = len(b2_asrs)
    try:
        from scipy.stats import t as t_dist
        ci_mult = t_dist.ppf(0.975, df=max(n - 1, 1))
        asr_ci = (mean_asr - ci_mult * std_asr / np.sqrt(n),
                  mean_asr + ci_mult * std_asr / np.sqrt(n))
        fpr_ci = (mean_fpr - ci_mult * std_fpr / np.sqrt(n),
                  mean_fpr + ci_mult * std_fpr / np.sqrt(n))
        tpr_ci = (mean_tpr - ci_mult * std_tpr / np.sqrt(n),
                  mean_tpr + ci_mult * std_tpr / np.sqrt(n))
    except ImportError:
        ci_mult = 2.776  # t(0.975, df=4) for 5 runs
        asr_ci = (mean_asr - ci_mult * std_asr / np.sqrt(n),
                  mean_asr + ci_mult * std_asr / np.sqrt(n))
        fpr_ci = (mean_fpr - ci_mult * std_fpr / np.sqrt(n),
                  mean_fpr + ci_mult * std_fpr / np.sqrt(n))
        tpr_ci = (mean_tpr - ci_mult * std_tpr / np.sqrt(n),
                  mean_tpr + ci_mult * std_tpr / np.sqrt(n))

    # McNemar's test
    try:
        mcnemar_result = compute_mcnemar(all_b0_outcomes, all_b2_outcomes)
    except ImportError:
        mcnemar_result = {"note": "scipy not installed, McNemar test skipped"}

    # Results
    stats_summary = {
        "n_runs": n,
        "b2_asr_mean": round(mean_asr, 4),
        "b2_asr_std": round(std_asr, 4),
        "b2_asr_95ci": [round(asr_ci[0], 4), round(asr_ci[1], 4)],
        "b2_fpr_mean": round(mean_fpr, 4),
        "b2_fpr_std": round(std_fpr, 4),
        "b2_fpr_95ci": [round(fpr_ci[0], 4), round(fpr_ci[1], 4)],
        "b2_tpr_mean": round(mean_tpr, 4),
        "b2_tpr_std": round(std_tpr, 4),
        "b2_tpr_95ci": [round(tpr_ci[0], 4), round(tpr_ci[1], 4)],
        "mcnemar": mcnemar_result,
        "per_run": all_runs,
    }

    print(f"\n{'='*60}")
    print(f"Statistical Summary ({n} runs)")
    print(f"{'='*60}")
    print(f"B2 ASR:  {mean_asr:.2%} ± {std_asr:.2%}  95% CI: [{asr_ci[0]:.2%}, {asr_ci[1]:.2%}]")
    print(f"B2 FPR:  {mean_fpr:.2%} ± {std_fpr:.2%}  95% CI: [{fpr_ci[0]:.2%}, {fpr_ci[1]:.2%}]")
    print(f"B2 TPR:  {mean_tpr:.2%} ± {std_tpr:.2%}  95% CI: [{tpr_ci[0]:.2%}, {tpr_ci[1]:.2%}]")
    if isinstance(mcnemar_result, dict) and "p_value" in mcnemar_result:
        print(f"McNemar p-value: {mcnemar_result['p_value']:.6f} "
              f"({'significant' if mcnemar_result['significant_at_005'] else 'not significant'} at α=0.05)")

    output_path = REPO_ROOT / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)

    class NumpyEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, (np.bool_, np.integer)):
                return int(obj)
            if isinstance(obj, np.floating):
                return float(obj)
            if isinstance(obj, np.ndarray):
                return obj.tolist()
            return super().default(obj)

    with open(output_path, "w") as f:
        json.dump(stats_summary, f, indent=2, cls=NumpyEncoder)
    print(f"\nSaved: {output_path}")


if __name__ == "__main__":
    main()
