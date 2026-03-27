#!/usr/bin/env python3
"""
eval/run_ablation.py

Ablation study: runs 6 system configurations against attack + benign prompts
to measure each gate's individual contribution.

Configs: B0 (unprotected), B2_no_G0a, B2_no_G0b, B2_no_G1, B2_no_LS,
         B2_single_tau, B2_full

Inputs:  data/attack_prompts_expanded.jsonl, data/benchmark/normal_prompts.jsonl,
         data/secrets/secrets.jsonl, data/index/secrets.faiss
Outputs: eval/results/ablation_results.json

Usage:
    python eval/run_ablation.py --all
    python eval/run_ablation.py --config B2_full
    python eval/run_ablation.py --all --dry-run
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.run_rag_with_audit import (
    load_config, intent_precheck, hardblock_precheck,
    embedding_secret_precheck, rule_gate,
)
from scripts.leakage_scan import load_faiss_index, scan_text, split_sentences


# ---------------------------------------------------------------------------
# Gate configuration definitions
# ---------------------------------------------------------------------------

CONFIGS = {
    "B0": {
        "description": "Unprotected baseline — no gates active",
        "gate_0a": False, "gate_0b": False, "gate_1": False,
        "grounding": False, "leakage_scan": False, "single_tau": None,
    },
    "B2_no_G0a": {
        "description": "Remove regex precheck (Gate 0a)",
        "gate_0a": False, "gate_0b": True, "gate_1": True,
        "grounding": True, "leakage_scan": True, "single_tau": None,
    },
    "B2_no_G0b": {
        "description": "Remove verb×object hard-block (Gate 0b)",
        "gate_0a": True, "gate_0b": False, "gate_1": True,
        "grounding": True, "leakage_scan": True, "single_tau": None,
    },
    "B2_no_G1": {
        "description": "Remove embedding gate (Gate 1)",
        "gate_0a": True, "gate_0b": True, "gate_1": False,
        "grounding": True, "leakage_scan": True, "single_tau": None,
    },
    "B2_no_LS": {
        "description": "Remove leakage scan",
        "gate_0a": True, "gate_0b": True, "gate_1": True,
        "grounding": True, "leakage_scan": False, "single_tau": None,
    },
    "B2_single_tau": {
        "description": "Gate 1 single threshold (τ=0.62, midpoint of τg=0.75 and τe=0.50)",
        "gate_0a": True, "gate_0b": True, "gate_1": True,
        "grounding": True, "leakage_scan": True, "single_tau": 0.62,
    },
    "B2_full": {
        "description": "Full SentinelFlow — all gates active",
        "gate_0a": True, "gate_0b": True, "gate_1": True,
        "grounding": True, "leakage_scan": True, "single_tau": None,
    },
}


def load_jsonl(path: str) -> List[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line.strip()))
    return rows


def run_single_query(
    query: str,
    config: dict,
    cfg: dict,
    embed_model,
    sec_index,
    sec_meta,
) -> Dict[str, Any]:
    """Run a single query through the pipeline with specified gate config."""
    t0 = time.time()
    blocked = False
    blocked_by = None
    llm_calls = 0

    policy_cfg = cfg.get("policy", {})
    pre_cfg = cfg.get("query_precheck", {})
    leak_cfg = cfg.get("leakage", {})

    # --- Gate 0a: regex intent ---
    g0a_res = {"blocked": False, "flagged_for_strict": False, "matched": []}
    if config["gate_0a"]:
        intent_rules = policy_cfg.get("intent_rules", [])
        g0a_res = intent_precheck(query, intent_rules)
        if g0a_res["blocked"]:
            blocked = True
            blocked_by = "gate_0a"

    # --- Gate 0b: hard-block classifier ---
    if not blocked and config["gate_0b"]:
        g0b_res = hardblock_precheck(query, policy_cfg)
        if g0b_res["blocked"]:
            blocked = True
            blocked_by = "gate_0b"

    # --- Gate 1: embedding precheck ---
    if not blocked and config["gate_1"]:
        query_vec = embed_model.encode([query], normalize_embeddings=True).astype("float32")

        # Determine threshold
        if config.get("single_tau") is not None:
            effective_threshold = config["single_tau"]
        else:
            # Tri-level threshold (ported from run_rag_with_audit.py)
            base_thr = float(pre_cfg.get("threshold", 0.75))
            sens_thr = float(pre_cfg.get("sensitive_threshold", base_thr))
            strict_thr = float(pre_cfg.get("strict_threshold", sens_thr - 0.05))
            amplifiers = pre_cfg.get("intent_amplifiers", [])
            q_lower = query.lower()
            has_intent = any(amp.lower() in q_lower for amp in amplifiers)
            flagged_strict = g0a_res.get("flagged_for_strict", False)

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
            blocked = True
            blocked_by = "gate_1"

    # --- Simulate LLM response (for leakage scan) ---
    # In ablation, we simulate a "worst case" where the LLM returns
    # text related to the query. We use the query itself as proxy.
    simulated_answer = query  # conservative: query echoed back

    # --- Leakage scan ---
    leakage_flag = False
    if not blocked and config["leakage_scan"]:
        leak_res = scan_text(
            text=simulated_answer,
            model=embed_model,
            secret_index=sec_index,
            secret_meta=sec_meta,
            hard_threshold=float(leak_cfg.get("hard_threshold", 0.70)),
            soft_threshold=float(leak_cfg.get("soft_threshold", 0.60)),
            cascade_k=int(leak_cfg.get("cascade_k", 2)),
            action="redact",
            top_k_secrets=1,
        )
        leakage_flag = leak_res["summary"]["leakage_flag"]
        if leakage_flag:
            blocked = True
            blocked_by = "leakage_scan"

    latency_ms = (time.time() - t0) * 1000

    return {
        "blocked": blocked,
        "blocked_by": blocked_by or "",
        "latency_ms": round(latency_ms, 2),
        "llm_calls": llm_calls,
    }


def run_ablation_config(
    config_id: str,
    config: dict,
    attack_prompts: List[dict],
    benign_prompts: List[dict],
    cfg: dict,
    embed_model,
    sec_index,
    sec_meta,
) -> Dict[str, Any]:
    """Run a full ablation for one configuration."""
    print(f"\n--- Config: {config_id} ({config['description']}) ---")

    # Attack evaluation
    attack_blocked = 0
    attack_results = []
    attack_latencies = []
    category_results = {}

    for p in attack_prompts:
        query = p.get("query", "")
        if not query:
            continue
        res = run_single_query(query, config, cfg, embed_model, sec_index, sec_meta)
        attack_results.append(res)
        attack_latencies.append(res["latency_ms"])
        if res["blocked"]:
            attack_blocked += 1

        group = p.get("group", "unknown")
        if group not in category_results:
            category_results[group] = {"total": 0, "blocked": 0}
        category_results[group]["total"] += 1
        if res["blocked"]:
            category_results[group]["blocked"] += 1

    total_attacks = len(attack_results) or 1
    asr = 1.0 - (attack_blocked / total_attacks)

    # Benign evaluation (FPR)
    benign_blocked = 0
    benign_latencies = []

    for p in benign_prompts:
        query = p.get("query", "")
        if not query:
            continue
        res = run_single_query(query, config, cfg, embed_model, sec_index, sec_meta)
        benign_latencies.append(res["latency_ms"])
        if res["blocked"]:
            benign_blocked += 1

    total_benign = len(benign_prompts) or 1
    fpr = benign_blocked / total_benign

    # Per-category ASR
    per_category_asr = {}
    for cat, counts in category_results.items():
        cat_total = counts["total"] or 1
        per_category_asr[cat] = round(1.0 - (counts["blocked"] / cat_total), 4)

    all_latencies = attack_latencies + benign_latencies
    avg_latency = np.mean(all_latencies) if all_latencies else 0

    result = {
        "config_id": config_id,
        "description": config["description"],
        "gates_active": {k: v for k, v in config.items() if k not in ("description", "single_tau")},
        "attack_total": total_attacks,
        "attack_blocked": attack_blocked,
        "asr": round(asr, 4),
        "benign_total": total_benign,
        "benign_blocked": benign_blocked,
        "fpr": round(fpr, 4),
        "avg_latency_ms": round(avg_latency, 2),
        "per_category_asr": per_category_asr,
    }

    print(f"  ASR: {asr:.2%} | FPR: {fpr:.2%} | Avg latency: {avg_latency:.1f}ms")
    return result


def print_comparison_table(results: List[dict]):
    """Print a formatted comparison table."""
    print("\n" + "=" * 90)
    print(f"{'Config':<16} {'ASR':>8} {'FPR':>8} {'Blocked':>10} {'Latency(ms)':>12} {'Description'}")
    print("-" * 90)
    for r in results:
        print(f"{r['config_id']:<16} {r['asr']:>7.2%} {r['fpr']:>7.2%} "
              f"{r['attack_blocked']:>5}/{r['attack_total']:<4} "
              f"{r['avg_latency_ms']:>10.1f}   {r['description'][:40]}")
    print("=" * 90)


def main():
    ap = argparse.ArgumentParser(description="SentinelFlow Ablation Study")
    ap.add_argument("--config", type=str, help="Run single config (e.g. B2_full)")
    ap.add_argument("--all", action="store_true", help="Run all 7 configurations")
    ap.add_argument("--output", type=str, default="eval/results/ablation_results.json")
    ap.add_argument("--dry-run", action="store_true", help="Print config info without running")
    ap.add_argument("--yaml-config", type=str, default="config.yaml", help="Path to config.yaml")
    args = ap.parse_args()

    if args.dry_run:
        print("=== Ablation Study (Dry Run) ===")
        for cid, cdef in CONFIGS.items():
            print(f"  {cid}: {cdef['description']}")
        return

    if not args.all and not args.config:
        print("Specify --all or --config <config_id>")
        return

    # Load config and data
    cfg = load_config(args.yaml_config)
    paths = cfg.get("paths", {})

    print("Loading embedding model...")
    from sentence_transformers import SentenceTransformer
    emb_cfg = cfg.get("embedding", {})
    model_name = emb_cfg.get("model_name", "sentence-transformers/all-MiniLM-L6-v2")
    embed_model = SentenceTransformer(model_name)

    print("Loading FAISS index...")
    sec_index, sec_meta = load_faiss_index(paths["secret_index"], paths["secret_meta"])

    # Load prompts
    attack_path = REPO_ROOT / "data" / "attack_prompts_expanded.jsonl"
    if not attack_path.exists():
        attack_path = REPO_ROOT / "data" / "benchmark" / "attack_prompts.jsonl"
    attack_prompts = load_jsonl(str(attack_path))

    benign_path = REPO_ROOT / "data" / "benchmark" / "normal_prompts.jsonl"
    benign_prompts = load_jsonl(str(benign_path))

    print(f"Attack prompts: {len(attack_prompts)}")
    print(f"Benign prompts: {len(benign_prompts)}")

    # Determine which configs to run
    if args.all:
        config_ids = list(CONFIGS.keys())
    else:
        config_ids = [args.config]
        if args.config not in CONFIGS:
            print(f"Unknown config: {args.config}. Available: {list(CONFIGS.keys())}")
            return

    # Run ablation
    results = []
    for cid in config_ids:
        result = run_ablation_config(
            cid, CONFIGS[cid],
            attack_prompts, benign_prompts,
            cfg, embed_model, sec_index, sec_meta,
        )
        results.append(result)

    # Print comparison table
    print_comparison_table(results)

    # Save results
    output_path = REPO_ROOT / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({"configs": results, "attack_count": len(attack_prompts),
                    "benign_count": len(benign_prompts)}, f, indent=2)
    print(f"\nSaved: {output_path}")


if __name__ == "__main__":
    main()
