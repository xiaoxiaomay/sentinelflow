#!/usr/bin/env python3
"""
eval/analyze_bypass_cases.py

Analyzes which attack prompts bypass all pre-gates, and why.
Runs each of the 271 prompts through Gate 0 Decode → Gate 0a → Gate 0b → Gate 1,
records per-gate decisions, and extracts bypass cases for detailed analysis.

Inputs:  data/attack_prompts_expanded.jsonl, data/benchmark/normal_prompts.jsonl
Outputs: eval/results/bypass_cases.jsonl          (prompts that pass all pre-gates)
         eval/results/bypass_analysis_report.json  (grouped stats + samples)

No LLM API calls needed.
"""

import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.run_rag_with_audit import (
    load_config, intent_precheck, hardblock_precheck,
    embedding_secret_precheck,
)
from scripts.leakage_scan import load_faiss_index
from gates.gate_0_decode import decode_gate


def load_jsonl(path: str) -> List[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line.strip()))
    return rows


def analyze_single_prompt(
    prompt: dict,
    cfg: dict,
    embed_model,
    sec_index,
    sec_meta,
) -> Dict[str, Any]:
    """Run a single prompt through all pre-gates and record decisions."""
    query = prompt.get("query", "")
    policy_cfg = cfg.get("policy", {})
    pre_cfg = cfg.get("query_precheck", {})
    decode_cfg = cfg.get("gate_0_decode", {})

    result = {
        "_id": prompt.get("_id", ""),
        "query": query,
        "group": prompt.get("group", ""),
        "evasion_technique": prompt.get("evasion_technique", "original"),
        "difficulty": prompt.get("difficulty", ""),
        "target_secret": prompt.get("target_secret", ""),
        "based_on_original_id": prompt.get("based_on_original_id", ""),
    }

    # Gate 0 Decode
    decode_res = decode_gate(query, decode_cfg)
    effective_query = decode_res["decoded_text"] if decode_res["encoding_detected"] else query
    result["gate_0_decode_detected"] = decode_res["encoding_detected"]
    result["gate_0_decode_type"] = decode_res["encoding_type"]

    # Gate 0a (regex)
    intent_rules = policy_cfg.get("intent_rules", [])
    g0a_res = intent_precheck(effective_query, intent_rules)
    result["gate_0a_blocked"] = g0a_res["blocked"]
    result["gate_0a_flagged_for_strict"] = g0a_res.get("flagged_for_strict", False)
    result["gate_0a_matched_rules"] = [h["id"] for h in g0a_res.get("matched", [])]

    # Gate 0b (hardblock)
    g0b_res = hardblock_precheck(effective_query, policy_cfg)
    result["gate_0b_blocked"] = g0b_res["blocked"]
    result["gate_0b_match_type"] = ""
    if g0b_res["matched"]:
        h = g0b_res["matched"][0]
        result["gate_0b_match_type"] = h.get("rule_type", "")
        if h.get("verb"):
            result["gate_0b_verb"] = h["verb"]
        if h.get("object"):
            result["gate_0b_object"] = h["object"]

    # Gate 1 (embedding)
    query_vec = embed_model.encode([effective_query], normalize_embeddings=True).astype("float32")

    base_thr = float(pre_cfg.get("threshold", 0.75))
    sens_thr = float(pre_cfg.get("sensitive_threshold", 0.50))
    strict_thr = float(pre_cfg.get("strict_threshold", sens_thr - 0.05))
    amplifiers = pre_cfg.get("intent_amplifiers", [])
    q_lower = effective_query.lower()
    has_intent = any(amp.lower() in q_lower for amp in amplifiers)
    flagged_strict = g0a_res.get("flagged_for_strict", False)

    if flagged_strict:
        effective_threshold = strict_thr
    elif has_intent:
        effective_threshold = sens_thr
    else:
        effective_threshold = base_thr

    g1_res = embedding_secret_precheck(
        embed_model, effective_query, sec_index, sec_meta,
        threshold=effective_threshold,
        top_k=int(pre_cfg.get("top_k_secrets", 3)),
        query_vec=query_vec,
    )
    result["gate_1_blocked"] = g1_res["blocked"]
    result["gate_1_score"] = g1_res["best_score"]
    result["gate_1_threshold_used"] = effective_threshold
    result["gate_1_has_intent_amplifier"] = has_intent
    result["gate_1_top_match"] = g1_res.get("top_match", {})

    # Overall
    blocked_by_any = (
        g0a_res["blocked"] or g0b_res["blocked"] or g1_res["blocked"]
    )
    result["blocked"] = blocked_by_any
    if g0a_res["blocked"]:
        result["blocked_by"] = "gate_0a"
    elif g0b_res["blocked"]:
        result["blocked_by"] = "gate_0b"
    elif g1_res["blocked"]:
        result["blocked_by"] = "gate_1"
    else:
        result["blocked_by"] = "none"

    result["bypass"] = not blocked_by_any

    return result


def main():
    cfg = load_config("config.yaml")
    paths = cfg.get("paths", {})

    print("Loading embedding model...")
    from sentence_transformers import SentenceTransformer
    emb_cfg = cfg.get("embedding", {})
    model_name = emb_cfg.get("model_name", "sentence-transformers/all-MiniLM-L6-v2")
    embed_model = SentenceTransformer(model_name)

    print("Loading FAISS index...")
    sec_index, sec_meta = load_faiss_index(paths["secret_index"], paths["secret_meta"])

    # Load attack prompts
    attack_path = REPO_ROOT / "data" / "attack_prompts_expanded.jsonl"
    attacks = load_jsonl(str(attack_path))
    print(f"Loaded {len(attacks)} attack prompts")

    # Also load extended prompts
    extended_path = REPO_ROOT / "data" / "attack_prompts_extended.jsonl"
    if extended_path.exists():
        extended = load_jsonl(str(extended_path))
        attacks.extend(extended)
        print(f"  + {len(extended)} extended prompts = {len(attacks)} total")

    # Analyze each prompt
    print("\nAnalyzing all prompts...")
    t0 = time.time()
    all_results = []
    bypass_cases = []

    for i, prompt in enumerate(attacks):
        res = analyze_single_prompt(prompt, cfg, embed_model, sec_index, sec_meta)
        all_results.append(res)
        if res["bypass"]:
            bypass_cases.append(res)

        if (i + 1) % 50 == 0:
            print(f"  [{i+1}/{len(attacks)}] bypass so far: {len(bypass_cases)}")

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.1f}s")

    # Summary stats
    total = len(all_results)
    n_bypass = len(bypass_cases)
    n_blocked = total - n_bypass
    print(f"\nTotal: {total} | Blocked: {n_blocked} ({n_blocked/total:.1%}) | Bypass: {n_bypass} ({n_bypass/total:.1%})")

    # Per-gate block stats
    g0a_blocks = sum(1 for r in all_results if r["gate_0a_blocked"])
    g0b_blocks = sum(1 for r in all_results if r["gate_0b_blocked"] and not r["gate_0a_blocked"])
    g1_blocks = sum(1 for r in all_results if r["blocked_by"] == "gate_1")
    print(f"\nGate distribution:")
    print(f"  Gate 0a (regex):     {g0a_blocks} blocks")
    print(f"  Gate 0b (hardblock): {g0b_blocks} blocks (after 0a pass)")
    print(f"  Gate 1 (embedding):  {g1_blocks} blocks (after 0a+0b pass)")
    print(f"  Bypass all:          {n_bypass}")

    # Group by evasion_technique
    technique_stats = defaultdict(lambda: {"total": 0, "bypass": 0, "samples": []})
    for r in all_results:
        tech = r.get("evasion_technique", "original")
        technique_stats[tech]["total"] += 1
        if r["bypass"]:
            technique_stats[tech]["bypass"] += 1
            if len(technique_stats[tech]["samples"]) < 3:
                technique_stats[tech]["samples"].append({
                    "_id": r["_id"],
                    "query": r["query"][:120],
                    "gate_1_score": r["gate_1_score"],
                    "gate_1_threshold": r["gate_1_threshold_used"],
                    "target_secret": r["target_secret"],
                })

    # Group by attack group
    group_stats = defaultdict(lambda: {"total": 0, "bypass": 0})
    for r in all_results:
        group = r.get("group", "unknown")
        group_stats[group]["total"] += 1
        if r["bypass"]:
            group_stats[group]["bypass"] += 1

    # Print technique table
    print(f"\n{'Evasion Technique':<30} | {'Total':>5} | {'Bypass':>6} | {'Bypass Rate':>11}")
    print("-" * 65)
    sorted_techniques = sorted(technique_stats.items(), key=lambda x: x[1]["bypass"] / max(x[1]["total"], 1), reverse=True)
    for tech, stats in sorted_techniques:
        rate = stats["bypass"] / max(stats["total"], 1)
        print(f"{tech:<30} | {stats['total']:>5} | {stats['bypass']:>6} | {rate:>10.1%}")

    # Print group table
    print(f"\n{'Attack Group':<30} | {'Total':>5} | {'Bypass':>6} | {'Bypass Rate':>11}")
    print("-" * 65)
    sorted_groups = sorted(group_stats.items(), key=lambda x: x[1]["bypass"] / max(x[1]["total"], 1), reverse=True)
    for group, stats in sorted_groups:
        rate = stats["bypass"] / max(stats["total"], 1)
        print(f"{group:<30} | {stats['total']:>5} | {stats['bypass']:>6} | {rate:>10.1%}")

    # Top 3 bypass techniques with samples
    top_bypass = sorted_techniques[:3]
    print(f"\n=== Top 3 Bypass Techniques (with samples) ===")
    for tech, stats in top_bypass:
        rate = stats["bypass"] / max(stats["total"], 1)
        print(f"\n{tech} (bypass rate: {rate:.1%}, {stats['bypass']}/{stats['total']}):")
        for s in stats["samples"]:
            print(f"  [{s['_id']}] score={s['gate_1_score']:.4f} thr={s['gate_1_threshold']} → \"{s['query']}\"")

    # Gate 1 score distribution for bypass cases
    bypass_scores = [r["gate_1_score"] for r in bypass_cases]
    if bypass_scores:
        print(f"\nGate 1 score distribution for bypass cases:")
        print(f"  Min:  {min(bypass_scores):.4f}")
        print(f"  Mean: {np.mean(bypass_scores):.4f}")
        print(f"  Max:  {max(bypass_scores):.4f}")
        print(f"  # with score >= 0.40: {sum(1 for s in bypass_scores if s >= 0.40)}")
        print(f"  # with score >= 0.30: {sum(1 for s in bypass_scores if s >= 0.30)}")
        print(f"  # with score <  0.30: {sum(1 for s in bypass_scores if s < 0.30)}")

    # Threshold analysis for bypass cases
    bypass_with_intent = sum(1 for r in bypass_cases if r["gate_1_has_intent_amplifier"])
    bypass_without_intent = n_bypass - bypass_with_intent
    print(f"\nIntent amplifier analysis for bypass cases:")
    print(f"  With amplifier (τ=0.50): {bypass_with_intent}")
    print(f"  Without amplifier (τ=0.75): {bypass_without_intent}")

    # Save bypass cases
    bypass_path = REPO_ROOT / "eval" / "results" / "bypass_cases.jsonl"
    with open(bypass_path, "w") as f:
        for r in bypass_cases:
            # Remove non-serializable bits
            row = {k: v for k, v in r.items() if k != "gate_1_top_match" or isinstance(v, (str, int, float, bool, dict, list, type(None)))}
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    print(f"\nSaved bypass cases: {bypass_path} ({len(bypass_cases)} entries)")

    # Save full report
    report = {
        "total_prompts": total,
        "total_blocked": n_blocked,
        "total_bypass": n_bypass,
        "block_rate": round(n_blocked / total, 4),
        "bypass_rate": round(n_bypass / total, 4),
        "gate_distribution": {
            "gate_0a": g0a_blocks,
            "gate_0b_incremental": g0b_blocks,
            "gate_1_incremental": g1_blocks,
            "bypass_all": n_bypass,
        },
        "by_evasion_technique": {
            tech: {
                "total": stats["total"],
                "bypass": stats["bypass"],
                "bypass_rate": round(stats["bypass"] / max(stats["total"], 1), 4),
                "samples": stats["samples"],
            }
            for tech, stats in sorted_techniques
        },
        "by_attack_group": {
            group: {
                "total": stats["total"],
                "bypass": stats["bypass"],
                "bypass_rate": round(stats["bypass"] / max(stats["total"], 1), 4),
            }
            for group, stats in sorted_groups
        },
        "bypass_gate1_score_stats": {
            "min": round(min(bypass_scores), 4) if bypass_scores else None,
            "mean": round(float(np.mean(bypass_scores)), 4) if bypass_scores else None,
            "max": round(max(bypass_scores), 4) if bypass_scores else None,
            "gte_040": sum(1 for s in bypass_scores if s >= 0.40),
            "gte_030": sum(1 for s in bypass_scores if s >= 0.30),
            "lt_030": sum(1 for s in bypass_scores if s < 0.30),
        },
        "bypass_intent_amplifier": {
            "with_amplifier": bypass_with_intent,
            "without_amplifier": bypass_without_intent,
        },
    }

    report_path = REPO_ROOT / "eval" / "results" / "bypass_analysis_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"Saved report: {report_path}")


if __name__ == "__main__":
    main()
