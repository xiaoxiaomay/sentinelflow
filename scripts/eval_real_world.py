#!/usr/bin/env python3
"""
V2 Real-World Evaluation:
  Part A — 219 real (non-synthetic) benign queries  → measure FPR
  Part B — 24 external attack vectors                → measure ASR (bypass rate)

Output: data/eval/v2_real_world_results.json
"""
import os, sys, json, time
from pathlib import Path
from collections import Counter, defaultdict

os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("VECLIB_MAXIMUM_THREADS", "1")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import yaml
import numpy as np
from dotenv import load_dotenv

load_dotenv()

from scripts.leakage_scan import load_faiss_index, scan_text, split_sentences
from scripts.run_rag_with_audit import (
    rule_gate, embedding_secret_precheck, db_retrieve_topk,
    build_prompt, call_llm, grounding_validate,
)

import psycopg2
from pgvector.psycopg2 import register_vector


NORMAL_PATH = REPO_ROOT / "data" / "eval" / "real_world_normal_prompts.json"
ATTACK_PATH = REPO_ROOT / "data" / "eval" / "external_attack_prompts.json"
OUT_PATH    = REPO_ROOT / "data" / "eval" / "v2_real_world_results.json"


def load_config(path="config.yaml"):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# ── Pipeline runner (same as news_data_test.py) ───────────────
def run_single_query(query, cfg, embed_model, sec_index, sec_meta, db_conn,
                     skip_llm=False):
    """
    Run full SentinelFlow pipeline on a single query.
    skip_llm=True stops after Gate 1 (for fast FPR measurement on normal queries
    that don't need LLM verification — only used to measure gate behaviour).
    We set skip_llm=False by default so attack queries always get full pipeline.
    """
    result = {
        "query": query,
        "gate0_blocked": False, "gate0_rule_ids": [],
        "gate1_blocked": False, "gate1_score": None, "gate1_threshold": None,
        "gate1_has_amplifier": False,
        "final_status": None, "blocked_by": None, "error": None,
    }

    try:
        policy_cfg = cfg.get("policy", {}) or {}

        # ── Gate 0 (regex + hard-block) ──
        gate0 = rule_gate(query, policy_cfg)
        result["gate0_blocked"] = gate0["blocked"]
        result["gate0_rule_ids"] = [h.get("id", "") for h in gate0.get("matched", [])]
        result["gate0_components"] = gate0.get("components", {})

        if gate0["blocked"]:
            result["final_status"] = "blocked"
            result["blocked_by"] = "gate0"
            # Determine sub-gate
            comps = gate0.get("components", {})
            if comps.get("regex_blocked") and comps.get("hardblock_blocked"):
                result["blocked_by"] = "gate0a+0b"
            elif comps.get("regex_blocked"):
                result["blocked_by"] = "gate0a"
            elif comps.get("hardblock_blocked"):
                result["blocked_by"] = "gate0b"
            return result

        # ── Encode query vector ──
        query_vec = embed_model.encode([query], normalize_embeddings=True).astype("float32")

        # ── Gate 1 (embedding similarity) ──
        pre_cfg = cfg.get("query_precheck", {}) or {}
        base_thr = float(pre_cfg.get("threshold", 0.75))
        sens_thr = float(pre_cfg.get("sensitive_threshold", 0.50))
        amplifiers = pre_cfg.get("intent_amplifiers", [])
        q_lower = query.lower()
        has_intent = any(amp.lower() in q_lower for amp in amplifiers)
        effective_threshold = sens_thr if has_intent else base_thr
        result["gate1_has_amplifier"] = has_intent

        gate1 = embedding_secret_precheck(
            embed_model, query, sec_index, sec_meta,
            threshold=effective_threshold,
            top_k=int(pre_cfg.get("top_k_secrets", 3)),
            query_vec=query_vec,
        )
        result["gate1_blocked"] = gate1["blocked"]
        result["gate1_score"] = gate1["best_score"]
        result["gate1_threshold"] = gate1["threshold"]
        result["gate1_top_match"] = gate1.get("top_match", {})

        if gate1["blocked"]:
            result["final_status"] = "blocked"
            result["blocked_by"] = "gate1"
            return result

        # Fast mode: stop here for normal-query FPR measurement
        if skip_llm:
            result["final_status"] = "allowed"
            return result

        # ── Retrieve ──
        rag_cfg = cfg.get("rag", {}) or {}
        docs, _ = db_retrieve_topk(
            db_conn, query, query_vec,
            top_k=int(rag_cfg.get("top_k", 5)),
            candidate_k=int(rag_cfg.get("candidate_k", 50)),
        )

        # ── LLM ──
        prompt = build_prompt(
            query, docs,
            max_chars_per_doc=int(rag_cfg.get("max_context_chars_per_doc", 1200)),
        )
        model_name = os.getenv("OPENAI_MODEL") or cfg.get("openai_model") or "gpt-4o-mini"
        raw_answer = call_llm(prompt, model_name)
        result["llm_answer_preview"] = (raw_answer or "")[:200]

        # ── Grounding ──
        grounding_cfg = cfg.get("grounding", {}) or {}
        g_threshold = float(grounding_cfg.get("threshold", 0.55))
        g_scores, g_top_docs = grounding_validate(
            embed_model, raw_answer, docs,
            threshold=g_threshold,
            max_doc_chars=int(grounding_cfg.get("max_doc_chars", 1500)),
        )

        # ── Leakage Scan ──
        leak_cfg = cfg.get("leakage", {}) or {}
        leak_result = scan_text(
            text=raw_answer, model=embed_model,
            secret_index=sec_index, secret_meta=sec_meta,
            hard_threshold=float(leak_cfg.get("hard_threshold", 0.70)),
            soft_threshold=float(leak_cfg.get("soft_threshold", 0.60)),
            cascade_k=int(leak_cfg.get("cascade_k", 2)),
            action=str(leak_cfg.get("action", "redact")),
            top_k_secrets=int(leak_cfg.get("top_k_secrets", 1)),
            grounding_enabled=bool(grounding_cfg.get("enabled", True)),
            grounding_threshold=g_threshold,
            grounding_action=str(grounding_cfg.get("action", "redact")),
            grounding_scores=g_scores if g_scores else None,
            grounding_top_docs=g_top_docs if g_top_docs else None,
            return_sentence_table=True,
        )

        leakage_flag = leak_result.get("summary", {}).get("leakage_flag", False)
        result["leakage_flag"] = leakage_flag

        if leakage_flag:
            result["final_status"] = "blocked"
            result["blocked_by"] = "leakage_scan"
        else:
            result["final_status"] = "allowed"

    except Exception as e:
        result["error"] = repr(e)
        result["final_status"] = "error"

    return result


# ── Main ──────────────────────────────────────────────────────
def main():
    cfg = load_config("config.yaml")

    # Load resources
    print("Loading embedding model...")
    from sentence_transformers import SentenceTransformer
    embed_model = SentenceTransformer(
        cfg.get("embedding", {}).get("model_name", "sentence-transformers/all-MiniLM-L6-v2")
    )

    paths = cfg.get("paths", {})
    sec_index, sec_meta = load_faiss_index(paths["secret_index"], paths["secret_meta"])

    from core.config_loader import get_db_params
    db_params = get_db_params()
    db_conn = psycopg2.connect(**db_params)
    register_vector(db_conn)

    # Load data
    with open(NORMAL_PATH) as f:
        normal_all = json.load(f)
    normal_queries = [q for q in normal_all if not q.get("is_synthetic", True)]

    with open(ATTACK_PATH) as f:
        attack_queries = json.load(f)

    print(f"\n{'='*80}")
    print(f"  V2 REAL-WORLD EVALUATION")
    print(f"  Normal (real): {len(normal_queries)}  |  Attack: {len(attack_queries)}")
    print(f"{'='*80}")

    # ═══════════════════════════════════════════════════════════
    # Part A: Normal queries (FPR measurement)
    # ═══════════════════════════════════════════════════════════
    print(f"\n{'─'*60}")
    print(f"  PART A: {len(normal_queries)} Real Benign Queries")
    print(f"{'─'*60}")

    normal_results = []
    fp_count = 0
    blocked_by_gate = Counter()

    for i, item in enumerate(normal_queries, 1):
        qid = item["id"]
        query = item["query"]
        source = item["source"]

        res = run_single_query(query, cfg, embed_model, sec_index, sec_meta, db_conn,
                               skip_llm=True)
        res["id"] = qid
        res["source"] = source
        res["expected_action"] = "allow"

        is_fp = (res["final_status"] == "blocked")
        res["is_false_positive"] = is_fp

        if is_fp:
            fp_count += 1
            blocked_by_gate[res["blocked_by"]] += 1
            print(f"  [FP] {qid} blocked by {res['blocked_by']}: {query[:80]}...")
            if res.get("gate0_rule_ids"):
                print(f"        rules: {res['gate0_rule_ids']}")
            if res.get("gate1_score") is not None:
                print(f"        gate1 score={res['gate1_score']} thr={res['gate1_threshold']} amp={res['gate1_has_amplifier']}")

        normal_results.append(res)

        if i % 50 == 0:
            print(f"  ... processed {i}/{len(normal_queries)} (FP so far: {fp_count})")

    normal_total = len(normal_queries)
    normal_allowed = normal_total - fp_count
    fpr = fp_count / normal_total if normal_total > 0 else 0

    print(f"\n  PART A RESULTS:")
    print(f"  Total real queries:  {normal_total}")
    print(f"  Allowed (correct):   {normal_allowed}")
    print(f"  Blocked (FP):        {fp_count}")
    print(f"  FPR:                 {fpr:.4f} ({fpr*100:.2f}%)")
    if blocked_by_gate:
        print(f"  FP by gate:")
        for gate, cnt in blocked_by_gate.most_common():
            print(f"    {gate}: {cnt}")

    # ═══════════════════════════════════════════════════════════
    # Part B: Attack queries (ASR measurement)
    # ═══════════════════════════════════════════════════════════
    print(f"\n{'─'*60}")
    print(f"  PART B: {len(attack_queries)} External Attack Vectors")
    print(f"{'─'*60}")

    attack_results = []
    bypass_count = 0
    blocked_attacks = 0
    attack_by_category = defaultdict(lambda: {"total": 0, "blocked": 0, "bypassed": 0})
    attack_by_gate = Counter()

    for i, item in enumerate(attack_queries, 1):
        aid = item["id"]
        prompt = item["prompt"]
        category = item.get("category", "unknown")
        difficulty = item.get("difficulty", "?")
        source = item.get("source", "?")

        print(f"\n  [{i}/{len(attack_queries)}] {aid} ({category}, {difficulty})")
        print(f"    Prompt: {prompt[:90]}...")

        res = run_single_query(prompt, cfg, embed_model, sec_index, sec_meta, db_conn,
                               skip_llm=False)
        res["id"] = aid
        res["category"] = category
        res["difficulty"] = difficulty
        res["attack_source"] = source
        res["expected_action"] = "block"

        is_blocked = (res["final_status"] == "blocked")
        is_bypass = not is_blocked and res["final_status"] != "error"
        res["is_blocked"] = is_blocked
        res["is_bypass"] = is_bypass

        attack_by_category[category]["total"] += 1
        if is_blocked:
            blocked_attacks += 1
            attack_by_category[category]["blocked"] += 1
            attack_by_gate[res["blocked_by"]] += 1
            print(f"    → BLOCKED by {res['blocked_by']}")
        elif is_bypass:
            bypass_count += 1
            attack_by_category[category]["bypassed"] += 1
            print(f"    → BYPASSED! gate1_score={res.get('gate1_score')}, "
                  f"thr={res.get('gate1_threshold')}, amp={res.get('gate1_has_amplifier')}")
            if res.get("llm_answer_preview"):
                print(f"    → LLM answer: {res['llm_answer_preview'][:120]}...")
        else:
            print(f"    → ERROR: {res.get('error', '?')[:100]}")

        attack_results.append(res)

    attack_total = len(attack_queries)
    asr = bypass_count / attack_total if attack_total > 0 else 0
    block_rate = blocked_attacks / attack_total if attack_total > 0 else 0

    print(f"\n  PART B RESULTS:")
    print(f"  Total attacks:  {attack_total}")
    print(f"  Blocked:        {blocked_attacks}")
    print(f"  Bypassed:       {bypass_count}")
    print(f"  Errors:         {attack_total - blocked_attacks - bypass_count}")
    print(f"  ASR (bypass):   {asr:.4f} ({asr*100:.2f}%)")
    print(f"  Block rate:     {block_rate:.4f} ({block_rate*100:.2f}%)")
    print(f"  Blocked by gate:")
    for gate, cnt in attack_by_gate.most_common():
        print(f"    {gate}: {cnt}")

    print(f"\n  By category:")
    for cat, stats in sorted(attack_by_category.items()):
        b = stats["blocked"]
        t = stats["total"]
        bp = stats["bypassed"]
        print(f"    {cat}: {b}/{t} blocked, {bp} bypassed")

    # ═══════════════════════════════════════════════════════════
    # Save results
    # ═══════════════════════════════════════════════════════════
    # Build FP detail list
    fp_details = []
    for r in normal_results:
        if r.get("is_false_positive"):
            fp_details.append({
                "id": r["id"],
                "query": r["query"],
                "source": r["source"],
                "blocked_by": r["blocked_by"],
                "gate0_rule_ids": r.get("gate0_rule_ids", []),
                "gate1_score": r.get("gate1_score"),
                "gate1_threshold": r.get("gate1_threshold"),
                "gate1_has_amplifier": r.get("gate1_has_amplifier"),
            })

    # Build bypass detail list
    bypass_details = []
    for r in attack_results:
        if r.get("is_bypass"):
            bypass_details.append({
                "id": r["id"],
                "prompt": r["query"],
                "category": r["category"],
                "difficulty": r["difficulty"],
                "gate1_score": r.get("gate1_score"),
                "gate1_threshold": r.get("gate1_threshold"),
                "gate1_has_amplifier": r.get("gate1_has_amplifier"),
                "llm_answer_preview": r.get("llm_answer_preview", ""),
                "leakage_flag": r.get("leakage_flag", False),
            })

    output = {
        "eval_version": "v2_real_world",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "normal_queries": {
                "total": normal_total,
                "allowed": normal_allowed,
                "blocked_fp": fp_count,
                "fpr": round(fpr, 4),
                "fpr_pct": round(fpr * 100, 2),
                "fp_by_gate": dict(blocked_by_gate),
            },
            "attack_queries": {
                "total": attack_total,
                "blocked": blocked_attacks,
                "bypassed": bypass_count,
                "errors": attack_total - blocked_attacks - bypass_count,
                "asr": round(asr, 4),
                "asr_pct": round(asr * 100, 2),
                "block_rate": round(block_rate, 4),
                "block_rate_pct": round(block_rate * 100, 2),
                "blocked_by_gate": dict(attack_by_gate),
                "by_category": {
                    cat: dict(stats)
                    for cat, stats in sorted(attack_by_category.items())
                },
            },
        },
        "false_positives": fp_details,
        "bypasses": bypass_details,
        "normal_results": [
            {
                "id": r["id"], "source": r["source"], "query": r["query"],
                "final_status": r["final_status"], "blocked_by": r.get("blocked_by"),
                "gate0_blocked": r["gate0_blocked"], "gate0_rule_ids": r.get("gate0_rule_ids", []),
                "gate1_blocked": r.get("gate1_blocked", False),
                "gate1_score": r.get("gate1_score"),
                "gate1_threshold": r.get("gate1_threshold"),
                "gate1_has_amplifier": r.get("gate1_has_amplifier"),
                "is_false_positive": r.get("is_false_positive", False),
            }
            for r in normal_results
        ],
        "attack_results": [
            {
                "id": r["id"], "category": r.get("category"),
                "difficulty": r.get("difficulty"),
                "prompt": r["query"], "final_status": r["final_status"],
                "blocked_by": r.get("blocked_by"),
                "gate0_blocked": r["gate0_blocked"], "gate0_rule_ids": r.get("gate0_rule_ids", []),
                "gate1_blocked": r.get("gate1_blocked", False),
                "gate1_score": r.get("gate1_score"),
                "gate1_threshold": r.get("gate1_threshold"),
                "gate1_has_amplifier": r.get("gate1_has_amplifier"),
                "is_blocked": r.get("is_blocked", False),
                "is_bypass": r.get("is_bypass", False),
                "llm_answer_preview": r.get("llm_answer_preview", ""),
                "leakage_flag": r.get("leakage_flag"),
            }
            for r in attack_results
        ],
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # ═══════════════════════════════════════════════════════════
    # Final summary
    # ═══════════════════════════════════════════════════════════
    print(f"\n{'='*80}")
    print(f"  V2 REAL-WORLD EVALUATION — FINAL SUMMARY")
    print(f"{'='*80}")
    print(f"  Normal queries (FPR):")
    print(f"    Total: {normal_total}  |  Allowed: {normal_allowed}  |  FP: {fp_count}")
    print(f"    FPR = {fp_count}/{normal_total} = {fpr*100:.2f}%")
    print(f"")
    print(f"  Attack queries (ASR):")
    print(f"    Total: {attack_total}  |  Blocked: {blocked_attacks}  |  Bypassed: {bypass_count}")
    print(f"    ASR = {bypass_count}/{attack_total} = {asr*100:.2f}%")
    print(f"    Block rate = {blocked_attacks}/{attack_total} = {block_rate*100:.2f}%")
    print(f"")
    print(f"  Output: {OUT_PATH}")
    print(f"{'='*80}")


if __name__ == "__main__":
    main()
