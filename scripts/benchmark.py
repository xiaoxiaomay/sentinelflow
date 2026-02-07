#!/usr/bin/env python3
"""
scripts/benchmark.py

Multi-mode benchmark runner for SentinelFlow.

Modes:
  - attack:   JailbreakBench + AdvBench + custom exfil -> ASR, blocking_rate
  - benign:   Financial PhraseBank + FinanceRAG queries -> FPR
  - leakage:  Salesforce prompt-leakage -> SLPR
  - ablation: Full attack suite x gate combinations -> marginal gate value
  - all:      Run all modes

Usage:
    python scripts/benchmark.py --mode all --config config.yaml
    python scripts/benchmark.py --mode attack --config config.yaml
    python scripts/benchmark.py --mode benign --config config.yaml --max_queries 50
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_jsonl(path: str) -> List[dict]:
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def read_appended_jsonl(path: str, start_pos: int) -> Tuple[List[dict], int]:
    if not os.path.exists(path):
        return [], start_pos
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        f.seek(start_pos)
        for line in f:
            if line.strip():
                try:
                    rows.append(json.loads(line.strip()))
                except Exception:
                    continue
        end_pos = f.tell()
    return rows, end_pos


def run_query(query: str, config_path: str, timeout: int = 60) -> dict:
    """Run a single query through the pipeline and return audit analysis."""
    audit_cfg = load_config(config_path).get("audit", {})
    audit_path = str(Path(audit_cfg.get("out_dir", "data/audit")) / audit_cfg.get("file_name", "audit_log.jsonl"))

    start_pos = os.path.getsize(audit_path) if os.path.exists(audit_path) else 0
    t0 = time.time()

    cmd = ["python", "scripts/run_rag_with_audit.py", "--query", query, "--config", config_path]
    try:
        subprocess.run(cmd, check=True, timeout=timeout, capture_output=True)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return {"outcome": "error", "error": str(e), "latency_s": time.time() - t0}

    latency = time.time() - t0
    new_records, _ = read_appended_jsonl(audit_path, start_pos)

    if not new_records:
        return {"outcome": "error", "error": "no_audit_records", "latency_s": latency}

    # Analyze outcome
    llm_called = any(r.get("type") == "llm_response" for r in new_records)
    blocked_by = None
    final_answer = ""

    finals = [r for r in new_records if r.get("type") == "final_output"]
    if finals:
        body = finals[-1].get("body", {})
        final_answer = body.get("final_answer", "")
        blocked_by = body.get("blocked_by")

    outcome = "block" if (blocked_by or final_answer.startswith("[BLOCKED]")) else "allow"

    # Extract DFP scores if present
    leakage_events = [r for r in new_records if r.get("type") == "leakage_scan"]
    dfp_scores = {}
    if leakage_events:
        summary = leakage_events[-1].get("body", {}).get("summary", {})
        dfp_scores = {
            "dfp_composite": summary.get("dfp_composite_score"),
            "dfp_elevated": summary.get("dfp_elevated_count"),
        }

    # Extract guard result if present
    guard_events = [r for r in new_records if r.get("type") == "llm_guard"]
    guard_info = {}
    if guard_events:
        gb = guard_events[-1].get("body", {})
        guard_info = {
            "guard_blocked": gb.get("blocked"),
            "guard_score": gb.get("score"),
            "guard_backend": gb.get("backend"),
        }

    return {
        "outcome": outcome,
        "blocked_by": blocked_by or "",
        "llm_called": llm_called,
        "latency_s": round(latency, 3),
        "final_answer_preview": final_answer[:200],
        **dfp_scores,
        **guard_info,
    }


# ---------------------------------------------------------------------------
# Benchmark modes
# ---------------------------------------------------------------------------

def run_attack_benchmark(cfg: dict, config_path: str, max_queries: int = 0) -> dict:
    """Run attack prompts (JailbreakBench + AdvBench + custom exfil)."""
    print("\n=== ATTACK BENCHMARK ===\n")

    bench_cfg = cfg.get("benchmark", {})
    datasets_cfg = bench_cfg.get("datasets", {})
    timeout = int(bench_cfg.get("timeout_per_query_s", 60))

    # Collect prompts
    prompts = []
    for ds_name in ["jailbreakbench", "advbench", "custom_exfil"]:
        ds = datasets_cfg.get(ds_name, {})
        path = ds.get("local_cache") or ds.get("source", "")
        records = load_jsonl(path)
        for r in records:
            r["dataset"] = ds_name
        prompts.extend(records)

    if max_queries > 0:
        prompts = prompts[:max_queries]

    print(f"Total attack prompts: {len(prompts)}")

    results = []
    blocked = 0
    gate_distribution = {}

    for i, p in enumerate(prompts):
        query = p.get("query", "")
        if not query or "PLACEHOLDER" in query:
            continue

        print(f"  [{i+1}/{len(prompts)}] {p.get('dataset', '')} | {query[:60]}...")
        result = run_query(query, config_path, timeout)
        result["prompt_id"] = p.get("prompt_id", f"ATK_{i}")
        result["dataset"] = p.get("dataset", "")
        result["expected"] = p.get("expected", "block")
        results.append(result)

        if result["outcome"] == "block":
            blocked += 1
            gate = result.get("blocked_by", "unknown")
            gate_distribution[gate] = gate_distribution.get(gate, 0) + 1

    total = len(results) or 1
    asr = 1.0 - (blocked / total)  # Attack Success Rate (lower is better)
    blocking_rate = blocked / total

    summary = {
        "mode": "attack",
        "total_prompts": total,
        "blocked": blocked,
        "allowed_through": total - blocked,
        "asr": round(asr, 4),
        "blocking_rate": round(blocking_rate, 4),
        "gate_distribution": gate_distribution,
    }

    print(f"\n  ASR: {asr:.2%} (lower is better)")
    print(f"  Blocking rate: {blocking_rate:.2%}")
    print(f"  Gate distribution: {gate_distribution}")

    return {"summary": summary, "results": results}


def run_benign_benchmark(cfg: dict, config_path: str, max_queries: int = 0) -> dict:
    """Run benign prompts (Financial PhraseBank) to measure FPR."""
    print("\n=== BENIGN BENCHMARK ===\n")

    bench_cfg = cfg.get("benchmark", {})
    datasets_cfg = bench_cfg.get("datasets", {})
    timeout = int(bench_cfg.get("timeout_per_query_s", 60))

    prompts = []
    for ds_name in ["financial_phrasebank"]:
        ds = datasets_cfg.get(ds_name, {})
        path = ds.get("local_cache") or ds.get("source", "")
        records = load_jsonl(path)
        for r in records:
            r["dataset"] = ds_name
        prompts.extend(records)

    if max_queries > 0:
        prompts = prompts[:max_queries]

    print(f"Total benign prompts: {len(prompts)}")

    results = []
    false_positives = 0
    fp_gate_distribution = {}

    for i, p in enumerate(prompts):
        query = p.get("query", "")
        if not query or "PLACEHOLDER" in query:
            continue

        print(f"  [{i+1}/{len(prompts)}] {query[:60]}...")
        result = run_query(query, config_path, timeout)
        result["prompt_id"] = p.get("prompt_id", f"BEN_{i}")
        result["dataset"] = p.get("dataset", "")
        result["expected"] = "allow"
        results.append(result)

        if result["outcome"] == "block":
            false_positives += 1
            gate = result.get("blocked_by", "unknown")
            fp_gate_distribution[gate] = fp_gate_distribution.get(gate, 0) + 1

    total = len(results) or 1
    fpr = false_positives / total

    summary = {
        "mode": "benign",
        "total_prompts": total,
        "false_positives": false_positives,
        "fpr": round(fpr, 4),
        "fp_gate_distribution": fp_gate_distribution,
    }

    print(f"\n  FPR: {fpr:.2%} (lower is better, target < 5%)")
    print(f"  FP gate distribution: {fp_gate_distribution}")

    return {"summary": summary, "results": results}


def run_leakage_benchmark(cfg: dict, config_path: str, max_queries: int = 0) -> dict:
    """Run leakage prompts (Salesforce + custom exfil) -> SLPR."""
    print("\n=== LEAKAGE BENCHMARK ===\n")

    bench_cfg = cfg.get("benchmark", {})
    datasets_cfg = bench_cfg.get("datasets", {})
    timeout = int(bench_cfg.get("timeout_per_query_s", 60))

    prompts = []
    for ds_name in ["salesforce_prompt_leakage", "custom_exfil"]:
        ds = datasets_cfg.get(ds_name, {})
        path = ds.get("local_cache") or ds.get("source", "")
        records = load_jsonl(path)
        for r in records:
            r["dataset"] = ds_name
        prompts.extend(records)

    if max_queries > 0:
        prompts = prompts[:max_queries]

    print(f"Total leakage prompts: {len(prompts)}")

    results = []
    prevented = 0

    for i, p in enumerate(prompts):
        query = p.get("query", "")
        if not query or "PLACEHOLDER" in query:
            continue

        print(f"  [{i+1}/{len(prompts)}] {query[:60]}...")
        result = run_query(query, config_path, timeout)
        result["prompt_id"] = p.get("prompt_id", f"LEAK_{i}")
        result["dataset"] = p.get("dataset", "")
        result["expected"] = p.get("expected", "block")
        results.append(result)

        if result["outcome"] == "block" or "[REDACTED]" in result.get("final_answer_preview", ""):
            prevented += 1

    total = len(results) or 1
    slpr = prevented / total

    summary = {
        "mode": "leakage",
        "total_prompts": total,
        "prevented": prevented,
        "slpr": round(slpr, 4),
    }

    print(f"\n  SLPR: {slpr:.2%} (higher is better, target > 95%)")

    return {"summary": summary, "results": results}


def run_ablation(cfg: dict, config_path: str, max_queries: int = 0) -> dict:
    """
    Run ablation analysis: test with each gate individually disabled.
    This is a reporting framework — actual gate toggling requires config modification.
    """
    print("\n=== ABLATION ANALYSIS ===\n")
    print("  Note: Full ablation requires running with modified configs.")
    print("  This mode reports the current baseline and provides the framework.")

    # Report current gate configuration
    policy = cfg.get("policy", {})
    precheck = cfg.get("query_precheck", {})
    guard = cfg.get("guard", {})
    dfp = cfg.get("dfp", {})

    config_state = {
        "rule_gate_enabled": bool(policy.get("hard_block", {}).get("enabled", True)),
        "embedding_precheck_enabled": bool(precheck.get("enabled", True)),
        "llm_guard_enabled": bool(guard.get("enabled", False)),
        "dfp_enabled": bool(dfp.get("enabled", False)),
        "precheck_threshold": precheck.get("threshold", 0.60),
    }

    summary = {
        "mode": "ablation",
        "config_state": config_state,
        "note": "Run with modified configs to compute marginal gate values",
        "gates": ["rule_gate", "embedding_precheck", "llm_guard", "dfp"],
    }

    print(f"  Current config: {json.dumps(config_state, indent=2)}")

    return {"summary": summary, "results": []}


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(all_results: dict, reports_dir: str, cfg: dict):
    """Generate benchmark_summary.json and benchmark_report.csv."""
    Path(reports_dir).mkdir(parents=True, exist_ok=True)

    # Build summary
    summary = {
        "standard_benchmarks": {},
        "domain_benchmarks": {},
        "operational_metrics": {"latencies": []},
        "demo_cases": {},
    }

    if "attack" in all_results:
        atk = all_results["attack"]["summary"]
        summary["standard_benchmarks"]["attack_success_rate"] = atk.get("asr", None)
        summary["standard_benchmarks"]["attack_blocking_rate"] = atk.get("blocking_rate", None)
        summary["standard_benchmarks"]["gate_distribution"] = atk.get("gate_distribution", {})

    if "benign" in all_results:
        ben = all_results["benign"]["summary"]
        summary["domain_benchmarks"]["financial_phrasebank_fpr"] = ben.get("fpr", None)

    if "leakage" in all_results:
        leak = all_results["leakage"]["summary"]
        summary["domain_benchmarks"]["strategy_leakage_prevention_rate"] = leak.get("slpr", None)

    if "ablation" in all_results:
        summary["ablation"] = all_results["ablation"]["summary"]

    # Collect all latencies
    all_latencies = []
    for mode_name, mode_data in all_results.items():
        for r in mode_data.get("results", []):
            lat = r.get("latency_s")
            if lat and lat > 0:
                all_latencies.append(lat)

    if all_latencies:
        all_latencies.sort()
        n = len(all_latencies)
        summary["operational_metrics"] = {
            "latency_p50_ms": round(all_latencies[n // 2] * 1000, 1),
            "latency_p95_ms": round(all_latencies[int(n * 0.95)] * 1000, 1) if n > 1 else None,
            "latency_p99_ms": round(all_latencies[int(n * 0.99)] * 1000, 1) if n > 1 else None,
            "total_queries": n,
        }

    # Write summary JSON
    summary_path = str(Path(reports_dir) / "benchmark_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\nSaved: {summary_path}")

    # Write detailed CSV
    csv_path = str(Path(reports_dir) / "benchmark_report.csv")
    all_rows = []
    for mode_name, mode_data in all_results.items():
        for r in mode_data.get("results", []):
            all_rows.append({
                "mode": mode_name,
                "prompt_id": r.get("prompt_id", ""),
                "dataset": r.get("dataset", ""),
                "expected": r.get("expected", ""),
                "outcome": r.get("outcome", ""),
                "blocked_by": r.get("blocked_by", ""),
                "llm_called": r.get("llm_called", ""),
                "latency_s": r.get("latency_s", ""),
                "dfp_composite": r.get("dfp_composite", ""),
                "guard_blocked": r.get("guard_blocked", ""),
            })

    if all_rows:
        fieldnames = list(all_rows[0].keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in all_rows:
                writer.writerow(row)
        print(f"Saved: {csv_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

MODES = {
    "attack": run_attack_benchmark,
    "benign": run_benign_benchmark,
    "leakage": run_leakage_benchmark,
    "ablation": run_ablation,
}


def main():
    ap = argparse.ArgumentParser(description="SentinelFlow Benchmark Runner")
    ap.add_argument("--mode", default="all", choices=list(MODES.keys()) + ["all"])
    ap.add_argument("--config", default="config.yaml", type=str)
    ap.add_argument("--max_queries", default=0, type=int, help="Max queries per mode (0=unlimited)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    bench_cfg = cfg.get("benchmark", {})
    reports_dir = bench_cfg.get("reports_dir", "reports")

    print("=== SentinelFlow Benchmark Suite ===")
    print(f"Config: {args.config}")
    print(f"Mode: {args.mode}")
    if args.max_queries > 0:
        print(f"Max queries per mode: {args.max_queries}")

    all_results = {}

    if args.mode == "all":
        for name, func in MODES.items():
            result = func(cfg, args.config, args.max_queries)
            all_results[name] = result
    else:
        result = MODES[args.mode](cfg, args.config, args.max_queries)
        all_results[args.mode] = result

    generate_report(all_results, reports_dir, cfg)
    print("\n=== Benchmark Complete ===")


if __name__ == "__main__":
    main()
