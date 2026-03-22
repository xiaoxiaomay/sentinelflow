#!/usr/bin/env python3
"""
Phase 16f: Compare evaluation results between secrets_v1 (original 60 entries)
and secrets_v2 (upgraded 90 entries, 6 alpha domains).
"""
import json
import sys
from pathlib import Path


def load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def compare_ablation(v1_path: str, v2_path: str):
    """Compare ablation results between v1 and v2."""
    v1 = load_json(v1_path)
    v2 = load_json(v2_path)

    v1_configs = {c["config_id"]: c for c in v1["configs"]}
    v2_configs = {c["config_id"]: c for c in v2["configs"]}

    print("=" * 100)
    print("ABLATION COMPARISON: secrets_v1 (60 entries) vs secrets_v2 (90 entries, 6 alpha domains)")
    print("=" * 100)
    print(f"\n{'Config':<16} {'ASR_v1':>8} {'ASR_v2':>8} {'Δ ASR':>8}  "
          f"{'FPR_v1':>8} {'FPR_v2':>8} {'Δ FPR':>8}")
    print("-" * 100)

    for cid in ["B0", "B2_no_G0a", "B2_no_G0b", "B2_no_G1", "B2_no_LS", "B2_single_tau", "B2_full"]:
        c1 = v1_configs.get(cid, {})
        c2 = v2_configs.get(cid, {})
        asr1 = c1.get("asr", 0)
        asr2 = c2.get("asr", 0)
        fpr1 = c1.get("fpr", 0)
        fpr2 = c2.get("fpr", 0)
        d_asr = asr2 - asr1
        d_fpr = fpr2 - fpr1
        print(f"{cid:<16} {asr1:>7.2%} {asr2:>7.2%} {d_asr:>+7.2%}  "
              f"{fpr1:>7.2%} {fpr2:>7.2%} {d_fpr:>+7.2%}")

    print("-" * 100)

    # Key metrics for B2_full
    full_v1 = v1_configs.get("B2_full", {})
    full_v2 = v2_configs.get("B2_full", {})
    print(f"\nB2_full (Full SentinelFlow):")
    print(f"  v1: ASR={full_v1.get('asr', 0):.2%}, FPR={full_v1.get('fpr', 0):.2%}, "
          f"Blocked={full_v1.get('attack_blocked', 0)}/{full_v1.get('attack_total', 0)}")
    print(f"  v2: ASR={full_v2.get('asr', 0):.2%}, FPR={full_v2.get('fpr', 0):.2%}, "
          f"Blocked={full_v2.get('attack_blocked', 0)}/{full_v2.get('attack_total', 0)}")


def compare_external(v1_path: str, v2_path: str):
    """Compare external framework eval results."""
    v1 = load_json(v1_path)
    v2 = load_json(v2_path)

    print("\n\n" + "=" * 100)
    print("EXTERNAL FRAMEWORK COMPARISON")
    print("=" * 100)

    for version, data, label in [(v1, "v1"), (v2, "v2")]:
        summary = data if isinstance(data, dict) else {}
        # Try to extract summary metrics
        total = summary.get("total_prompts", 0)
        blocked = summary.get("total_blocked", 0)
        rate = blocked / total if total > 0 else 0
        print(f"  {label}: {blocked}/{total} blocked ({rate:.1%})")


def compare_latency(v1_path: str, v2_path: str):
    """Compare latency benchmark results."""
    v1 = load_json(v1_path)
    v2 = load_json(v2_path)

    print("\n\n" + "=" * 100)
    print("LATENCY COMPARISON")
    print("=" * 100)

    for label, data in [("v1", v1), ("v2", v2)]:
        gates = data.get("per_gate", {})
        e2e = data.get("end_to_end", {})
        p50 = e2e.get("p50_ms", "N/A")
        p95 = e2e.get("p95_ms", "N/A")
        print(f"  {label} end-to-end: P50={p50}ms, P95={p95}ms")


def main():
    repo = Path(__file__).resolve().parents[1]
    results = repo / "eval" / "results"

    # Ablation comparison
    v1_ablation = results / "ablation_results.json"
    v2_ablation = results / "ablation_v2.json"
    if v1_ablation.exists() and v2_ablation.exists():
        compare_ablation(str(v1_ablation), str(v2_ablation))
    else:
        print(f"Missing ablation files: v1={v1_ablation.exists()}, v2={v2_ablation.exists()}")

    # External framework comparison
    v1_ext = results / "harmbench_results.json"
    v2_ext = results / "harmbench_v2_results.json"
    if v1_ext.exists() and v2_ext.exists():
        compare_external(str(v1_ext), str(v2_ext))

    # Latency comparison
    v1_lat = results / "latency_results.json"
    v2_lat = results / "latency_v2.json"
    if v1_lat.exists() and v2_lat.exists():
        compare_latency(str(v1_lat), str(v2_lat))

    print("\n\n" + "=" * 100)
    print("SUMMARY")
    print("=" * 100)
    print("Secrets v2 dataset: 90 entries (30 L3 + 30 L2 + 30 L1)")
    print("Covers 6 institutional alpha domains:")
    print("  1. Price/Volume Momentum")
    print("  2. Event Driven")
    print("  3. Statistical Arbitrage")
    print("  4. Alternative Data")
    print("  5. Factor Neutralization")
    print("  6. ML Signals")


if __name__ == "__main__":
    main()
