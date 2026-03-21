#!/usr/bin/env python3
"""
eval/ablation_table.py

Reads ablation_results.json and generates a LaTeX table for the paper.

Input:  eval/results/ablation_results.json
Output: eval/latex_tables/table_ablation.tex
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def generate_latex_table(results_path: str, output_path: str):
    with open(results_path, "r") as f:
        data = json.load(f)

    configs = data.get("configs", [])

    lines = [
        r"\begin{table*}[htbp]",
        r"\centering",
        r"\caption{Ablation Study: Per-Gate Contribution Analysis}",
        r"\label{tab:ablation}",
        r"\begin{tabular}{llcccc}",
        r"\toprule",
        r"\textbf{Config} & \textbf{Gates Active} & \textbf{ASR (\%)} & \textbf{FPR (\%)} & \textbf{Blocked} & \textbf{Latency (ms)} \\",
        r"\midrule",
    ]

    for c in configs:
        cid = c["config_id"].replace("_", r"\_")
        gates = c.get("gates_active", {})
        active = [k for k, v in gates.items() if v and k != "single_tau"]
        gates_str = ", ".join(active) if active else "None"
        if len(gates_str) > 30:
            gates_str = f"{len(active)} gates"

        asr_pct = c["asr"] * 100
        fpr_pct = c["fpr"] * 100
        blocked_str = f"{c['attack_blocked']}/{c['attack_total']}"
        latency = c["avg_latency_ms"]

        lines.append(
            f"  {cid} & {gates_str} & {asr_pct:.1f} & {fpr_pct:.1f} & {blocked_str} & {latency:.1f} \\\\"
        )

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table*}",
    ])

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Saved: {output_path}")


def main():
    results_path = str(REPO_ROOT / "eval" / "results" / "ablation_results.json")
    output_path = str(REPO_ROOT / "eval" / "latex_tables" / "table_ablation.tex")

    if len(sys.argv) > 1:
        results_path = sys.argv[1]
    if len(sys.argv) > 2:
        output_path = sys.argv[2]

    generate_latex_table(results_path, output_path)


if __name__ == "__main__":
    main()
