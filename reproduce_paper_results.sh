#!/bin/bash
# One-command reproduction of all paper results
# Usage: ./reproduce_paper_results.sh
# For full pipeline eval (requires OpenAI API):
#   OPENAI_API_KEY=sk-... ./reproduce_paper_results.sh --full

set -e

echo "=== SentinelFlow Paper Results Reproduction ==="
echo "Estimated time: ~15 minutes (gate-level eval, no LLM calls needed)"
echo ""

# Ensure output directories exist
mkdir -p eval/results eval/figures eval/latex_tables

# Phase 1: Skip prompt generation if expanded file already exists
if [ -f "data/attack_prompts_expanded.jsonl" ]; then
    echo "[1/6] Expanded attack prompts already exist (271 prompts) — skipping generation"
else
    echo "[1/6] Generating expanded attack prompts (requires ANTHROPIC_API_KEY)..."
    python scripts/generate_adversarial_prompts.py
fi

# Phase 2: Ablation study
echo "[2/6] Running ablation study (7 configurations, no LLM calls)..."
python eval/run_ablation.py --all --output eval/results/ablation.json

# Phase 3: Statistical evaluation (5 runs)
echo "[3/6] Running statistical evaluation (5 runs, no LLM calls)..."
python eval/run_statistical_eval.py --runs 5 --output eval/results/core_eval.json

# Phase 4: Latency benchmark
echo "[4/6] Running latency benchmark..."
python eval/run_latency_benchmark.py --output eval/results/latency.json

# Phase 5: Medical generalization
echo "[5/6] Running medical domain evaluation (no LLM calls)..."
python eval/run_medical_eval.py --output eval/results/medical.json

# Phase 6: Generate all LaTeX tables
echo "[6/6] Generating LaTeX tables..."
python eval/generate_latex_tables.py --results-dir eval/results/ --output eval/latex_tables/

echo ""
echo "=== Done. Results saved to eval/results/ ==="
echo "LaTeX tables saved to eval/latex_tables/"
echo "Latency plot saved to eval/figures/latency_plot.pdf"
echo ""
echo "To run full pipeline eval with LLM (true ASR measurement):"
echo "  OPENAI_API_KEY=sk-... python eval/run_full_pipeline_eval.py"
