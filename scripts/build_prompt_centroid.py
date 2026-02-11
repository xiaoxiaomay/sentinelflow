#!/usr/bin/env python3
"""
scripts/build_prompt_centroid.py

Builds the normal prompt centroid from data/benchmark/normal_prompts.jsonl.
Used by C4 prompt distribution monitoring.

Usage:
    python scripts/build_prompt_centroid.py --config config.yaml
"""
import json
import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

NORMAL_PROMPTS_PATH = REPO_ROOT / "data" / "benchmark" / "normal_prompts.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "index" / "normal_centroid.pkl"


def main():
    ap = argparse.ArgumentParser(description="Build normal prompt centroid for C4 monitoring")
    ap.add_argument("--config", default="config.yaml", type=str)
    ap.add_argument("--output", default=None, type=str, help="Override output path")
    args = ap.parse_args()

    import yaml
    with open(args.config, "r") as f:
        cfg = yaml.safe_load(f) or {}

    pm_cfg = cfg.get("prompt_monitoring", {}) or {}
    output_path = args.output or pm_cfg.get("centroid_path", str(DEFAULT_OUTPUT))
    output_path = Path(output_path)

    # Load normal prompts
    prompts = []
    with open(NORMAL_PROMPTS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rec = json.loads(line)
                prompts.append(rec["query"])

    print(f"Loaded {len(prompts)} normal prompts from {NORMAL_PROMPTS_PATH}")

    # Embed and compute centroid
    from sentence_transformers import SentenceTransformer
    from scripts.prompt_monitor import compute_centroid, save_centroid

    emb_model_name = cfg.get("embedding", {}).get("model_name", "sentence-transformers/all-MiniLM-L6-v2")
    model = SentenceTransformer(emb_model_name)

    centroid_data = compute_centroid(model, prompts)

    print(f"Centroid computed from {centroid_data['n_prompts']} prompts")
    print(f"  Mean distance: {centroid_data['mean_dist']:.6f}")
    print(f"  Std distance:  {centroid_data['std_dist']:.6f}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    save_centroid(centroid_data, str(output_path))
    print(f"Saved centroid to: {output_path}")


if __name__ == "__main__":
    main()
