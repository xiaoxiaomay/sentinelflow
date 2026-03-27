#!/usr/bin/env python3
"""
scripts/benchmark_data.py

Download and prepare benchmark datasets for SentinelFlow evaluation.

Datasets:
  - JailbreakBench (JBB-Behaviors): 100 standard jailbreak behaviors
  - AdvBench (harmful_behaviors.csv): 520 attack prompts
  - Salesforce prompt-leakage (finance subset): multi-turn leakage attempts
  - Financial PhraseBank (Sentences_AllAgree.txt): benign financial baseline
  - Custom strategy exfiltration: finance-specific attack prompts

Usage:
    python scripts/benchmark_data.py --config config.yaml --dataset all
    python scripts/benchmark_data.py --config config.yaml --dataset jailbreakbench
"""

import argparse
import csv
import json
import os
import random
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def safe_write_jsonl(records: list, path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"  Wrote {len(records)} records to {path}")


# ---------------------------------------------------------------------------
# JailbreakBench
# ---------------------------------------------------------------------------

def prepare_jailbreakbench(cfg: dict):
    """Download JailbreakBench behaviors from HuggingFace datasets."""
    ds_cfg = cfg.get("datasets", {}).get("jailbreakbench", {})
    cache_path = ds_cfg.get("local_cache", "data/benchmark/jailbreakbench.jsonl")

    if os.path.exists(cache_path):
        print(f"  [skip] {cache_path} already exists")
        return

    print("  Downloading JailbreakBench...")
    try:
        from datasets import load_dataset
        ds = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split="harmful")
        records = []
        for i, row in enumerate(ds):
            records.append({
                "prompt_id": f"JBB_{i:03d}",
                "source": "jailbreakbench",
                "category": row.get("Category", "unknown"),
                "query": row.get("Behavior", row.get("Goal", "")),
                "expected": "block",
            })
        safe_write_jsonl(records, cache_path)
    except Exception as e:
        print(f"  [error] Could not download JailbreakBench: {e}")
        print("  [fallback] Creating placeholder file")
        safe_write_jsonl([{
            "prompt_id": "JBB_PLACEHOLDER",
            "source": "jailbreakbench",
            "query": "PLACEHOLDER - install 'datasets' and retry",
            "expected": "block",
        }], cache_path)


# ---------------------------------------------------------------------------
# AdvBench
# ---------------------------------------------------------------------------

def prepare_advbench(cfg: dict):
    """Parse AdvBench harmful_behaviors.csv into JSONL format."""
    ds_cfg = cfg.get("datasets", {}).get("advbench", {})
    source = ds_cfg.get("source", "data/raw/harmful_behaviors.csv")
    cache_path = ds_cfg.get("local_cache", "data/benchmark/advbench_prompts.jsonl")

    if os.path.exists(cache_path):
        print(f"  [skip] {cache_path} already exists")
        return

    if not os.path.exists(source):
        print(f"  [skip] Source not found: {source}")
        safe_write_jsonl([{
            "prompt_id": "ADV_PLACEHOLDER",
            "source": "advbench",
            "query": "PLACEHOLDER - download harmful_behaviors.csv",
            "expected": "block",
        }], cache_path)
        return

    print(f"  Parsing AdvBench from {source}...")
    records = []
    with open(source, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for i, row in enumerate(reader):
            if row:
                query = row[0].strip()
                if query:
                    records.append({
                        "prompt_id": f"ADV_{i:03d}",
                        "source": "advbench",
                        "query": query,
                        "expected": "block",
                    })
    safe_write_jsonl(records, cache_path)


# ---------------------------------------------------------------------------
# Salesforce Prompt Leakage
# ---------------------------------------------------------------------------

def prepare_salesforce(cfg: dict):
    """Download Salesforce prompt-leakage dataset (finance subset)."""
    ds_cfg = cfg.get("datasets", {}).get("salesforce_prompt_leakage", {})
    cache_path = ds_cfg.get("local_cache", "data/benchmark/salesforce_leakage.jsonl")

    if os.path.exists(cache_path):
        print(f"  [skip] {cache_path} already exists")
        return

    print("  Downloading Salesforce prompt-leakage...")
    try:
        from datasets import load_dataset
        ds = load_dataset("Salesforce/prompt-leakage", split="test")
        records = []
        for i, row in enumerate(ds):
            records.append({
                "prompt_id": f"SF_{i:03d}",
                "source": "salesforce_prompt_leakage",
                "query": row.get("prompt", row.get("text", "")),
                "category": row.get("category", "unknown"),
                "expected": "block",
            })
        safe_write_jsonl(records, cache_path)
    except Exception as e:
        print(f"  [error] Could not download Salesforce dataset: {e}")
        safe_write_jsonl([{
            "prompt_id": "SF_PLACEHOLDER",
            "source": "salesforce_prompt_leakage",
            "query": "PLACEHOLDER - install 'datasets' and retry",
            "expected": "block",
        }], cache_path)


# ---------------------------------------------------------------------------
# Financial PhraseBank (benign baseline)
# ---------------------------------------------------------------------------

def prepare_financial_phrasebank(cfg: dict):
    """Parse Financial PhraseBank Sentences_AllAgree.txt (benign baseline)."""
    ds_cfg = cfg.get("datasets", {}).get("financial_phrasebank", {})
    source = ds_cfg.get("source", "data/raw/FinancialPhraseBank-v1.0/Sentences_AllAgree.txt")
    cache_path = ds_cfg.get("local_cache", "data/benchmark/financial_phrasebank.jsonl")
    sample_size = int(ds_cfg.get("sample_size", 200))
    seed = int(ds_cfg.get("seed", 42))

    if os.path.exists(cache_path):
        print(f"  [skip] {cache_path} already exists")
        return

    if not os.path.exists(source):
        print(f"  [skip] Source not found: {source}")
        safe_write_jsonl([{
            "prompt_id": "FPB_PLACEHOLDER",
            "source": "financial_phrasebank",
            "query": "PLACEHOLDER - download FinancialPhraseBank",
            "expected": "allow",
        }], cache_path)
        return

    print(f"  Parsing Financial PhraseBank from {source}...")
    all_sentences = []
    with open(source, "r", encoding="latin-1") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Format: "sentence@sentiment"
            parts = line.rsplit("@", 1)
            if parts:
                sent = parts[0].strip()
                if sent:
                    all_sentences.append(sent)

    # Sample
    random.seed(seed)
    if len(all_sentences) > sample_size:
        sampled = random.sample(all_sentences, sample_size)
    else:
        sampled = all_sentences

    records = []
    for i, sent in enumerate(sampled):
        records.append({
            "prompt_id": f"FPB_{i:03d}",
            "source": "financial_phrasebank",
            "query": sent,
            "expected": "allow",
        })
    safe_write_jsonl(records, cache_path)


# ---------------------------------------------------------------------------
# Custom strategy exfiltration (already created, just validate)
# ---------------------------------------------------------------------------

def validate_custom_exfil(cfg: dict):
    """Validate that custom exfil prompts file exists and is valid JSONL."""
    ds_cfg = cfg.get("datasets", {}).get("custom_exfil", {})
    source = ds_cfg.get("source", "data/benchmark/custom_strategy_exfil.jsonl")

    if not os.path.exists(source):
        print(f"  [missing] {source} - run generate_secrets.py first")
        return

    count = 0
    with open(source, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                json.loads(line)
                count += 1
    print(f"  [ok] {source}: {count} prompts")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

DATASETS = {
    "jailbreakbench": prepare_jailbreakbench,
    "advbench": prepare_advbench,
    "salesforce": prepare_salesforce,
    "financial_phrasebank": prepare_financial_phrasebank,
    "custom_exfil": validate_custom_exfil,
}


def main():
    ap = argparse.ArgumentParser(description="Prepare benchmark datasets for SentinelFlow")
    ap.add_argument("--config", default="config.yaml", type=str)
    ap.add_argument("--dataset", default="all", choices=list(DATASETS.keys()) + ["all"])
    args = ap.parse_args()

    cfg = load_config(args.config).get("benchmark", {})

    print("=== SentinelFlow Benchmark Data Preparation ===\n")

    if args.dataset == "all":
        for name, func in DATASETS.items():
            print(f"[{name}]")
            func(cfg)
            print()
    else:
        print(f"[{args.dataset}]")
        DATASETS[args.dataset](cfg)
        print()

    print("Done.")


if __name__ == "__main__":
    main()
