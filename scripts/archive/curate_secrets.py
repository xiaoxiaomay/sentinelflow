#!/usr/bin/env python3
"""
scripts/curate_secrets.py

One-time curation script for C3: Domain-Specific Evaluation Framework.
Curates secrets.jsonl to exactly 60 entries (50 L3 + 10 L2) with style/level fields.

Usage:
    python scripts/curate_secrets.py
    python scripts/curate_secrets.py --dry_run
"""
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.generate_secrets import GENERATED_SECRETS, _add_defaults

SECRETS_PATH = REPO_ROOT / "data" / "secrets" / "secrets.jsonl"

# --- Selection: 10 additional L3 records (diverse archetypes) ---
L3_IDS = [
    "S0056",  # Mean Reversion: Bollinger Band Bounce
    "S0071",  # StatArb: PCA Residual Alpha
    "S0083",  # Volatility: Variance Risk Premium
    "S0095",  # Macro: FX Carry Trade
    "S0105",  # Event: Post-Earnings Drift v2
    "S0120",  # Risk: Drawdown Recovery Protocol
    "S0122",  # Risk: Beta Hedging Parameters
    "S0126",  # Risk: Factor Exposure Bands
    "S0136",  # Execution: Market Impact Model v2
    "S0158",  # Committee: Risk Budget Allocation FY2025
]

# --- Selection: 10 L2 records (diverse categories) ---
L2_IDS = [
    "S0045",  # Momentum: Industry Momentum Spread
    "S0060",  # Mean Reversion: ETF Premium/Discount
    "S0076",  # StatArb: Cross-Listed Arbitrage
    "S0087",  # Volatility: Realized Vol Breakout
    "S0097",  # Macro: Risk Parity Allocation
    "S0107",  # Event: Buyback Announcement
    "S0117",  # Risk: VaR Methodology v3
    "S0135",  # Execution: Optimal Execution VWAP v2
    "S0155",  # Client: Pension Fund Mandate Constraints
    "S0156",  # Client: Endowment Mandate Terms
]

SELECTED_IDS = set(L3_IDS + L2_IDS)


def _classify_style(record: dict) -> str:
    """Heuristic style classification: parametric, procedural, or descriptive."""
    text = record.get("text", "")
    category = record.get("category", "")

    # Count numeric-like tokens (thresholds, percentages, specific values)
    import re
    numbers = re.findall(r"\d+\.?\d*%?", text)
    has_threshold = record.get("has_threshold_conditions", False)

    if len(numbers) >= 3 or (has_threshold and len(numbers) >= 2):
        return "parametric"
    elif category in ("execution_policy", "portfolio_policy", "committee_notes"):
        return "procedural"
    elif category in ("client_sensitive", "internal_data_asset"):
        return "descriptive"
    else:
        return "parametric" if has_threshold else "descriptive"


def _level_str(sensitivity_level: int) -> str:
    return f"L{sensitivity_level}"


def load_existing() -> list:
    records = []
    if not SECRETS_PATH.exists():
        return records
    with open(SECRETS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Curate secrets.jsonl for C3 evaluation framework")
    ap.add_argument("--dry_run", action="store_true", help="Print stats without writing")
    args = ap.parse_args()

    # Load existing secrets (S0001-S0040)
    existing = load_existing()
    existing_ids = {r["_id"] for r in existing}
    print(f"Existing secrets: {len(existing)} (IDs: {min(existing_ids)}..{max(existing_ids)})")

    # Build lookup from GENERATED_SECRETS
    gen_lookup = {}
    for rec in GENERATED_SECRETS:
        rec = _add_defaults(rec)
        gen_lookup[rec["_id"]] = rec

    # Validate selections exist
    missing = SELECTED_IDS - set(gen_lookup.keys())
    if missing:
        raise ValueError(f"Selected IDs not found in GENERATED_SECRETS: {missing}")

    # Verify L3/L2 levels match
    for sid in L3_IDS:
        assert gen_lookup[sid]["sensitivity_level"] == 3, f"{sid} is not L3"
    for sid in L2_IDS:
        assert gen_lookup[sid]["sensitivity_level"] == 2, f"{sid} is not L2"

    # Add style + level to existing records
    for rec in existing:
        rec["style"] = _classify_style(rec)
        rec["level"] = _level_str(rec.get("sensitivity_level", 3))

    # Build new records from selections
    new_records = []
    for sid in L3_IDS + L2_IDS:
        if sid not in existing_ids:
            rec = dict(gen_lookup[sid])
            rec["source_type"] = rec.get("source_type", "internal")
            rec["trust_score"] = rec.get("trust_score", 1.0)
            rec["style"] = _classify_style(rec)
            rec["level"] = _level_str(rec["sensitivity_level"])
            new_records.append(rec)

    all_records = existing + new_records

    # Stats
    l3_count = sum(1 for r in all_records if r.get("sensitivity_level") == 3 or r.get("level") == "L3")
    l2_count = sum(1 for r in all_records if r.get("sensitivity_level") == 2 or r.get("level") == "L2")

    categories = {}
    for r in all_records:
        cat = r.get("category", "unknown")
        categories[cat] = categories.get(cat, 0) + 1

    archetypes = {}
    for r in all_records:
        arch = r.get("strategy_archetype", r.get("category", "unknown"))
        archetypes[arch] = archetypes.get(arch, 0) + 1

    print(f"\nCurated corpus: {len(all_records)} total ({l3_count} L3, {l2_count} L2)")
    print(f"New records added: {len(new_records)}")
    print(f"\nCategory distribution:")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")
    print(f"\nArchetype distribution:")
    for arch, count in sorted(archetypes.items(), key=lambda x: -x[1]):
        print(f"  {arch}: {count}")

    if args.dry_run:
        print("\n[DRY RUN] No file written.")
        return

    # Write curated file
    SECRETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(SECRETS_PATH, "w", encoding="utf-8") as f:
        for rec in all_records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"\nWritten {len(all_records)} records to: {SECRETS_PATH}")
    print("Next: rebuild FAISS index with:")
    print("  python scripts/build_secret_faiss_index.py")


if __name__ == "__main__":
    main()
