#!/usr/bin/env python3
"""
scripts/find_hard_negatives.py

Finds public corpus passages with cosine similarity 0.50-0.70 to L3 secrets.
These are "hard negatives" — passages that share vocabulary with confidential
content but are clearly public knowledge. Used in C6 evaluation to verify
the system doesn't over-block.

Usage:
    python scripts/find_hard_negatives.py
    python scripts/find_hard_negatives.py --sim_low 0.50 --sim_high 0.70 --top_n 50
"""
import json
import argparse
import sys
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SECRETS_PATH = REPO_ROOT / "data" / "secrets" / "secrets.jsonl"
PUBLIC_PATH = REPO_ROOT / "data" / "processed" / "public_corpus.jsonl"
OUTPUT_PATH = REPO_ROOT / "data" / "benchmark" / "hard_negatives.jsonl"


def load_jsonl(path: Path) -> list:
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def main():
    ap = argparse.ArgumentParser(description="Find hard negatives from public corpus")
    ap.add_argument("--sim_low", type=float, default=0.50, help="Min cosine similarity")
    ap.add_argument("--sim_high", type=float, default=0.70, help="Max cosine similarity")
    ap.add_argument("--top_n", type=int, default=50, help="Max passages per secret to scan")
    ap.add_argument("--max_output", type=int, default=100, help="Max hard negatives to output")
    args = ap.parse_args()

    from sentence_transformers import SentenceTransformer

    # Load data
    secrets = load_jsonl(SECRETS_PATH)
    l3_secrets = [s for s in secrets if s.get("sensitivity_level") == 3 or s.get("level") == "L3"]
    print(f"Loaded {len(l3_secrets)} L3 secrets")

    public = load_jsonl(PUBLIC_PATH)
    print(f"Loaded {len(public)} public passages")

    if not public:
        print("No public corpus found. Skipping hard negative generation.")
        return

    # Embed
    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

    secret_texts = [f"{s.get('title', '')}\n{s.get('text', '')}".strip() for s in l3_secrets]
    public_texts = [f"{p.get('title', '')}\n{p.get('text', '')}".strip() for p in public]

    print("Encoding secrets...")
    secret_emb = model.encode(secret_texts, normalize_embeddings=True, show_progress_bar=True)
    secret_emb = np.asarray(secret_emb, dtype="float32")

    print("Encoding public corpus...")
    public_emb = model.encode(public_texts, normalize_embeddings=True, show_progress_bar=True)
    public_emb = np.asarray(public_emb, dtype="float32")

    # Compute similarities
    print("Computing similarities...")
    sims = secret_emb @ public_emb.T  # (n_secrets, n_public)

    # Find hard negatives
    seen_public_ids = set()
    hard_negatives = []

    for i, secret in enumerate(l3_secrets):
        scores = sims[i]
        # Get indices in similarity range
        mask = (scores >= args.sim_low) & (scores <= args.sim_high)
        candidates = np.where(mask)[0]

        # Sort by similarity descending (closest to upper bound = hardest)
        if len(candidates) == 0:
            continue
        sorted_idx = candidates[np.argsort(-scores[candidates])]

        for j in sorted_idx[:5]:  # up to 5 per secret
            pub_id = public[j].get("_id", f"PUB_{j}")
            if pub_id in seen_public_ids:
                continue
            seen_public_ids.add(pub_id)

            hard_negatives.append({
                "_id": f"HN_{len(hard_negatives)+1:03d}",
                "public_id": pub_id,
                "public_title": public[j].get("title", ""),
                "public_text": public[j].get("text", ""),
                "matched_secret_id": secret["_id"],
                "matched_secret_title": secret.get("title", ""),
                "cosine_similarity": round(float(scores[j]), 4),
                "expected_decision": "allow",
                "level": "L0",
            })

            if len(hard_negatives) >= args.max_output:
                break
        if len(hard_negatives) >= args.max_output:
            break

    # Write output
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        for hn in hard_negatives:
            f.write(json.dumps(hn, ensure_ascii=False) + "\n")

    print(f"\nFound {len(hard_negatives)} hard negatives")
    print(f"Similarity range: {args.sim_low:.2f} - {args.sim_high:.2f}")
    print(f"Written to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
