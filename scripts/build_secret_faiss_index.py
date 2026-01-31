import json
import pickle
from pathlib import Path
from typing import List, Dict

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


SECRETS_PATH = Path("data/secrets/secrets.jsonl")
OUT_DIR = Path("data/index")
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def load_jsonl(path: Path) -> List[Dict]:
    items = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            items.append(json.loads(line))
    return items


def main():
    if not SECRETS_PATH.exists():
        raise FileNotFoundError(
            f"Not found: {SECRETS_PATH}\n"
            f"Create it first (data/secrets/secrets.jsonl)."
        )

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    secrets = load_jsonl(SECRETS_PATH)
    if len(secrets) == 0:
        raise ValueError("secrets.jsonl is empty.")

    # Build text to embed
    texts = []
    meta = []
    for s in secrets:
        # embed both title + text to stabilize matching
        title = (s.get("title") or "").strip()
        text = (s.get("text") or "").strip()
        joined = f"{title}\n{text}".strip()
        texts.append(joined)
        meta.append(s)

    print(f"Loaded secrets: {len(texts)}")
    model = SentenceTransformer(MODEL_NAME)

    # Encode
    emb = model.encode(
        texts,
        batch_size=32,
        show_progress_bar=True,
        normalize_embeddings=True,  # cosine similarity via inner product
    )
    emb = np.asarray(emb, dtype="float32")
    dim = emb.shape[1]
    print(f"Embedding dim: {dim}")

    # FAISS index (inner product works as cosine because normalized)
    index = faiss.IndexFlatIP(dim)
    index.add(emb)

    out_faiss = OUT_DIR / "secrets.faiss"
    out_meta = OUT_DIR / "secrets_meta.pkl"

    faiss.write_index(index, str(out_faiss))
    with out_meta.open("wb") as f:
        pickle.dump(meta, f)

    print("Saved:")
    print(f"  - {out_faiss}")
    print(f"  - {out_meta}")


if __name__ == "__main__":
    main()