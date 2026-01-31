# scripts/build_faiss_index.py
import os, json, pickle
from tqdm import tqdm
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer

CORPUS_PATH = "data/processed/public_corpus.jsonl"
INDEX_DIR = "data/index"
INDEX_PATH = os.path.join(INDEX_DIR, "finder.faiss")
META_PATH  = os.path.join(INDEX_DIR, "finder_meta.pkl")

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
BATCH_SIZE = 64

def iter_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)

def main():
    os.makedirs(INDEX_DIR, exist_ok=True)
    model = SentenceTransformer(MODEL_NAME)

    meta_list = []
    texts = []

    print(f"Loading corpus from: {CORPUS_PATH}")
    for row in tqdm(iter_jsonl(CORPUS_PATH)):
        # keep whole row as meta (dashboard-friendly)
        # IMPORTANT: order here must match embedding order
        meta_list.append(row)
        texts.append(row.get("text", ""))

    print(f"Total docs: {len(texts)}")

    print("Encoding embeddings...")
    embs = model.encode(
        texts,
        batch_size=BATCH_SIZE,
        show_progress_bar=True,
        normalize_embeddings=True,   # cosine-ready
    ).astype("float32")

    dim = embs.shape[1]
    print("Embedding dim:", dim)

    index = faiss.IndexFlatIP(dim)   # IP on normalized vectors == cosine
    index.add(embs)

    faiss.write_index(index, INDEX_PATH)
    with open(META_PATH, "wb") as f:
        pickle.dump(meta_list, f)

    print("Saved:")
    print(" -", INDEX_PATH)
    print(" -", META_PATH)
    print(f"Meta type: list (len={len(meta_list)}) aligned to FAISS positions")

if __name__ == "__main__":
    main()