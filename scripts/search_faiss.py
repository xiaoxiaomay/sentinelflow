import os, pickle, sys
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer

INDEX_DIR = "data/index"
INDEX_PATH = os.path.join(INDEX_DIR, "finder.faiss")
META_PATH  = os.path.join(INDEX_DIR, "finder_meta.pkl")
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

def main():
    query = " ".join(sys.argv[1:]).strip() if len(sys.argv) > 1 else "MSFT segment breakdown"
    topk = 5

    model = SentenceTransformer(MODEL_NAME)
    index = faiss.read_index(INDEX_PATH)

    with open(META_PATH, "rb") as f:
        meta = pickle.load(f)

    q = model.encode([query], normalize_embeddings=True).astype("float32")
    scores, idxs = index.search(q, topk)

    print("\nQuery:", query)
    print("-" * 60)

    for rank, (i, s) in enumerate(zip(idxs[0], scores[0]), start=1):
        doc_id = meta["ids"][i]
        title  = meta["titles"][i]
        text   = meta["texts"][i]
        print(f"\n#{rank} score={float(s):.4f} id={doc_id} title={title}")
        print(text[:500])

if __name__ == "__main__":
    main()